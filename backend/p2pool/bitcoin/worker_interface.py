

import collections
import io
import hashlib
import hmac
import json
import os
import random
import socket
import sys

from twisted.internet import defer

import p2pool
from p2pool.bitcoin import data as bitcoin_data, getwork
from p2pool.util import expiring_dict, jsonrpc, pack, variable
from p2pool.util.py3 import ensure_bytes, ensure_text

MAX_ACTIVE_GETWORK_HANDLERS = 16384
MAX_STALE_GETWORK_HANDLERS = 4096
MAX_CURRENT_GETWORK_HANDLERS = (
    MAX_ACTIVE_GETWORK_HANDLERS - MAX_STALE_GETWORK_HANDLERS)
MAX_GETWORK_HANDLERS_PER_CLIENT = 512
MAX_UNVERIFIED_GETWORK_HANDLERS_PER_CLIENT = 64
MAX_GETWORK_HANDLERS_PER_IPV6_PREFIX = 2048
MAX_VERIFIED_GETWORK_CLIENTS = 4096
VERIFIED_GETWORK_CLIENT_TTL = 3600
MAX_CONCURRENT_LONG_POLLS = 4096
MAX_LONG_POLL_IDENTITIES = 4096
LONG_POLL_IDENTITY_TTL = 600
LONG_POLL_TIMEOUT = 120
MAX_CACHED_WORK_ITEMS = 4096
GETWORK_ROLL_NTIME_SECONDS = 100
# Defcoin rejects block candidates more than two hours in the future. This
# conservative cap makes the final 101-second-stride base offset 404 and its
# advertised window end at 504, leaving ample clock-skew margin.
MAX_GETWORK_ROLL_TIMESTAMP_OFFSET = 500
_LONG_POLL_IDENTITY_KEY = os.urandom(32)

def _normalize_ip(value):
    for address_family in (socket.AF_INET, socket.AF_INET6):
        try:
            packed = socket.inet_pton(address_family, value)
            return socket.inet_ntop(address_family, packed)
        except (AttributeError, OSError, socket.error):
            pass
    return None

_TRUSTED_PROXY_IPS = frozenset(filter(None, (
    _normalize_ip(value.strip()) for value in
    os.environ.get('P2POOL_TRUSTED_PROXY_IPS', '127.0.0.1,::1').split(',')
    if value.strip())))

def _request_client_ip(request):
    """Use forwarded identity only when the immediate peer is trusted."""
    peer = ensure_text(request.getClientIP() or '', 'utf-8')
    peer = _normalize_ip(peer)
    if peer is None:
        return ensure_text(request.getClientIP() or '', 'utf-8')
    if peer not in _TRUSTED_PROXY_IPS:
        return peer

    forwarded = request.getHeader('X-Forwarded-For')
    if not forwarded:
        return peer
    forwarded = ensure_text(forwarded, 'utf-8')
    for value in reversed(forwarded.split(',')):
        candidate = _normalize_ip(value.strip())
        if candidate is None:
            return peer
        if candidate not in _TRUSTED_PROXY_IPS:
            return candidate
    return peer

def _long_poll_identity(client_ip, authorization):
    client_id = hmac.new(
        _LONG_POLL_IDENTITY_KEY,
        ensure_bytes(client_ip or '', 'utf-8'), hashlib.sha256).digest()
    authorization_id = (
        None if authorization is None else
        hmac.new(
            _LONG_POLL_IDENTITY_KEY,
            ensure_bytes(authorization, 'utf-8'), hashlib.sha256).digest())
    return client_id, authorization_id

def _getwork_client_identity(client_ip):
    normalized = _normalize_ip(client_ip)
    if normalized is not None:
        try:
            packed = socket.inet_pton(socket.AF_INET6, normalized)
        except (AttributeError, OSError, socket.error):
            pass
        else:
            if packed[:12] == b'\0' * 10 + b'\xff\xff':
                normalized = socket.inet_ntop(socket.AF_INET, packed[12:])
            else:
                # Preserve one client bucket per /64 so independent IPv6
                # subscribers do not share the small per-client quota. A
                # separate /48 aggregate below bounds subnet rotation.
                normalized = socket.inet_ntop(
                    socket.AF_INET6, packed[:8] + b'\0' * 8) + '/64'
    return _long_poll_identity(normalized or client_ip, None)[0]

def _getwork_ipv6_prefix_identity(client_ip):
    normalized = _normalize_ip(client_ip)
    if normalized is None:
        return None
    try:
        packed = socket.inet_pton(socket.AF_INET6, normalized)
    except (AttributeError, OSError, socket.error):
        return None
    if packed[:12] == b'\0' * 10 + b'\xff\xff':
        return None
    prefix = socket.inet_ntop(
        socket.AF_INET6, packed[:6] + b'\0' * 10) + '/48'
    return _long_poll_identity(prefix, None)[0]

def _getwork_request_identity(client_identity, work_args, generation):
    """Hash payout/work parameters without retaining miner credentials."""
    # Production preprocessors return (user, address, share target,
    # pseudoshare target). The handler receives the submitting user later, so
    # workers sharing the same payout parameters can safely share one ntime
    # sequence while still receiving distinct header work.
    cache_args = work_args[1:] if len(work_args) > 1 else work_args
    request_id = hmac.new(
        _LONG_POLL_IDENTITY_KEY,
        ensure_bytes(repr((generation, cache_args)), 'utf-8'),
        hashlib.sha256).digest()
    return client_identity, request_id

class _Provider(object):
    def __init__(self, parent, long_poll):
        self.parent = parent
        self.long_poll = long_poll
    
    def rpc_getwork(self, request, data=None):
        return self.parent._getwork(request, data, long_poll=self.long_poll)

class _GETableServer(jsonrpc.HTTPServer):
    def __init__(self, provider, render_get_func):
        jsonrpc.HTTPServer.__init__(self, provider)
        self.render_GET = render_get_func

class WorkerBridge(object):
    def __init__(self):
        self.new_work_event = variable.Event()
    
    def preprocess_request(self, request):
        return request, # *args to self.compute
    
    def get_work(self, request):
        raise NotImplementedError()

class WorkerInterface(object):
    def __init__(self, worker_bridge):
        self.worker_bridge = worker_bridge
        
        self.worker_views = expiring_dict.ExpiringDict(
            LONG_POLL_IDENTITY_TTL, get_touches=False,
            max_len=MAX_LONG_POLL_IDENTITIES)
        self._long_poll_waiters = 0
        self._active_long_poll_waiters = set()

        self.merkle_root_to_handler = expiring_dict.ExpiringDict(
            300, get_touches=False,
            max_len=MAX_CURRENT_GETWORK_HANDLERS)
        self.stale_merkle_root_to_handler = expiring_dict.ExpiringDict(
            300, get_touches=False,
            max_len=MAX_STALE_GETWORK_HANDLERS)
        self.getwork_roots_by_client = expiring_dict.ExpiringDict(
            300, get_touches=False,
            max_len=MAX_ACTIVE_GETWORK_HANDLERS)
        self.getwork_roots_by_ipv6_prefix = expiring_dict.ExpiringDict(
            300, get_touches=False,
            max_len=MAX_CURRENT_GETWORK_HANDLERS)
        self.getwork_by_request = expiring_dict.ExpiringDict(
            300, get_touches=False,
            max_len=MAX_ACTIVE_GETWORK_HANDLERS)
        self.verified_getwork_clients = expiring_dict.ExpiringDict(
            VERIFIED_GETWORK_CLIENT_TTL, get_touches=False,
            max_len=MAX_VERIFIED_GETWORK_CLIENTS)
        self._getwork_generation = self.worker_bridge.new_work_event.times

    def stop(self):
        for waiter in list(self._active_long_poll_waiters):
            if not waiter.called:
                waiter.cancel()
        self.worker_views.stop()
        self.merkle_root_to_handler.stop()
        self.stale_merkle_root_to_handler.stop()
        self.getwork_roots_by_client.stop()
        self.getwork_roots_by_ipv6_prefix.stop()
        self.getwork_by_request.stop()
        self.verified_getwork_clients.stop()

    def attach_to(self, res, get_handler=None):
        res.putChild(b'', _GETableServer(_Provider(self, long_poll=False), get_handler))

        def repost(request):
            request.content = io.BytesIO(json.dumps(dict(id=0, method='getwork')).encode('utf-8'))
            return s.render_POST(request)
        s = _GETableServer(_Provider(self, long_poll=True), repost)
        res.putChild(b'long-polling', s)

    def _getwork_client_roots(self, client_identity):
        self.merkle_root_to_handler.expire()
        self.getwork_roots_by_client.expire()
        roots = self.getwork_roots_by_client.get(client_identity, set())
        return set(root for root in roots
                   if root in self.merkle_root_to_handler)

    def _getwork_ipv6_prefix_roots(self, prefix_identity):
        if prefix_identity is None:
            return set()
        self.merkle_root_to_handler.expire()
        self.getwork_roots_by_ipv6_prefix.expire()
        roots = self.getwork_roots_by_ipv6_prefix.get(
            prefix_identity, set())
        return set(root for root in roots
                   if root in self.merkle_root_to_handler)

    def _sync_getwork_generation(self):
        generation = self.worker_bridge.new_work_event.times
        if generation == self._getwork_generation:
            return
        for merkle_root, handler in self.merkle_root_to_handler.items():
            self.stale_merkle_root_to_handler[merkle_root] = handler
        for state in (self.merkle_root_to_handler,
                      self.getwork_roots_by_client,
                      self.getwork_roots_by_ipv6_prefix,
                      self.getwork_by_request):
            for key in state.keys():
                del state[key]
        self._getwork_generation = generation

    def _getwork_handler(self, merkle_root):
        self.merkle_root_to_handler.expire()
        self.stale_merkle_root_to_handler.expire()
        if merkle_root in self.merkle_root_to_handler:
            return self.merkle_root_to_handler[merkle_root]
        return self.stale_merkle_root_to_handler.get(merkle_root)

    def _can_issue_getwork(
            self, client_identity, ipv6_prefix_identity=None):
        roots = self._getwork_client_roots(client_identity)
        prefix_roots = self._getwork_ipv6_prefix_roots(
            ipv6_prefix_identity)
        self.verified_getwork_clients.expire()
        client_limit = (
            MAX_GETWORK_HANDLERS_PER_CLIENT
            if client_identity in self.verified_getwork_clients else
            MAX_UNVERIFIED_GETWORK_HANDLERS_PER_CLIENT)
        return (len(roots) < client_limit and
                (ipv6_prefix_identity is None or
                 len(prefix_roots) <
                 MAX_GETWORK_HANDLERS_PER_IPV6_PREFIX) and
                len(self.merkle_root_to_handler) <
                MAX_CURRENT_GETWORK_HANDLERS)

    def _remember_getwork_handler(
            self, merkle_root, handler, client_identity,
            ipv6_prefix_identity=None):
        if merkle_root in self.merkle_root_to_handler:
            return False
        roots = self._getwork_client_roots(client_identity)
        if not self._can_issue_getwork(
                client_identity, ipv6_prefix_identity):
            return False
        handler_func, pseudoshare_target = handler
        self.merkle_root_to_handler[merkle_root] = (
            handler_func, pseudoshare_target, client_identity)
        roots.add(merkle_root)
        self.getwork_roots_by_client[client_identity] = roots
        if ipv6_prefix_identity is not None:
            prefix_roots = self._getwork_ipv6_prefix_roots(
                ipv6_prefix_identity)
            prefix_roots.add(merkle_root)
            self.getwork_roots_by_ipv6_prefix[
                ipv6_prefix_identity] = prefix_roots
        return True

    def _get_cached_getwork(self, request_identity):
        self.merkle_root_to_handler.expire()
        self.getwork_by_request.expire()
        cached = self.getwork_by_request.get(request_identity)
        if cached is None:
            return None
        merkle_root, block_attempt, next_timestamp_offset = cached
        if merkle_root in self.merkle_root_to_handler:
            if (next_timestamp_offset <=
                    MAX_GETWORK_ROLL_TIMESTAMP_OFFSET):
                self.getwork_by_request[request_identity] = (
                    merkle_root, block_attempt,
                    next_timestamp_offset +
                    GETWORK_ROLL_NTIME_SECONDS + 1)
                return block_attempt.update(
                    timestamp=block_attempt.timestamp +
                    next_timestamp_offset)
            del self.getwork_by_request[request_identity]
            return None
        del self.getwork_by_request[request_identity]
        return None

    def _format_getwork(self, request, block_attempt):
        if request.getHeader('User-Agent') == 'Jephis PIC Miner':
            # ASICMINER BE Blades apparently have a buffer overflow bug and
            # can't handle much extra in the getwork response
            extra_params = {}
        else:
            extra_params = dict(
                identifier=str(self.worker_bridge.new_work_event.times),
                submitold=True)
        return block_attempt.getwork(**extra_params)
    
    @defer.inlineCallbacks
    def _getwork(self, request, data, long_poll):
        request.setHeader('X-Long-Polling', '/long-polling')
        request.setHeader(
            'X-Roll-NTime',
            'expire=%d' % (GETWORK_ROLL_NTIME_SECONDS,))
        request.setHeader('X-Is-P2Pool', 'true')
        if request.getHeader('Host') is not None:
            request.setHeader('X-Stratum', 'stratum+tcp://' + request.getHeader('Host'))

        self._sync_getwork_generation()
        
        if data is not None:
            header = getwork.decode_data(data)
            handler_record = self._getwork_handler(header['merkle_root'])
            if handler_record is None:
                print('''Couldn't link returned work's merkle root with its handler. This should only happen if this process was recently restarted!''', file=sys.stderr)
                defer.returnValue(False)
            handler, pseudoshare_target, client_identity = handler_record
            request_user = request.getUser() if request.getUser() is not None else ''
            request_user = ensure_text(request_user, 'utf-8') if request_user else ''
            result = handler(
                header, request_user,
                b'\0'*self.worker_bridge.COINBASE_NONCE_LENGTH,
                pseudoshare_target)
            if getattr(handler, 'last_submission_met_share_target', False):
                self.verified_getwork_clients[client_identity] = True
            defer.returnValue(result)
        
        if p2pool.DEBUG:
            id = random.randrange(1000, 10000)
            print('POLL %i START is_long_poll=%r user_agent=%r user=%r' % (id, long_poll, request.getHeader('User-Agent'), request.getUser()))
        
        if long_poll:
            authorization = request.getHeader('Authorization')
            request_id = _long_poll_identity(
                _request_client_ip(request), authorization)
            if self.worker_views.get(request_id, self.worker_bridge.new_work_event.times) != self.worker_bridge.new_work_event.times:
                if p2pool.DEBUG:
                    print('POLL %i PUSH' % (id,))
            else:
                if p2pool.DEBUG:
                    print('POLL %i WAITING' % (id,))
                if self._long_poll_waiters >= MAX_CONCURRENT_LONG_POLLS:
                    request.setResponseCode(503)
                    request.setHeader('Retry-After', '5')
                    defer.returnValue(None)
                self._long_poll_waiters += 1
                waiter = self.worker_bridge.new_work_event.get_deferred(
                    timeout=LONG_POLL_TIMEOUT)
                self._active_long_poll_waiters.add(waiter)
                if hasattr(request, 'notifyFinish'):
                    def request_disconnected(fail):
                        if not waiter.called:
                            waiter.cancel()
                        return None
                    request.notifyFinish().addErrback(request_disconnected)
                try:
                    yield waiter
                except defer.TimeoutError:
                    pass
                except defer.CancelledError:
                    defer.returnValue(None)
                finally:
                    self._active_long_poll_waiters.discard(waiter)
                    self._long_poll_waiters -= 1
            self.worker_views[request_id] = self.worker_bridge.new_work_event.times

        self._sync_getwork_generation()
        
        request_user = request.getUser() if request.getUser() is not None else ''
        request_user = ensure_text(request_user, 'utf-8') if request_user else ''
        client_ip = _request_client_ip(request)
        client_identity = _getwork_client_identity(client_ip)
        ipv6_prefix_identity = _getwork_ipv6_prefix_identity(client_ip)
        work_args = tuple(self.worker_bridge.preprocess_request(request_user))
        request_identity = _getwork_request_identity(
            client_identity, work_args,
            self.worker_bridge.new_work_event.times)
        cached_work = self._get_cached_getwork(request_identity)
        if cached_work is not None:
            defer.returnValue(self._format_getwork(request, cached_work))
        if not self._can_issue_getwork(
                client_identity, ipv6_prefix_identity):
            request.setResponseCode(503)
            request.setHeader('Retry-After', '5')
            defer.returnValue(None)
        x, handler = self.worker_bridge.get_work(*work_args)
        res = getwork.BlockAttempt(
            version=x['version'],
            previous_block=x['previous_block'],
            merkle_root=bitcoin_data.check_merkle_link(bitcoin_data.hash256(x['coinb1'] + b'\0'*self.worker_bridge.COINBASE_NONCE_LENGTH + x['coinb2']), x['merkle_link']),
            timestamp=x['timestamp'],
            bits=x['bits'],
            share_target=x['share_target'],
        )
        if not self._remember_getwork_handler(
                res.merkle_root, (handler, res.share_target),
                client_identity, ipv6_prefix_identity):
            request.setResponseCode(503)
            request.setHeader('Retry-After', '5')
            defer.returnValue(None)
        self.getwork_by_request[request_identity] = (
            res.merkle_root, res, GETWORK_ROLL_NTIME_SECONDS + 1)
        
        if p2pool.DEBUG:
            print('POLL %i END identifier=%i' % (id, self.worker_bridge.new_work_event.times))
        
        defer.returnValue(self._format_getwork(request, res))

class CachingWorkerBridge(object):
    def __init__(self, inner):
        self._inner = inner
        self.net = self._inner.net
        
        self.COINBASE_NONCE_LENGTH = (inner.COINBASE_NONCE_LENGTH+1)//2
        self.new_work_event = inner.new_work_event
        self.preprocess_request = inner.preprocess_request
        
        self._my_bits = (self._inner.COINBASE_NONCE_LENGTH - self.COINBASE_NONCE_LENGTH)*8
        
        self._cache = collections.OrderedDict()
        self._times = None
    
    def get_work(self, user, address, desired_share_target,
                 desired_pseudoshare_target, worker_ip=None, *args):
        if self._times != self.new_work_event.times:
            self._cache = collections.OrderedDict()
            self._times = self.new_work_event.times
        
        cachekey = (
            address, desired_share_target, desired_pseudoshare_target, args)
        if cachekey not in self._cache:
            x, handler = self._inner.get_work(user, address, desired_share_target,
                desired_pseudoshare_target, worker_ip, *args)
            self._cache[cachekey] = x, handler, 0
        
        x, handler, nonce = self._cache.pop(cachekey)
        
        def got_response(header, user, coinbase_nonce, pseudoshare_target):
            result = handler(
                header, user,
                pack.IntType(self._my_bits).pack(nonce) + coinbase_nonce,
                pseudoshare_target)
            got_response.last_submission_met_share_target = getattr(
                handler, 'last_submission_met_share_target', False)
            return result
        got_response.last_submission_met_share_target = False

        res = (
            dict(x, coinb1=x['coinb1'] + pack.IntType(self._my_bits).pack(nonce)),
            got_response,
        )
        
        if nonce + 1 != 2**self._my_bits:
            self._cache[cachekey] = x, handler, nonce + 1
            if len(self._cache) > MAX_CACHED_WORK_ITEMS:
                self._cache.popitem(last=False)
        
        return res
    def __getattr__(self, attr):
        return getattr(self._inner, attr)

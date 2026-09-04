import hashlib
import struct

import ltc_scrypt
from twisted.internet import defer, task
from twisted.internet.testing import StringTransport
from twisted.trial import unittest

from p2pool import p2p, work
from p2pool.bitcoin import data as bitcoin_data, getwork, worker_interface
from p2pool.util import expiring_dict, graph, math, p2protocol, pack, switchprotocol, variable


class TestNativeScryptBoundary(unittest.TestCase):
    def test_exact_header_matches_reference_vector(self):
        header = b'\0' * 80
        result = ltc_scrypt.getPoWHash(header)
        self.assertEqual(len(result), 32)
        self.assertEqual(
            result.hex(),
            '161d0876f3b93b1048cda1bdeaa7332ee210f7131b42013cb43913a6553a4b69')
        self.assertEqual(
            result,
            hashlib.scrypt(header, salt=header, n=1024, r=1, p=1, dklen=32))

    def test_every_non_header_length_is_rejected(self):
        for size in (0, 1, 79, 81, 1024 * 1024):
            self.assertRaises(ValueError, ltc_scrypt.getPoWHash, b'x' * size)
        self.assertRaises(TypeError, ltc_scrypt.getPoWHash, 'x' * 80)


class TestRetainedStateLimits(unittest.TestCase):
    def test_expiring_dict_evicts_oldest_at_capacity(self):
        values = expiring_dict.ExpiringDict(60, get_touches=False, max_len=2)
        self.addCleanup(values.stop)
        values['a'] = 1
        values['b'] = 2
        values['c'] = 3
        self.assertNotIn('a', values)
        self.assertEqual(dict(values.items()), {'b': 2, 'c': 3})

    def test_rate_monitor_caps_samples(self):
        monitor = math.RateMonitor(60, max_len=3)
        for datum in range(10):
            monitor.add_datum(datum)
        self.assertEqual([datum for _, datum in monitor.datums], [7, 8, 9])

    def test_rate_monitor_discards_fully_expired_window(self):
        monitor = math.RateMonitor(60, max_len=3)
        monitor.datums = [(0, 'old')]
        self.patch(math.time, 'time', lambda: 1000)
        self.assertEqual(monitor.get_datums_in_last()[0], [])

    def test_miner_telemetry_identity_preserves_normal_names(self):
        self.assertEqual(
            work.miner_telemetry_identity('DAddress.worker'),
            'DAddress.worker')

    def test_miner_telemetry_identity_bounds_untrusted_names(self):
        identity = work.miner_telemetry_identity('x' * 10000)
        self.assertTrue(identity.startswith('worker-sha256:'))
        self.assertLessEqual(len(identity), work.MAX_MINER_IDENTITY_LENGTH)
        self.assertNotIn('x' * 100, identity)
        self.assertTrue(work.miner_telemetry_identity('worker\nforged').startswith(
            'worker-sha256:'))

    def test_peer_penalties_are_capped_and_expire(self):
        self.patch(p2p, 'MAX_PEER_PENALTY_IDENTITIES', 2)
        node = p2p.Node(lambda: None, 1, object())
        self.assertTrue(node.penalize_peer('192.0.2.1', now=100))
        self.assertTrue(node.penalize_peer('192.0.2.2', now=100))
        self.assertFalse(node.penalize_peer('192.0.2.3', now=100))
        self.assertEqual(len(node.bans), 2)
        self.assertEqual(len(node.banscores), 2)
        node._prune_peer_penalties(now=4000)
        self.assertEqual(len(node.bans), 0)


class _P2PProtocol(p2protocol.Protocol):
    def __init__(self, max_payload_length=8):
        self.bad_peers = 0
        self.dispatched = 0
        p2protocol.Protocol.__init__(self, b'MAGC', max_payload_length)

    def badPeerHappened(self):
        self.bad_peers += 1

    message_boom = pack.IntType(8)

    def packetReceived(self, command, payload):
        self.dispatched += 1
        raise ValueError('malformed payload')


def _p2p_frame(command, payload, checksum=None):
    if checksum is None:
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return (b'MAGC' + command.ljust(12, b'\0') +
            struct.pack('<I', len(payload)) + checksum + payload)


class TestP2PFraming(unittest.TestCase):
    def _protocol(self, max_payload_length=8):
        protocol = _P2PProtocol(max_payload_length)
        protocol.makeConnection(StringTransport())
        return protocol

    def test_oversized_frame_stops_parser(self):
        protocol = self._protocol(4)
        protocol.dataReceived(
            b'MAGC' + b'ping'.ljust(12, b'\0') + struct.pack('<I', 5))
        protocol.dataReceived(_p2p_frame(b'boom', b'\1'))
        self.assertEqual(protocol.bad_peers, 1)
        self.assertEqual(protocol.dispatched, 0)

    def test_non_ascii_command_stops_parser(self):
        protocol = self._protocol()
        protocol.dataReceived(
            b'MAGC' + b'\xff'.ljust(12, b'\0') + struct.pack('<I', 0))
        protocol.dataReceived(_p2p_frame(b'boom', b'\1'))
        self.assertEqual(protocol.bad_peers, 1)
        self.assertEqual(protocol.dispatched, 0)

    def test_bad_checksum_stops_parser(self):
        protocol = self._protocol()
        protocol.dataReceived(_p2p_frame(b'boom', b'\1', b'nope'))
        protocol.dataReceived(_p2p_frame(b'boom', b'\1'))
        self.assertEqual(protocol.bad_peers, 1)
        self.assertEqual(protocol.dispatched, 0)

    def test_handler_exception_stops_buffered_frames(self):
        protocol = self._protocol()
        frame = _p2p_frame(b'boom', b'\1')
        protocol.dataReceived(frame + frame)
        self.assertEqual(protocol.dispatched, 1)
        self.flushLoggedErrors(ValueError)


class TestPackedInputBoundaries(unittest.TestCase):
    def test_truncated_fixed_width_value_raises_early_end(self):
        self.assertRaises(pack.EarlyEnd, pack.IntType(32).unpack, b'\0' * 3)

    def test_declared_list_count_is_bounded(self):
        encoded_count = pack.VarIntType().pack(pack.MAX_LIST_ITEMS + 1)
        self.assertRaises(
            ValueError, pack.ListType(pack.VarIntType()).unpack, encoded_count)

    def test_message_specific_list_limit_precedes_item_decode(self):
        encoded_count = pack.VarIntType().pack(3)
        self.assertRaises(
            ValueError,
            pack.ListType(pack.IntType(256), max_count=2).unpack,
            encoded_count)

    def test_peer_lists_reject_declared_count_before_materializing(self):
        addrs_count = pack.VarIntType().pack(
            p2p.MAX_PEER_ADDRESSES_PER_MESSAGE + 1)
        self.assertRaises(ValueError, p2p.Protocol.message_addrs.unpack,
                          addrs_count)

        share_request = (
            pack.IntType(256).pack(1) +
            pack.VarIntType().pack(p2p.MAX_SHARE_REQUEST_ITEMS + 1))
        self.assertRaises(ValueError, p2p.Protocol.message_sharereq.unpack,
                          share_request)

        transaction_count = pack.VarIntType().pack(
            p2p.MAX_TRANSACTION_ITEMS_PER_MESSAGE + 1)
        self.assertRaises(ValueError, p2p.Protocol.message_have_tx.unpack,
                          transaction_count)

    def test_transaction_input_count_is_bounded_before_allocation(self):
        payload = (
            pack.IntType(32).pack(1) +
            pack.VarIntType().pack(
                bitcoin_data.MAX_TRANSACTION_VECTOR_ITEMS + 1))
        self.assertRaises(ValueError, bitcoin_data.tx_type.unpack, payload)

    def test_nested_list_decode_budget_is_cumulative(self):
        nested_type = pack.ListType(pack.ListType(pack.IntType(8)))
        payload = nested_type.pack([[1, 2], [3, 4]])
        self.patch(pack, 'MAX_DECODE_LIST_ITEMS', 5)
        self.assertRaises(ValueError, nested_type.unpack, payload)

    def test_segwit_witness_budget_is_cumulative_per_transaction(self):
        tx_in = dict(previous_output=None, script=b'', sequence=None)
        payload = (
            pack.IntType(32).pack(1) + pack.VarIntType().pack(0) +
            bitcoin_data.TransactionType._wtx_type.pack(dict(
                flag=1, tx_ins=[tx_in, tx_in], tx_outs=[])) +
            pack.VarIntType().pack(2) +
            pack.VarStrType().pack(b'') * 2 +
            pack.VarIntType().pack(1))
        self.patch(bitcoin_data, 'MAX_TRANSACTION_WITNESS_ITEMS', 2)
        self.assertRaises(ValueError, bitcoin_data.tx_type.unpack, payload)

    def test_segwit_witness_budget_is_enforced_on_write(self):
        tx_in = dict(previous_output=None, script=b'', sequence=None)
        transaction = dict(
            version=1, marker=0, flag=1, tx_ins=[tx_in], tx_outs=[],
            witness=[[b'', b'']], lock_time=0)
        self.patch(bitcoin_data, 'MAX_TRANSACTION_WITNESS_ITEMS', 1)
        self.assertRaises(ValueError, bitcoin_data.tx_type.pack, transaction)

    def test_fragment_chunks_every_item_without_loss(self):
        calls = []
        p2p.fragment(
            lambda **kwargs: calls.append(kwargs), max_items=2,
            tx_hashes=[1, 2, 3, 4, 5], txs=[6, 7, 8])
        self.assertEqual(calls, [
            {'tx_hashes': [1, 2], 'txs': [6, 7]},
            {'tx_hashes': [3, 4], 'txs': [8]},
            {'tx_hashes': [5], 'txs': []},
        ])


class _RecordingProtocol(object):
    def __init__(self, received):
        self.received = received

    def makeConnection(self, transport):
        self.transport = transport

    def dataReceived(self, data):
        self.received.append(data)

    def connectionLost(self, reason):
        pass


class _RecordingFactory(object):
    def __init__(self, received):
        self.received = received

    def buildProtocol(self, addr):
        return _RecordingProtocol(self.received)


class TestFirstByteSwitch(unittest.TestCase):
    def _switch(self):
        clock = task.Clock()
        stratum_received = []
        http_received = []
        factory = switchprotocol.FirstByteSwitchFactory(
            {b'{': _RecordingFactory(stratum_received)},
            _RecordingFactory(http_received), reactor=clock)
        protocol = factory.buildProtocol(object())
        transport = StringTransport()
        protocol.makeConnection(transport)
        return clock, protocol, transport, stratum_received, http_received

    def test_plaintext_stratum_first_chunk_is_forwarded_unchanged(self):
        _, protocol, _, stratum_received, http_received = self._switch()
        chunk = b'{"id":1}\n'
        protocol.dataReceived(chunk)
        self.assertEqual(stratum_received, [chunk])
        self.assertEqual(http_received, [])

    def test_http_first_chunk_is_forwarded_unchanged(self):
        _, protocol, _, stratum_received, http_received = self._switch()
        chunk = b'GET / HTTP/1.1\r\n'
        protocol.dataReceived(chunk)
        self.assertEqual(stratum_received, [])
        self.assertEqual(http_received, [chunk])

    def test_silent_connection_is_aborted_after_thirty_seconds(self):
        clock, _, transport, _, _ = self._switch()
        clock.advance(switchprotocol.FIRST_BYTE_TIMEOUT)
        self.assertTrue(transport.disconnecting)


class TestEventCleanup(unittest.TestCase):
    def setUp(self):
        self.clock = task.Clock()
        self.patch(variable, 'reactor', self.clock)

    def test_cancel_removes_observer_and_timer(self):
        event = variable.Event()
        result = event.get_deferred(timeout=30)
        once = event._once
        self.assertEqual(len(once.observers), 1)
        result.cancel()
        self.failureResultOf(result, defer.CancelledError)
        self.assertEqual(len(once.observers), 0)
        self.assertEqual([call for call in self.clock.getDelayedCalls()
                          if call.active()], [])

    def test_event_removes_observer_and_timer(self):
        event = variable.Event()
        result = event.get_deferred(timeout=30)
        once = event._once
        event.happened('work')
        self.assertEqual(self.successResultOf(result), ('work',))
        self.assertEqual(len(once.observers), 0)
        self.assertEqual([call for call in self.clock.getDelayedCalls()
                          if call.active()], [])


class _CacheInner(object):
    COINBASE_NONCE_LENGTH = 2
    net = object()

    def __init__(self):
        self.new_work_event = variable.Event()
        self.calls = []

    def preprocess_request(self, request):
        return request,

    def get_work(self, user, address, desired_share_target,
                 desired_pseudoshare_target, worker_ip=None, *args):
        self.calls.append((address, desired_share_target,
                           desired_pseudoshare_target))
        return {'coinb1': b'', 'coinb2': b''}, lambda *unused: None


class TestWorkerCache(unittest.TestCase):
    def test_pseudoshare_target_is_part_of_cache_identity(self):
        inner = _CacheInner()
        cache = worker_interface.CachingWorkerBridge(inner)
        cache.get_work('user', 'address', 1, 2)
        cache.get_work('user', 'address', 1, 3)
        self.assertEqual(len(inner.calls), 2)

    def test_cache_is_bounded(self):
        self.patch(worker_interface, 'MAX_CACHED_WORK_ITEMS', 2)
        inner = _CacheInner()
        cache = worker_interface.CachingWorkerBridge(inner)
        for address in ('one', 'two', 'three'):
            cache.get_work('user', address, 1, 2)
        self.assertEqual(len(cache._cache), 2)

    def test_getwork_capacity_does_not_evict_live_handler(self):
        self.patch(worker_interface, 'MAX_CURRENT_GETWORK_HANDLERS', 3)
        self.patch(worker_interface, 'MAX_GETWORK_HANDLERS_PER_CLIENT', 1)
        self.patch(
            worker_interface,
            'MAX_UNVERIFIED_GETWORK_HANDLERS_PER_CLIENT', 1)
        interface = worker_interface.WorkerInterface(_LongPollBridge())
        self.addCleanup(interface.stop)
        self.assertTrue(interface._remember_getwork_handler(
            b'attacker-one', ('attacker-handler', 1), b'attacker'))
        self.assertFalse(interface._remember_getwork_handler(
            b'attacker-two', ('attacker-handler', 1), b'attacker'))
        self.assertTrue(interface._remember_getwork_handler(
            b'legitimate', ('legitimate-handler', 1), b'legitimate'))
        self.assertEqual(
            interface.merkle_root_to_handler[b'legitimate'],
            ('legitimate-handler', 1, b'legitimate'))

    def test_getwork_submission_does_not_refresh_handler_lifetime(self):
        interface = worker_interface.WorkerInterface(_LongPollBridge())
        self.addCleanup(interface.stop)
        interface._remember_getwork_handler(
            b'root', ('handler', 1), b'client')
        before = interface.merkle_root_to_handler.d[b'root'][0].contents[0]
        self.assertEqual(
            interface.merkle_root_to_handler[b'root'],
            ('handler', 1, b'client'))
        after = interface.merkle_root_to_handler.d[b'root'][0].contents[0]
        self.assertEqual(before, after)


class _LongPollBridge(object):
    COINBASE_NONCE_LENGTH = 8

    def __init__(self):
        self.new_work_event = variable.Event()


class _GetworkBridge(_LongPollBridge):
    def __init__(self):
        _LongPollBridge.__init__(self)
        self.calls = 0

    def preprocess_request(self, user):
        return user, 'DTestAddress', None, None

    def get_work(self, user, address, desired_share_target,
                 desired_pseudoshare_target):
        self.calls += 1
        work = dict(
            version=1,
            previous_block=None,
            coinb1=('coinbase-%d' % (self.calls,)).encode('ascii'),
            coinb2=b'',
            merkle_link=dict(branch=[], index=0),
            timestamp=1,
            bits=bitcoin_data.FloatingInteger(0x207fffff),
            share_target=2**256 - 1,
        )
        def handler(*unused):
            handler.last_submission_met_share_target = True
            return True
        handler.last_submission_met_share_target = False
        return work, handler


class _LongPollRequest(object):
    def __init__(self, user=b'', client_ip='192.0.2.123'):
        self.code = None
        self.headers = {}
        self.user = user
        self.client_ip = client_ip

    def setHeader(self, name, value):
        self.headers[name] = value

    def getHeader(self, name):
        if name == 'X-Forwarded-For':
            return self.headers.get(name)
        return {
            'Authorization': 'Basic cleartext-secret',
            'Host': None,
            'User-Agent': None,
        }.get(name)

    def getClientIP(self):
        return self.client_ip

    def getUser(self):
        return self.user

    def setResponseCode(self, code):
        self.code = code


class _NeverFinishingRequest(_LongPollRequest):
    pass


class TestLongPollLimits(unittest.TestCase):
    def test_identity_hashes_address_and_authorization(self):
        identity = worker_interface._long_poll_identity(
            '192.0.2.123', 'Basic cleartext-secret')
        self.assertEqual(len(identity[0]), 32)
        self.assertEqual(len(identity[1]), 32)
        self.assertNotIn(b'192.0.2.123', repr(identity).encode())
        self.assertNotIn(b'cleartext-secret', repr(identity).encode())

    def test_forwarded_address_is_used_only_for_trusted_proxy(self):
        trusted = _LongPollRequest(client_ip='127.0.0.1')
        trusted.headers['X-Forwarded-For'] = '198.51.100.20'
        untrusted = _LongPollRequest(client_ip='192.0.2.50')
        untrusted.headers['X-Forwarded-For'] = '198.51.100.21'
        self.assertEqual(
            worker_interface._request_client_ip(trusted), '198.51.100.20')
        self.assertEqual(
            worker_interface._request_client_ip(untrusted), '192.0.2.50')

    def test_trusted_proxy_configuration_is_canonicalized(self):
        self.assertIn('::1', worker_interface._TRUSTED_PROXY_IPS)
        self.assertEqual(
            worker_interface._normalize_ip(
                '0:0:0:0:0:0:0:1'), '::1')

    def test_ipv6_admission_identity_groups_one_subscriber_prefix(self):
        self.assertEqual(
            worker_interface._getwork_client_identity('2001:db8:1:2::1'),
            worker_interface._getwork_client_identity('2001:db8:1:2::ffff'))
        self.assertNotEqual(
            worker_interface._getwork_client_identity('2001:db8:1:2::1'),
            worker_interface._getwork_client_identity('2001:db8:1:3::1'))

    def test_ipv6_site_prefix_groups_subscriber_prefixes(self):
        self.assertEqual(
            worker_interface._getwork_ipv6_prefix_identity(
                '2001:db8:1:2::1'),
            worker_interface._getwork_ipv6_prefix_identity(
                '2001:db8:1:ffff::1'))
        self.assertNotEqual(
            worker_interface._getwork_ipv6_prefix_identity(
                '2001:db8:1:2::1'),
            worker_interface._getwork_ipv6_prefix_identity(
                '2001:db8:2::1'))
        self.assertIsNone(
            worker_interface._getwork_ipv6_prefix_identity('192.0.2.1'))

    def test_waiter_limit_rejects_without_retaining_cleartext_identity(self):
        self.patch(worker_interface, 'MAX_CONCURRENT_LONG_POLLS', 0)
        interface = worker_interface.WorkerInterface(_LongPollBridge())
        self.addCleanup(interface.stop)
        request = _LongPollRequest()
        result = interface._getwork(request, None, long_poll=True)
        self.assertIsNone(self.successResultOf(result))
        self.assertEqual(request.code, 503)
        self.assertEqual(request.headers['Retry-After'], '5')
        self.assertNotIn(b'cleartext-secret', repr(interface.worker_views).encode())
        self.assertNotIn(b'192.0.2.123', repr(interface.worker_views).encode())

    def test_stop_cancels_active_waiter(self):
        clock = task.Clock()
        self.patch(variable, 'reactor', clock)
        interface = worker_interface.WorkerInterface(_LongPollBridge())
        result = interface._getwork(
            _NeverFinishingRequest(), None, long_poll=True)
        self.assertEqual(interface._long_poll_waiters, 1)
        self.assertEqual(len(interface._active_long_poll_waiters), 1)
        interface.stop()
        self.assertIsNone(self.successResultOf(result))
        self.assertEqual(interface._long_poll_waiters, 0)
        self.assertEqual(interface._active_long_poll_waiters, set())
        self.assertEqual(
            [call for call in clock.getDelayedCalls() if call.active()], [])


class TestGetworkAdmission(unittest.TestCase):
    def test_normal_repeated_poll_preserves_unique_work(self):
        bridge = _GetworkBridge()
        interface = worker_interface.WorkerInterface(bridge)
        self.addCleanup(interface.stop)
        request = _LongPollRequest(user=b'DAddress.worker')
        first = self.successResultOf(
            interface._getwork(request, None, long_poll=False))
        second = self.successResultOf(
            interface._getwork(request, None, long_poll=False))
        self.assertNotEqual(first['data'], second['data'])
        first_header = getwork.decode_data(first['data'])
        second_header = getwork.decode_data(second['data'])
        self.assertEqual(first_header['merkle_root'], second_header['merkle_root'])
        self.assertGreater(
            second_header['timestamp'],
            first_header['timestamp'] +
            worker_interface.GETWORK_ROLL_NTIME_SECONDS)
        self.assertEqual(bridge.calls, 1)
        self.assertEqual(len(interface.merkle_root_to_handler), 1)

    def test_worker_aliases_share_roll_sequence_without_duplicate_work(self):
        bridge = _GetworkBridge()
        interface = worker_interface.WorkerInterface(bridge)
        self.addCleanup(interface.stop)
        first = self.successResultOf(interface._getwork(
            _LongPollRequest(user=b'DAddress.worker-one'), None,
            long_poll=False))
        second = self.successResultOf(interface._getwork(
            _LongPollRequest(user=b'DAddress.worker-two'), None,
            long_poll=False))
        self.assertNotEqual(first['data'], second['data'])
        first_header = getwork.decode_data(first['data'])
        second_header = getwork.decode_data(second['data'])
        self.assertGreater(
            second_header['timestamp'],
            first_header['timestamp'] +
            worker_interface.GETWORK_ROLL_NTIME_SECONDS)
        self.assertEqual(bridge.calls, 1)
        self.assertEqual(len(interface.merkle_root_to_handler), 1)

    def test_roll_window_refreshes_root_without_duplicate_work(self):
        self.patch(worker_interface, 'GETWORK_ROLL_NTIME_SECONDS', 2)
        self.patch(worker_interface, 'MAX_GETWORK_ROLL_TIMESTAMP_OFFSET', 6)
        bridge = _GetworkBridge()
        interface = worker_interface.WorkerInterface(bridge)
        self.addCleanup(interface.stop)
        request = _LongPollRequest(user=b'DAddress.worker')
        works = [self.successResultOf(interface._getwork(
            request, None, long_poll=False)) for _ in range(4)]
        self.assertEqual(len(set(work['data'] for work in works)), 4)
        headers = [getwork.decode_data(work['data']) for work in works]
        for previous, current in zip(headers[:2], headers[1:3]):
            self.assertEqual(
                previous['merkle_root'], current['merkle_root'])
            self.assertGreater(
                current['timestamp'],
                previous['timestamp'] +
                worker_interface.GETWORK_ROLL_NTIME_SECONDS)
        self.assertNotEqual(
            headers[2]['merkle_root'], headers[3]['merkle_root'])
        self.assertEqual(bridge.calls, 2)
        self.assertEqual(len(interface.merkle_root_to_handler), 2)

    def test_ipv6_site_aggregate_blocks_rotation_not_other_sites(self):
        self.patch(
            worker_interface,
            'MAX_GETWORK_HANDLERS_PER_IPV6_PREFIX', 1)
        bridge = _GetworkBridge()
        interface = worker_interface.WorkerInterface(bridge)
        self.addCleanup(interface.stop)
        first = _LongPollRequest(
            user=b'DAddress.one', client_ip='2001:db8:1:1::1')
        same_site = _LongPollRequest(
            user=b'DAddress.two', client_ip='2001:db8:1:2::1')
        other_site = _LongPollRequest(
            user=b'DAddress.three', client_ip='2001:db8:2:1::1')
        self.assertIsNotNone(self.successResultOf(
            interface._getwork(first, None, long_poll=False)))
        self.assertIsNone(self.successResultOf(
            interface._getwork(same_site, None, long_poll=False)))
        self.assertEqual(same_site.code, 503)
        self.assertIsNotNone(self.successResultOf(
            interface._getwork(other_site, None, long_poll=False)))
        self.assertEqual(bridge.calls, 2)

    def test_cached_miner_keeps_working_at_global_capacity(self):
        self.patch(worker_interface, 'MAX_CURRENT_GETWORK_HANDLERS', 1)
        self.patch(worker_interface, 'MAX_GETWORK_HANDLERS_PER_CLIENT', 1)
        self.patch(
            worker_interface,
            'MAX_UNVERIFIED_GETWORK_HANDLERS_PER_CLIENT', 1)
        bridge = _GetworkBridge()
        interface = worker_interface.WorkerInterface(bridge)
        self.addCleanup(interface.stop)
        active = _LongPollRequest(user=b'DAddress.active')
        first = self.successResultOf(
            interface._getwork(active, None, long_poll=False))
        second = self.successResultOf(
            interface._getwork(active, None, long_poll=False))
        self.assertNotEqual(first['data'], second['data'])
        self.assertEqual(
            getwork.decode_data(first['data'])['merkle_root'],
            getwork.decode_data(second['data'])['merkle_root'])
        self.assertEqual(bridge.calls, 1)

        newcomer = _LongPollRequest(
            user=b'DAddress.new', client_ip='192.0.2.124')
        self.assertIsNone(self.successResultOf(
            interface._getwork(newcomer, None, long_poll=False)))
        self.assertEqual(newcomer.code, 503)
        self.assertEqual(bridge.calls, 1)

    def test_generation_change_reserves_capacity_and_accepts_stale_work(self):
        bridge = _GetworkBridge()
        interface = worker_interface.WorkerInterface(bridge)
        self.addCleanup(interface.stop)
        request = _LongPollRequest(user=b'DAddress.worker')
        work = self.successResultOf(interface._getwork(
            request, None, long_poll=False))
        self.assertEqual(len(interface.merkle_root_to_handler), 1)
        bridge.new_work_event.happened()
        interface._sync_getwork_generation()
        self.assertEqual(len(interface.merkle_root_to_handler), 0)
        self.assertEqual(len(interface.stale_merkle_root_to_handler), 1)
        self.assertEqual(len(interface.getwork_roots_by_client), 0)
        self.assertEqual(len(interface.getwork_by_request), 0)
        self.assertTrue(self.successResultOf(interface._getwork(
            request, work['data'], long_poll=False)))

    def test_valid_submission_promotes_client_quota(self):
        bridge = _GetworkBridge()
        interface = worker_interface.WorkerInterface(bridge)
        self.addCleanup(interface.stop)
        request = _LongPollRequest(user=b'DAddress.worker')
        work = self.successResultOf(interface._getwork(
            request, None, long_poll=False))
        self.assertTrue(self.successResultOf(interface._getwork(
            request, work['data'], long_poll=False)))
        client_identity = worker_interface._getwork_client_identity(
            worker_interface._request_client_ip(request))
        self.assertIn(client_identity, interface.verified_getwork_clients)

    def test_rolled_ntime_submission_uses_original_handler(self):
        bridge = _GetworkBridge()
        interface = worker_interface.WorkerInterface(bridge)
        self.addCleanup(interface.stop)
        request = _LongPollRequest(user=b'DAddress.worker')
        first = self.successResultOf(interface._getwork(
            request, None, long_poll=False))
        rolled = self.successResultOf(interface._getwork(
            request, None, long_poll=False))
        self.assertNotEqual(first['data'], rolled['data'])
        self.assertTrue(self.successResultOf(interface._getwork(
            request, rolled['data'], long_poll=False)))
        self.assertEqual(bridge.calls, 1)


class TestTwentyYearGraphMigration(unittest.TestCase):
    def test_twenty_year_view_is_seeded_from_existing_year_data(self):
        descriptions = {
            'last_year': graph.DataViewDescription(2, 2),
            'last_twenty_years': graph.DataViewDescription(4, 4),
        }
        stream = graph.DataStreamDescription(descriptions, is_gauge=False)
        existing = {'rate': {'last_year': {
            'last_bin_end': 2,
            'bin_width': 1,
            'bins': [{'null': (2, 1)}, {'null': (1, 1)}],
        }}}
        database = graph.HistoryDatabase.from_obj({'rate': stream}, existing)
        migrated = database.datastreams['rate'].dataviews['last_twenty_years']
        self.assertEqual(len(migrated.bins), 4)
        self.assertTrue(any(migrated.bins))

    def test_legacy_multivalue_views_resize_and_seed_new_view(self):
        descriptions = {
            'last_year': graph.DataViewDescription(4, 4),
            'last_twenty_years': graph.DataViewDescription(8, 8),
        }
        streams = {
            'peers': graph.DataStreamDescription(
                descriptions, multivalues=True,
                default_func=graph.make_multivalue_migrator({
                    'incoming': 'incoming_peers',
                    'outgoing': 'outgoing_peers',
                })),
        }
        incoming_view = {
            'last_bin_end': 4,
            'bin_width': 2,
            'bins': [{'null': (2, 1)}, {'null': (1, 1)}],
        }
        outgoing_view = {
            'last_bin_end': 2,
            'bin_width': 2,
            'bins': [{'null': (3, 1)}, {'null': (1, 1)}],
        }
        existing = {
            'incoming_peers': {'last_year': incoming_view},
            'outgoing_peers': {'last_year': outgoing_view},
        }
        database = graph.HistoryDatabase.from_obj(streams, existing)
        year = database.datastreams['peers'].dataviews['last_year']
        twenty_years = database.datastreams['peers'].dataviews[
            'last_twenty_years']
        self.assertEqual(len(year.bins), 4)
        self.assertEqual(len(twenty_years.bins), 8)
        self.assertTrue(any(year.bins))
        self.assertTrue(any(twenty_years.bins))

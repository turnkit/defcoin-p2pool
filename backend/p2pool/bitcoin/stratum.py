import secrets
import sys
import time

from twisted.internet import protocol, reactor
from twisted.python import log

from p2pool.bitcoin import data as bitcoin_data, getwork
from p2pool.util import expiring_dict, jsonrpc, pack
from p2pool.util.py3 import bytes_to_hex, hex_to_bytes

MAX_ACTIVE_STRATUM_JOBS = 512
MAX_STRATUM_SETUP_CALLS = 64
MAX_STRATUM_CONNECTIONS = 2048

def clip(num, bot, top):
    return min(top, max(bot, num))

class StratumRPCMiningProvider(object):
    def __init__(self, wb, other, transport):
        self.pool_version_mask = 0x1fffe000
        self.wb = wb
        self.other = other
        self.transport = transport
        self._closed = False
        self._send_work_call = None
        self._setup_calls = 0
        
        self.username = None
        self.handler_map = expiring_dict.ExpiringDict(
            300, max_len=MAX_ACTIVE_STRATUM_JOBS)
        
        self.watch_id = self.wb.new_work_event.watch(self._queue_send_work)

        self.recent_shares = []
        self.target = None
        self.share_rate = wb.share_rate
        self.fixed_target = False
        self.desired_pseudoshare_target = None

    
    def rpc_subscribe(self, miner_version=None, session_id=None, *args):
        if not self._allow_setup_call():
            return False
        self._queue_send_work()
        
        return [
            ["mining.notify", "ae6812eb4cd7735a302a8a9dd95cf71f"], # subscription details
            "", # extranonce1
            self.wb.COINBASE_NONCE_LENGTH, # extranonce2_size
        ]
    
    def rpc_authorize(self, username, password):
        if not self._allow_setup_call():
            return False
        if not isinstance(username, str):
            return False
        username = username.strip()
        if not hasattr(self, 'authorized'): # authorize can be called many times in one connection
            print('>>>Authorize: %s' % (
                self.wb.miner_telemetry_identity(username),))
            self.authorized = username
        self.username = username
        
        self.user, self.address, self.desired_share_target, self.desired_pseudoshare_target = self.wb.get_user_details(username)
        self._queue_send_work()
        return True

    def rpc_configure(self, extensions, extensionParameters):
        if not self._allow_setup_call():
            return False
        if not isinstance(extensions, list) or not isinstance(extensionParameters, dict):
            return False
        #extensions is a list of extension codes defined in BIP310
        #extensionParameters is a dict of parameters for each extension code
        if 'version-rolling' in extensions:
            #mask from miner is mandatory but we dont use it
            miner_mask = extensionParameters.get('version-rolling.mask')
            if not isinstance(miner_mask, str) or not 1 <= len(miner_mask) <= 8:
                return False
            try:
                miner_mask_value = int(miner_mask, 16)
            except ValueError:
                return False
            #min-bit-count from miner is mandatory but we dont use it
            minbitcount = extensionParameters.get(
                'version-rolling.min-bit-count', 2)
            #according to the spec, pool should return largest mask possible (to support mining proxies)
            return {"version-rolling" : True, "version-rolling.mask" : '{:08x}'.format(self.pool_version_mask & miner_mask_value)}
            #pool can send mining.set_version_mask at any time if the pool mask changes

        if 'minimum-difficulty' in extensions:
            print('Extension method minimum-difficulty not implemented')
        if 'subscribe-extranonce' in extensions:
            print('Extension method subscribe-extranonce not implemented')

    def _allow_setup_call(self):
        self._setup_calls += 1
        if self._setup_calls <= MAX_STRATUM_SETUP_CALLS:
            return True
        self.transport.loseConnection()
        return False

    def _queue_send_work(self, *event):
        if self._closed:
            return
        if self._send_work_call is not None and self._send_work_call.active():
            return
        self._send_work_call = reactor.callLater(0, self._run_queued_send_work)

    def _run_queued_send_work(self):
        self._send_work_call = None
        if not self._closed:
            self._send_work()

    def _send_work(self):
        try:
            x, got_response = self.wb.get_work(*self.wb.preprocess_request('' if self.username is None else self.username))
        except:
            log.err()
            self.transport.loseConnection()
            return
        if self.desired_pseudoshare_target:
            self.fixed_target = True
            self.target = self.desired_pseudoshare_target
            self.target = max(self.target, int(x['bits'].target))
        else:
            self.fixed_target = False
            self.target = x['share_target'] if self.target == None else max(x['min_share_target'], self.target)
        jobid = str(secrets.randbits(128))
        self.other.svc_mining.rpc_set_difficulty(bitcoin_data.target_to_difficulty(self.target)*self.wb.net.DUMB_SCRYPT_DIFF).addErrback(lambda err: None)
        self.other.svc_mining.rpc_notify(
            jobid, # jobid
            bytes_to_hex(getwork._swap4(pack.IntType(256).pack(x['previous_block']))), # prevhash
            bytes_to_hex(x['coinb1']), # coinb1
            bytes_to_hex(x['coinb2']), # coinb2
            [bytes_to_hex(pack.IntType(256).pack(s)) for s in x['merkle_link']['branch']], # merkle_branch
            bytes_to_hex(getwork._swap4(pack.IntType(32).pack(x['version']))), # version
            bytes_to_hex(getwork._swap4(pack.IntType(32).pack(x['bits'].bits))), # nbits
            bytes_to_hex(getwork._swap4(pack.IntType(32).pack(x['timestamp']))), # ntime
            True, # clean_jobs
        ).addErrback(lambda err: None)
        self.handler_map[jobid] = x, got_response
    
    def rpc_submit(self, worker_name, job_id, extranonce2, ntime, nonce, version_bits = None, *args):
        #asicboost: version_bits is the version mask that the miner used
        if not isinstance(worker_name, str) or not isinstance(job_id, str):
            return False
        worker_name = worker_name.strip()
        if job_id not in self.handler_map:
            print('''Couldn't link returned work's job id with its handler. This should only happen if this process was recently restarted!''', file=sys.stderr)
            #self.other.svc_client.rpc_reconnect().addErrback(lambda err: None)
            return False
        x, got_response = self.handler_map[job_id]
        try:
            coinb_nonce = hex_to_bytes(extranonce2)
            packed_ntime = hex_to_bytes(ntime)
            packed_nonce = hex_to_bytes(nonce)
        except (TypeError, ValueError):
            return False
        if (len(coinb_nonce) != self.wb.COINBASE_NONCE_LENGTH or
                len(packed_ntime) != 4 or len(packed_nonce) != 4):
            return False
        new_packed_gentx = x['coinb1'] + coinb_nonce + x['coinb2']

        job_version = x['version']
        nversion = job_version
        #check if miner changed bits that they were not supposed to change
        if version_bits:
            if not isinstance(version_bits, str) or not 1 <= len(version_bits) <= 8:
                return False
            try:
                submitted_version_bits = int(version_bits, 16)
            except ValueError:
                return False
            if ((~self.pool_version_mask) & submitted_version_bits) != 0:
                return False
            nversion = (job_version & ~self.pool_version_mask) | (submitted_version_bits & self.pool_version_mask)
            #nversion = nversion & int(version_bits,16)

        header = dict(
            version=nversion,
            previous_block=x['previous_block'],
            merkle_root=bitcoin_data.check_merkle_link(bitcoin_data.hash256(new_packed_gentx), x['merkle_link']), # new_packed_gentx has witness data stripped
            timestamp=pack.IntType(32).unpack(getwork._swap4(packed_ntime)),
            bits=x['bits'],
            nonce=pack.IntType(32).unpack(getwork._swap4(packed_nonce)),
        )
        result = got_response(header, worker_name, coinb_nonce, self.target)

        # adjust difficulty on this stratum to target ~10sec/pseudoshare
        if not self.fixed_target:
            self.recent_shares.append(time.time())
            if len(self.recent_shares) > 12 or (time.time() - self.recent_shares[0]) > 10*len(self.recent_shares)*self.share_rate:
                old_time = self.recent_shares[0]
                del self.recent_shares[0]
                olddiff = bitcoin_data.target_to_difficulty(self.target)
                self.target = int(self.target * clip((time.time() - old_time)/(len(self.recent_shares)*self.share_rate), 0.5, 2.) + 0.5)
                newtarget = clip(self.target, self.wb.net.SANE_TARGET_RANGE[0], self.wb.net.SANE_TARGET_RANGE[1])
                if newtarget != self.target:
                    print("Clipping target from %064x to %064x" % (self.target, newtarget))
                    self.target = newtarget
                self.target = max(x['min_share_target'], self.target)
                self.recent_shares = [time.time()]
                self._queue_send_work()

        return result

    
    def close(self):
        if self._closed:
            return
        self._closed = True
        if self._send_work_call is not None:
            if self._send_work_call.active():
                self._send_work_call.cancel()
            self._send_work_call = None
        self.wb.new_work_event.unwatch(self.watch_id)
        self.handler_map.stop()

class StratumProtocol(jsonrpc.LineBasedPeer):
    def connectionMade(self):
        self.svc_mining = StratumRPCMiningProvider(self.factory.wb, self.other, self.transport)
    
    def connectionLost(self, reason):
        if hasattr(self, 'svc_mining'):
            self.svc_mining.close()
        if getattr(self, '_registered', False):
            self._registered = False
            self.factory.unregister_connection()

class StratumServerFactory(protocol.ServerFactory):
    protocol = StratumProtocol
    
    def __init__(self, wb):
        self.wb = wb
        self.active_connections = 0

    def register_connection(self):
        if self.active_connections >= MAX_STRATUM_CONNECTIONS:
            return False
        self.active_connections += 1
        return True

    def buildProtocol(self, addr):
        if not self.register_connection():
            return None
        result = self.protocol()
        result.factory = self
        result._registered = True
        return result

    def unregister_connection(self):
        if self.active_connections:
            self.active_connections -= 1

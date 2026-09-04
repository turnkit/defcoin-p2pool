
from collections import OrderedDict, deque

import base64
import hashlib
import random
import re
import secrets
import sys
import time

from twisted.internet import defer
from twisted.python import log

from .bitcoin import getwork as bitcoin_getwork, data as bitcoin_data
from .bitcoin import helper, script, worker_interface
from .util import expiring_dict, forest, jsonrpc, variable, deferral, math, pack
from .util.py3 import bytes_to_hex, hex_to_bytes, ensure_bytes
import p2pool, p2pool.data as p2pool_data

print_throttle = 0.0
MINER_LAST_SEEN_KEEP = 90*24*60*60
MAX_MINER_IDENTITIES = 4096
MAX_MINER_IDENTITY_LENGTH = 256
MAX_RATE_DATUMS = 65536

def miner_telemetry_identity(user):
    """Return a bounded, log-safe identity without changing payout routing."""
    if not isinstance(user, str):
        return None
    if (len(user) <= MAX_MINER_IDENTITY_LENGTH and user.isprintable() and
            '\r' not in user and '\n' not in user):
        return user
    digest = hashlib.sha256(
        user.encode('utf-8', errors='surrogatepass')).hexdigest()
    return 'worker-sha256:' + digest

class WorkerBridge(worker_interface.WorkerBridge):
    COINBASE_NONCE_LENGTH = 8

    @staticmethod
    def miner_telemetry_identity(user):
        return miner_telemetry_identity(user)
    
    def __init__(self, node, my_address, donation_percentage, merged_urls,
                 worker_fee, args, pubkeys, bitcoind, share_rate):
        worker_interface.WorkerBridge.__init__(self)
        self.recent_shares_ts_work = []
        
        self.node = node

        self.bitcoind = bitcoind
        self.pubkeys = pubkeys
        self.args = args
        self.address = my_address

        self.donation_percentage = args.donation_percentage
        self.worker_fee = args.worker_fee
        
        self.net = self.node.net.PARENT
        self.running = True
        self.pseudoshare_received = variable.Event()
        self.share_received = variable.Event()
        self.local_rate_monitor = math.RateMonitor(
            10*60, max_len=MAX_RATE_DATUMS)
        self.local_addr_rate_monitor = math.RateMonitor(
            10*60, max_len=MAX_RATE_DATUMS)
        self.miner_last_seen_times = expiring_dict.ExpiringDict(
            MINER_LAST_SEEN_KEEP, get_touches=False,
            max_len=MAX_MINER_IDENTITIES)
        
        self.removed_unstales_var = variable.Variable((0, 0, 0))
        self.removed_doa_unstales_var = variable.Variable(0)
        
        self.last_work_shares = variable.Variable(OrderedDict())
        self.my_share_hashes = set()
        self.my_doa_share_hashes = set()

        self.address_throttle = 0
        self.share_rate = share_rate
        
        self.tracker_view = forest.TrackerView(self.node.tracker, forest.get_attributedelta_type(dict(forest.AttributeDelta.attrs,
            my_count=lambda share: 1 if share.hash in self.my_share_hashes else 0,
            my_doa_count=lambda share: 1 if share.hash in self.my_doa_share_hashes else 0,
            my_orphan_announce_count=lambda share: 1 if share.hash in self.my_share_hashes and share.share_data['stale_info'] == 'orphan' else 0,
            my_dead_announce_count=lambda share: 1 if share.hash in self.my_share_hashes and share.share_data['stale_info'] == 'doa' else 0,
        )))
        
        @self.node.tracker.verified.removed.watch
        def _(share):
            if share.hash in self.my_share_hashes and self.node.tracker.is_child_of(share.hash, self.node.best_share_var.value):
                assert share.share_data['stale_info'] in [None, 'orphan', 'doa'] # we made these shares in this instance
                self.removed_unstales_var.set((
                    self.removed_unstales_var.value[0] + 1,
                    self.removed_unstales_var.value[1] + (1 if share.share_data['stale_info'] == 'orphan' else 0),
                    self.removed_unstales_var.value[2] + (1 if share.share_data['stale_info'] == 'doa' else 0),
                ))
            if share.hash in self.my_doa_share_hashes and self.node.tracker.is_child_of(share.hash, self.node.best_share_var.value):
                self.removed_doa_unstales_var.set(self.removed_doa_unstales_var.value + 1)
        
        # MERGED WORK
        
        self.merged_work = variable.Variable({})
        
        @defer.inlineCallbacks
        def set_merged_work(merged_url, merged_userpass):
            merged_proxy = jsonrpc.HTTPProxy(merged_url, dict(
                Authorization='Basic ' + base64.b64encode(ensure_bytes(merged_userpass)).decode('ascii')))
            while self.running:
                auxblock = yield deferral.retry('Error while calling merged getauxblock on %s:' % (merged_url,), 30)(merged_proxy.rpc_getauxblock)()
                target = auxblock['target'] if 'target' in auxblock else auxblock['_target']
                self.merged_work.set(math.merge_dicts(self.merged_work.value, {auxblock['chainid']: dict(
                    hash=int(auxblock['hash'], 16),
                    target='p2pool' if target == 'p2pool' else pack.IntType(256).unpack(hex_to_bytes(target)),
                    merged_proxy=merged_proxy,
                )}))
                yield deferral.sleep(1)
        for merged_url, merged_userpass in merged_urls:
            set_merged_work(merged_url, merged_userpass)
        
        @self.merged_work.changed.watch
        def _(new_merged_work):
            print('Got new merged mining work!')
        
        # COMBINE WORK
        
        self.current_work = variable.Variable(None)
        def compute_work():
            t = self.node.bitcoind_work.value
            bb = self.node.best_block_header.value
            if bb is not None and bb['previous_block'] == t['previous_block'] and self.node.net.PARENT.POW_FUNC(bitcoin_data.block_header_type.pack(bb)) <= t['bits'].target:
                print('Skipping from block %x to block %x!' % (bb['previous_block'],
                    bitcoin_data.hash256(bitcoin_data.block_header_type.pack(bb))))
                t = dict(
                    version=bb['version'],
                    previous_block=bitcoin_data.hash256(bitcoin_data.block_header_type.pack(bb)),
                    bits=bb['bits'], # not always true
                    coinbaseflags='',
                    height=t['height'] + 1,
                    time=max(int(time.time() + 0.5), bb['timestamp'] + 1),
                    transactions=[],
                    transaction_hashes=[],
                    transaction_fees=[],
                    merkle_link=bitcoin_data.calculate_merkle_link([None], 0),
                    subsidy=self.node.net.PARENT.SUBSIDY_FUNC(self.node.bitcoind_work.value['height']),
                    last_update=self.node.bitcoind_work.value['last_update'],
                )
            
            self.current_work.set(t)
        self.node.bitcoind_work.changed.watch(lambda _: compute_work())
        self.node.best_block_header.changed.watch(lambda _: compute_work())
        compute_work()
        
        self.new_work_event = variable.Event()

        @self.current_work.transitioned.watch
        def _(before, after):
            # trigger LP if version/previous_block/bits changed or transactions changed from nothing
            if any(before[x] != after[x] for x in ['version', 'previous_block', 'bits']) or (not before['transactions'] and after['transactions']):
                self.new_work_event.happened()
        self.merged_work.changed.watch(lambda _: self.new_work_event.happened())
        self.node.best_share_var.changed.watch(lambda _: self.new_work_event.happened())
    
    def stop(self):
        self.running = False
        self.miner_last_seen_times.stop()

    def note_miner_seen(self, user, now=None):
        user = miner_telemetry_identity(user)
        if user is None:
            return
        if now is None:
            now = time.time()
        self.miner_last_seen_times[user] = now
    
    def get_stale_counts(self):
        '''Returns (orphans, doas), total, (orphans_recorded_in_chain, doas_recorded_in_chain)'''
        my_shares = len(self.my_share_hashes)
        my_doa_shares = len(self.my_doa_share_hashes)
        delta = self.tracker_view.get_delta_to_last(self.node.best_share_var.value)
        my_shares_in_chain = delta.my_count + self.removed_unstales_var.value[0]
        my_doa_shares_in_chain = delta.my_doa_count + self.removed_doa_unstales_var.value
        orphans_recorded_in_chain = delta.my_orphan_announce_count + self.removed_unstales_var.value[1]
        doas_recorded_in_chain = delta.my_dead_announce_count + self.removed_unstales_var.value[2]
        
        my_shares_not_in_chain = my_shares - my_shares_in_chain
        my_doa_shares_not_in_chain = my_doa_shares - my_doa_shares_in_chain
        
        return (my_shares_not_in_chain - my_doa_shares_not_in_chain, my_doa_shares_not_in_chain), my_shares, (orphans_recorded_in_chain, doas_recorded_in_chain)
    
    @defer.inlineCallbacks
    def freshen_addresses(self, c):
        self.cur_address_throttle = time.time()
        if self.cur_address_throttle - self.address_throttle < 30:
            return
        self.address_throttle=time.time()
        print("ATTEMPTING TO FRESHEN ADDRESS.")
        self.address = yield deferral.retry('Error getting a dynamic address from bitcoind:', 5)(lambda: self.bitcoind.rpc_getnewaddress('p2pool'))()
        self.pubkeys.popleft()
        self.pubkeys.addkey({'address': self.address})
        print(" Updated payout pool:")
        for i in range(len(self.pubkeys.keys)):
            print(('    ...payout %d: %s(%f)' %
                    (i, self.address, self.pubkeys.keyweights[i])))
        self.pubkeys.updatestamp(c)
        print(" Next address rotation in : %fs" % (time.time()-c+self.args.timeaddresses))
 
    def get_user_details(self, username):
        contents = re.split('([+/])', username)
        assert len(contents) % 2 == 1
        
        user, contents2 = contents[0], contents[1:]
        worker = ''
        if '_' in user:
            worker = user.split('_')[1]
            user = user.split('_')[0]
        elif '.' in user:
            worker = user.split('.')[1]
            user = user.split('.')[0]

        desired_pseudoshare_target = None
        desired_share_target = None
        for symbol, parameter in zip(contents2[::2], contents2[1::2]):
            if symbol == '+':
                try:
                    desired_pseudoshare_target = bitcoin_data.difficulty_to_target(float(parameter))
                except:
                    if p2pool.DEBUG:
                        log.err()
            elif symbol == '/':
                try:
                    desired_share_target = bitcoin_data.difficulty_to_target(float(parameter))
                except:
                    if p2pool.DEBUG:
                        log.err()

        if self.args.address == 'dynamic':
            i = self.pubkeys.weighted()
            address = self.pubkeys.keys[i]['address']

            c = time.time()
            if (c - self.pubkeys.stamp) > self.args.timeaddresses:
                self.freshen_addresses(c)

        if random.uniform(0, 100) < self.worker_fee:
            address = self.address
        else:
            try:
                if self.node.best_share_var.value is not None:
                    share_type = type(self.node.tracker.items[self.node.best_share_var.value])
                else:
                    share_type = p2pool_data.Share

                ret = bitcoin_data.address_to_pubkey_hash(user, self.node.net.PARENT)
                if share_type.VERSION < 34 and ret[1] != self.node.net.PARENT.ADDRESS_VERSION:
                    print(("not supporting %s yet, share version needs to be 34, but is %s."
                            % (user, share_type.VERSION)))
                    raise ValueError
                address = user
            except Exception: # XXX blah
                if self.args.address != 'dynamic':
                    address = self.address
        if worker:
            user = user + '.' + worker
        return (user, address, desired_share_target, desired_pseudoshare_target)
    
    def preprocess_request(self, user):
        if (self.node.p2p_node is None or len(self.node.p2p_node.peers) == 0) and self.node.net.PERSIST:
            raise jsonrpc.Error_for_code(-12345)('p2pool is not connected to any peers')
        if time.time() > self.current_work.value['last_update'] + 60:
            raise jsonrpc.Error_for_code(-12345)('lost contact with bitcoind')
        return self.get_user_details(user)
    
    def _estimate_local_hash_rate(self):
        if len(self.recent_shares_ts_work) == 50:
            hash_rate = sum(work for ts, work in self.recent_shares_ts_work[1:])//(self.recent_shares_ts_work[-1][0] - self.recent_shares_ts_work[0][0])
            if hash_rate > 0:
                return hash_rate
        return None
    
    def get_local_rates(self):
        miner_hash_rates = OrderedDict()
        miner_dead_hash_rates = OrderedDict()
        datums, dt = self.local_rate_monitor.get_datums_in_last()
        if dt <= 0:
            return {}, {}
        for datum in datums:
            user = datum['user']
            if user in miner_hash_rates:
                miner_hash_rates.move_to_end(user)
            elif len(miner_hash_rates) >= MAX_MINER_IDENTITIES:
                evicted_user, _ = miner_hash_rates.popitem(last=False)
                miner_dead_hash_rates.pop(evicted_user, None)
            miner_hash_rates[datum['user']] = miner_hash_rates.get(datum['user'], 0) + datum['work']/dt
            if datum['dead']:
                miner_dead_hash_rates[datum['user']] = miner_dead_hash_rates.get(datum['user'], 0) + datum['work']/dt
        return dict(miner_hash_rates), dict(miner_dead_hash_rates)
    
    def get_local_addr_rates(self):
        addr_hash_rates = OrderedDict()
        datums, dt = self.local_addr_rate_monitor.get_datums_in_last()
        if dt <= 0:
            return {}
        for datum in datums:
            address = datum['address']
            if address in addr_hash_rates:
                addr_hash_rates.move_to_end(address)
            elif len(addr_hash_rates) >= MAX_MINER_IDENTITIES:
                addr_hash_rates.popitem(last=False)
            addr_hash_rates[address] = \
                    addr_hash_rates.get(address, 0) + datum['work']/dt
        return dict(addr_hash_rates)
 
    def get_work(self, user, address, desired_share_target,
                 desired_pseudoshare_target, worker_ip=None):
        global print_throttle
        t0 = time.time()
        if (self.node.p2p_node is None or len(self.node.p2p_node.peers) == 0) and self.node.net.PERSIST:
            raise jsonrpc.Error_for_code(-12345)('p2pool is not connected to any peers')
        if self.node.best_share_var.value is None and self.node.net.PERSIST:
            raise jsonrpc.Error_for_code(-12345)('p2pool is downloading shares')
        unknown_rules = set(r[1:] if r.startswith('!') else r for r in self.node.bitcoind_work.value['rules'] if r) - set(getattr(self.node.net, 'SOFTFORKS_REQUIRED', []))
        if unknown_rules:
            print("Unknown softforks found: ", unknown_rules)
            print("Required softforks: ", self.node.bitcoind_work.value['rules'], "\tKnown: ", getattr(self.node.net, 'SOFTFORKS_REQUIRED', []))
            raise jsonrpc.Error_for_code(-12345)('unknown rule activated')
        
        if self.merged_work.value:
            tree, size = bitcoin_data.make_auxpow_tree(self.merged_work.value)
            mm_hashes = [self.merged_work.value.get(tree.get(i), dict(hash=0))['hash'] for i in range(size)]
            mm_data = b'\xfa\xbemm' + bitcoin_data.aux_pow_coinbase_type.pack(dict(
                merkle_root=bitcoin_data.merkle_hash(mm_hashes),
                size=size,
                nonce=0,
            ))
            mm_later = [(aux_work, mm_hashes.index(aux_work['hash']), mm_hashes) for chain_id, aux_work in self.merged_work.value.items()]
        else:
            mm_data = b''
            mm_later = []
        
        tx_hashes = self.current_work.value['transaction_hashes']
        tx_map = dict(list(zip(tx_hashes, self.current_work.value['transactions'])))

        self.node.mining2_txs_var.set(tx_map) # let node.py know not to evict these transactions
        
        previous_share = self.node.tracker.items[self.node.best_share_var.value] if self.node.best_share_var.value is not None else None
        if previous_share is None:
            share_type = p2pool_data.Share
        else:
            previous_share_type = type(previous_share)
            
            if previous_share_type.SUCCESSOR is None or self.node.tracker.get_height(previous_share.hash) < self.node.net.CHAIN_LENGTH:
                share_type = previous_share_type
            else:
                successor_type = previous_share_type.SUCCESSOR

                if (
                        successor_type is p2pool_data.DonationDustFixedShare and
                        p2pool_data.dustfix_flag_day_enabled(self.node.net)):
                    share_type = successor_type
                else:
                    counts = p2pool_data.get_desired_version_counts(self.node.tracker,
                        self.node.tracker.get_nth_parent_hash(previous_share.hash, self.node.net.CHAIN_LENGTH*9//10), self.node.net.CHAIN_LENGTH//10)
                    upgraded = counts.get(successor_type.VERSION, 0)/sum(counts.values())
                    if upgraded > .65:
                        print('Switchover imminent. Upgraded: %.3f%% Threshold: %.3f%%' % (upgraded*100, 95))
                    # Share -> NewShare only valid if 95% of hashes in [net.CHAIN_LENGTH*9//10, net.CHAIN_LENGTH] for new version
                    if counts.get(successor_type.VERSION, 0) > sum(counts.values())*95//100:
                        share_type = successor_type
                    else:
                        share_type = previous_share_type
        
        if desired_share_target is None:
            desired_share_target = 2**256-1
            local_hash_rate = self._estimate_local_hash_rate()
            if local_hash_rate is not None:
                desired_share_target = min(desired_share_target,
                    bitcoin_data.average_attempts_to_target(local_hash_rate * self.node.net.SHARE_PERIOD / 0.0167)) # limit to 1.67% of pool shares by modulating share difficulty
            
            if self.node.punish:
                print("trying to punish a share by mining a low-diff share")
                desired_share_target = bitcoin_data.difficulty_to_target(1.)
            local_addr_rates = self.get_local_addr_rates()
            lookbehind = 3600//self.node.net.SHARE_PERIOD
            block_subsidy = self.node.bitcoind_work.value['subsidy']
            if previous_share is not None and self.node.tracker.get_height(previous_share.hash) > lookbehind:
                expected_payout_per_block = local_addr_rates.get(address, 0)/p2pool_data.get_pool_attempts_per_second(self.node.tracker, self.node.best_share_var.value, lookbehind) \
                    * block_subsidy*(1-self.donation_percentage/100) # XXX doesn't use global stale rate to compute pool hash
                if expected_payout_per_block < self.node.net.PARENT.DUST_THRESHOLD:
                    desired_share_target = min(desired_share_target,
                        bitcoin_data.average_attempts_to_target((bitcoin_data.target_to_average_attempts(self.node.bitcoind_work.value['bits'].target)*self.node.net.SPREAD)*self.node.net.PARENT.DUST_THRESHOLD/block_subsidy)
                    )
        
        if True:
            share_info, gentx, other_transaction_hashes, get_share = share_type.generate_transaction(
                tracker=self.node.tracker,
                share_data=dict(
                    previous_share_hash=self.node.best_share_var.value,
                    coinbase=(script.create_push_script([
                        self.current_work.value['height'],
                        ] + ([mm_data] if mm_data else []) + [ensure_bytes(x) for x in self.args.coinb_texts]
                    ) + ensure_bytes(self.current_work.value['coinbaseflags']))[:100],
                    nonce=secrets.randbits(32),
                    address=address,
                    subsidy=self.current_work.value['subsidy'],
                    donation=(
                        math.perfect_round(65535*self.donation_percentage/100)
                        if share_type.PAYS_LEGACY_DONATION else 0),
                    stale_info=(lambda stale, total, recorded:
                        'orphan' if stale[0] > recorded[0] else
                        'doa' if stale[1] > recorded[1] else
                        None
                    )(*self.get_stale_counts()),
                    desired_version=(share_type.SUCCESSOR if share_type.SUCCESSOR is not None else share_type).VOTING_VERSION,
                ),
                block_target=self.current_work.value['bits'].target,
                desired_timestamp=int(time.time() + 0.5),
                desired_target=desired_share_target,
                ref_merkle_link=dict(branch=[], index=0),
                desired_other_transaction_hashes_and_fees=list(zip(tx_hashes, self.current_work.value['transaction_fees'])),
                net=self.node.net,
                known_txs=tx_map,
                base_subsidy=self.node.net.PARENT.SUBSIDY_FUNC(self.current_work.value['height']),
            )
        
        packed_gentx = bitcoin_data.tx_id_type.pack(gentx) # stratum miners work with stripped transactions
        other_transactions = [tx_map[tx_hash] for tx_hash in other_transaction_hashes]

        del tx_hashes
        if (self.node.cur_share_ver or 0) >= 34:
            tx_map = {} # we can free up this memory now
        
        mm_later = [(dict(aux_work, target=aux_work['target'] if aux_work['target'] != 'p2pool' else share_info['bits'].target), index, hashes) for aux_work, index, hashes in mm_later]
        
        if desired_pseudoshare_target is None:
            target = 2**256-1
            local_hash_rate = self._estimate_local_hash_rate()
            if local_hash_rate is not None:
                target = min(target,
                    bitcoin_data.average_attempts_to_target(local_hash_rate / 10)) # target no more than 10 share responses every second node-wide by modulating min pseudoshare difficulty
            else:
                # If we don't yet have an estimated node hashrate, then we still need to not undershoot the difficulty.
                # Otherwise, we might get 1 PH/s of hashrate on difficulty settings appropriate for 1 GH/s.
                # 1/3000th the difficulty of a full share should be a reasonable upper bound. That way, if
                # one node has the whole p2pool hashrate, it will still only need to process one pseudoshare
                # every ~0.01 seconds.
                block_subsidy = self.node.bitcoind_work.value['subsidy']
                target = min(target, 3000 * bitcoin_data.average_attempts_to_target((bitcoin_data.target_to_average_attempts(
                    self.node.bitcoind_work.value['bits'].target)*self.node.net.SPREAD)*self.node.net.PARENT.DUST_THRESHOLD/block_subsidy))
        else:
            target = desired_pseudoshare_target
        target = max(target, share_info['bits'].target)
        for aux_work, index, hashes in mm_later:
            target = max(target, aux_work['target'])
        target = math.clip(target, self.node.net.PARENT.SANE_TARGET_RANGE)
        
        getwork_time = time.time()
        lp_count = self.new_work_event.times
        merkle_link = bitcoin_data.calculate_merkle_link([None] + other_transaction_hashes, 0) if share_info.get('segwit_data', None) is None else share_info['segwit_data']['txid_merkle_link']
        del other_transaction_hashes

        if print_throttle == 0.0:
            print_throttle = time.time()
        else:
            current_time = time.time()
            if (current_time - print_throttle) > 5.0:
                print('New work! Share diff: %.02f Block value: %.2f %s (%i tx, %.0f kB)' % (
                    bitcoin_data.target_to_difficulty(share_info['bits'].target),
                    self.current_work.value['subsidy']*1e-8, self.node.net.PARENT.SYMBOL,
                    len(self.current_work.value['transactions']),
                    sum((bitcoin_data.get_size(tx) for tx in self.current_work.value['transactions']))/1000.,
                ))
                print_throttle = time.time()

        #need this for stats
        self.last_work_shares.value.pop(address, None)
        self.last_work_shares.value[address] = share_info['bits']
        if len(self.last_work_shares.value) > MAX_MINER_IDENTITIES:
            self.last_work_shares.value.popitem(last=False)
        
        ba = dict(
            version=max(self.current_work.value['version'], 0x20000000),
            previous_block=self.current_work.value['previous_block'],
            merkle_link=merkle_link,
            coinb1=packed_gentx[:-self.COINBASE_NONCE_LENGTH-4],
            coinb2=packed_gentx[-4:],
            timestamp=self.current_work.value['time'],
            bits=self.current_work.value['bits'],
            min_share_target=share_info['bits'].target,
            share_target=target,
        )
        
        received_header_hashes = set()
        
        def got_response(header, username, coinbase_nonce, pseudoshare_target):
            t0 = time.time()
            assert len(coinbase_nonce) == self.COINBASE_NONCE_LENGTH
            new_packed_gentx = packed_gentx[:-self.COINBASE_NONCE_LENGTH-4] + coinbase_nonce + packed_gentx[-4:] if coinbase_nonce != '\0'*self.COINBASE_NONCE_LENGTH else packed_gentx
            new_gentx = bitcoin_data.tx_type.unpack(new_packed_gentx) if coinbase_nonce != '\0'*self.COINBASE_NONCE_LENGTH else gentx
            if bitcoin_data.is_segwit_tx(gentx): # reintroduce witness data to the gentx produced by stratum miners
                new_gentx['marker'] = 0
                new_gentx['flag'] = gentx['flag']
                new_gentx['witness'] = gentx['witness']
            
            header_hash = bitcoin_data.hash256(bitcoin_data.block_header_type.pack(header))
            pow_hash = self.node.net.PARENT.POW_FUNC(bitcoin_data.block_header_type.pack(header))
            got_response.last_submission_met_share_target = \
                pow_hash <= share_info['bits'].target
            try:
                if pow_hash <= header['bits'].target or p2pool.DEBUG:
                    if pow_hash <= header['bits'].target:
                        print()
                        print('GOT BLOCK FROM MINER! Passing to bitcoind! %s%064x' % (self.node.net.PARENT.BLOCK_EXPLORER_URL_PREFIX, header_hash))
                        print()
                    helper.submit_block(dict(header=header, txs=[new_gentx] + other_transactions), False, self.node)
            except:
                log.err(None, 'Error while processing potential block:')
            
            username, _, _, _ = self.get_user_details(username)
            telemetry_username = miner_telemetry_identity(username)
            assert header['previous_block'] == ba['previous_block']
            assert header['merkle_root'] == bitcoin_data.check_merkle_link(bitcoin_data.hash256(new_packed_gentx), merkle_link)
            assert header['bits'] == ba['bits']
            
            on_time = self.new_work_event.times == lp_count
            
            for aux_work, index, hashes in mm_later:
                try:
                    if pow_hash <= aux_work['target'] or p2pool.DEBUG:
                        df = deferral.retry('Error submitting merged block: (will retry)', 10, 10)(aux_work['merged_proxy'].rpc_getauxblock)(
                            bytes_to_hex(pack.IntType(256, 'big').pack(aux_work['hash'])),
                            bytes_to_hex(bitcoin_data.aux_pow_type.pack(dict(
                                merkle_tx=dict(
                                    tx=new_gentx,
                                    block_hash=header_hash,
                                    merkle_link=merkle_link,
                                ),
                                merkle_link=bitcoin_data.calculate_merkle_link(hashes, index),
                                parent_block_header=header,
                            ))),
                        )
                        @df.addCallback
                        def _(result, aux_work=aux_work):
                            if result != (pow_hash <= aux_work['target']):
                                print('Merged block submittal result: %s Expected: %s' % (result, pow_hash <= aux_work['target']), file=sys.stderr)
                            else:
                                print('Merged block submittal result: %s' % (result,))
                        @df.addErrback
                        def _(err):
                            log.err(err, 'Error submitting merged block:')
                except:
                    log.err(None, 'Error while processing merged mining POW:')
            
            if pow_hash <= share_info['bits'].target and header_hash not in received_header_hashes:
                last_txout_nonce = pack.IntType(8*self.COINBASE_NONCE_LENGTH).unpack(coinbase_nonce)
                share = get_share(header, last_txout_nonce)
                
                print('GOT SHARE! %s %s prev %s age %.2fs%s' % (
                    telemetry_username,
                    p2pool_data.format_hash(share.hash),
                    p2pool_data.format_hash(share.previous_hash),
                    time.time() - getwork_time,
                    ' DEAD ON ARRIVAL' if not on_time else '',
                ))

                if (self.node.cur_share_ver or 0) < 34:
                    # node.py will sometimes forget transactions if bitcoind's work has changed since this stratum
                    # job was assigned. Fortunately, the tx_map is still in in our scope from this job, so we can use that
                    # to refill it if needed.

                    known_txs = self.node.known_txs_var.value
                    missing = {hsh:val for (hsh, val) in tx_map.items() if not hsh in known_txs}
                    if missing:
                        print("Warning: %i transactions were erroneously evicted from known_txs_var. Refilling now." % len(missing))
                        self.node.known_txs_var.add(missing)

                self.my_share_hashes.add(share.hash)
                if not on_time:
                    self.my_doa_share_hashes.add(share.hash)
                
                sibling_count = len(self.node.tracker.reverse.get(share.previous_hash, set()))
                if on_time or sibling_count < 4:
                    self.node.tracker.add(share)
                else:
                    print("Already have %i DOA shares with this parent. Not adding more." % sibling_count)
                if on_time:
                    self.node.set_best_share()
                else:
                    print("Not considering work switching to DOA share")
                
                try:
                    if (pow_hash <= header['bits'].target or p2pool.DEBUG) and self.node.p2p_node is not None:
                        self.node.p2p_node.broadcast_share(share.hash)
                except:
                    log.err(None, 'Error forwarding block solution:')
                
                self.share_received.happened(bitcoin_data.target_to_average_attempts(share.target), not on_time, share.hash)

            if pow_hash > pseudoshare_target:
                print('Worker %s submitted share with hash > target:' % (telemetry_username,))
                print('    Hash:   %064x' % (pow_hash,))
                print('    Target: %064x' % (pseudoshare_target,))
            elif header_hash in received_header_hashes:
                print('Worker %s submitted share more than once!' % (telemetry_username,), file=sys.stderr)
            else:
                received_header_hashes.add(header_hash)
                
                now = time.time()
                self.note_miner_seen(telemetry_username, now)
                self.pseudoshare_received.happened(bitcoin_data.target_to_average_attempts(pseudoshare_target), not on_time, telemetry_username)
                self.recent_shares_ts_work.append((now, bitcoin_data.target_to_average_attempts(pseudoshare_target)))
                while len(self.recent_shares_ts_work) > 50:
                    self.recent_shares_ts_work.pop(0)
                self.local_rate_monitor.add_datum(dict(work=bitcoin_data.target_to_average_attempts(pseudoshare_target), dead=not on_time, user=telemetry_username, share_target=share_info['bits'].target))
                self.local_addr_rate_monitor.add_datum(dict(work=bitcoin_data.target_to_average_attempts(pseudoshare_target), address=address))
            t1 = time.time()
            if p2pool.BENCH and (t1-t0) > .01: print("%8.3f ms for work.py:got_response(%s)" % ((t1-t0)*1000., telemetry_username))

            return on_time
        got_response.last_submission_met_share_target = False
        t1 = time.time()
        if p2pool.BENCH: print("%8.3f ms for work.py:get_work(%s, %s)" % ((t1-t0)*1000., user, address))
        return ba, got_response

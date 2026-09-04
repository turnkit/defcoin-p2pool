from twisted.internet import task
from twisted.trial import unittest

from p2pool import work
from p2pool.bitcoin import stratum
from p2pool.util import variable


class _Transport(object):
    def __init__(self):
        self.disconnects = 0

    def loseConnection(self):
        self.disconnects += 1


class _WorkerBridge(object):
    COINBASE_NONCE_LENGTH = 8
    share_rate = 1

    def __init__(self):
        self.new_work_event = variable.Event()

    def get_user_details(self, username):
        return username, 'address', None, None

    @staticmethod
    def miner_telemetry_identity(username):
        return work.miner_telemetry_identity(username)


class TestStratumSecurity(unittest.TestCase):
    def setUp(self):
        self.clock = task.Clock()
        self.patch(stratum, 'reactor', self.clock)
        self.wb = _WorkerBridge()
        self.transport = _Transport()
        self.provider = stratum.StratumRPCMiningProvider(
            self.wb, object(), self.transport)

    def tearDown(self):
        self.provider.close()

    def test_setup_calls_coalesce_work_send(self):
        self.provider.rpc_subscribe('miner/1.0')
        self.provider.rpc_authorize('DAddress.worker', 'arbitrary-password')
        self.provider.rpc_configure(
            ['version-rolling'], {
                'version-rolling.mask': '1fffe000',
                'version-rolling.min-bit-count': 2,
            })
        active = [call for call in self.clock.getDelayedCalls() if call.active()]
        self.assertEqual(len(active), 1)
        self.assertEqual(self.provider._setup_calls, 3)

    def test_setup_call_limit_disconnects(self):
        for _ in range(stratum.MAX_STRATUM_SETUP_CALLS):
            self.assertTrue(
                self.provider.rpc_authorize('DAddress.worker', 'anything'))
        self.assertFalse(
            self.provider.rpc_authorize('DAddress.worker', 'anything'))
        self.assertEqual(self.transport.disconnects, 1)

    def test_malformed_configure_is_rejected(self):
        self.assertFalse(self.provider.rpc_configure('version-rolling', {}))
        self.assertFalse(self.provider.rpc_configure(
            ['version-rolling'], {'version-rolling.mask': []}))
        self.assertFalse(self.provider.rpc_configure(
            ['version-rolling'], {'version-rolling.mask': 'not-hex'}))

    def test_unhashable_job_and_invalid_version_mask_are_rejected(self):
        self.assertFalse(self.provider.rpc_submit(
            'worker', [], '00' * 8, '00' * 4, '00' * 4))
        self.provider.handler_map['job'] = ({
            'coinb1': b'',
            'coinb2': b'',
            'version': 0,
        }, object())
        self.assertFalse(self.provider.rpc_submit(
            'worker', 'job', '00' * 8, '00' * 4, '00' * 4,
            'ffffffff'))

    def test_factory_rejects_before_protocol_receives_initial_data(self):
        factory = stratum.StratumServerFactory(self.wb)
        self.patch(stratum, 'MAX_STRATUM_CONNECTIONS', 1)
        first = factory.buildProtocol(object())
        self.assertIsNotNone(first)
        self.assertIsNone(factory.buildProtocol(object()))
        first.connectionLost(None)
        self.assertEqual(factory.active_connections, 0)

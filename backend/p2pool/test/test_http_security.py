import json

from twisted.internet.address import IPv4Address
from twisted.internet.testing import StringTransport, StringTransportWithDisconnection
from twisted.trial import unittest
from twisted.web import resource, server

from p2pool.util import jsonrpc


class _CountingResource(resource.Resource):
    isLeaf = True

    def __init__(self):
        resource.Resource.__init__(self)
        self.requests = []

    def render_POST(self, request):
        self.requests.append(request.content.read())
        return b'ok'


class TestHTTPSizeLimits(unittest.TestCase):
    def _request(self, raw_request):
        root = _CountingResource()
        site = server.Site(
            root, requestFactory=jsonrpc.SizeLimitedRequest,
            parsePOSTFormSubmission=False)
        site.protocol = jsonrpc.SizeLimitedHTTPChannel
        channel = site.buildProtocol(IPv4Address('TCP', '127.0.0.1', 12345))
        transport = StringTransportWithDisconnection()
        transport.protocol = channel
        channel.makeConnection(transport)
        channel.dataReceived(raw_request)
        return transport.value(), root

    def test_declared_body_at_limit_reaches_resource(self):
        body = b'x' * jsonrpc.MAX_HTTP_JSON_REQUEST_SIZE
        response, root = self._request(
            b'POST / HTTP/1.1\r\nHost: example\r\nContent-Length: ' +
            str(len(body)).encode('ascii') + b'\r\nConnection: close\r\n\r\n' +
            body)
        self.assertIn(b'200 OK', response)
        self.assertEqual(root.requests, [body])

    def test_declared_body_over_limit_rejected_before_continue(self):
        response, root = self._request(
            b'POST / HTTP/1.1\r\nHost: example\r\nExpect: 100-continue\r\n'
            b'Content-Length: 65537\r\n\r\n')
        self.assertIn(b'413 Payload Too Large', response)
        self.assertNotIn(b'100 Continue', response)
        self.assertEqual(root.requests, [])

    def test_chunked_body_crossing_limit_is_rejected(self):
        first = b'x' * jsonrpc.MAX_HTTP_JSON_REQUEST_SIZE
        response, root = self._request(
            b'POST / HTTP/1.1\r\nHost: example\r\n'
            b'Transfer-Encoding: chunked\r\n\r\n' +
            b'10000\r\n' + first + b'\r\n1\r\ny\r\n0\r\n\r\n')
        self.assertIn(b'413 Payload Too Large', response)
        self.assertEqual(root.requests, [])

    def test_duplicate_content_length_is_bad_request(self):
        response, root = self._request(
            b'POST / HTTP/1.1\r\nHost: example\r\n'
            b'Content-Length: 1\r\nContent-Length: 1\r\n\r\nx')
        self.assertIn(b'400 Bad Request', response)
        self.assertEqual(root.requests, [])

    def test_jsonrpc_scalar_is_controlled_invalid_request(self):
        result = self.successResultOf(jsonrpc._handle(b'[]', object()))
        parsed = json.loads(result)
        self.assertEqual(parsed['error']['code'], -32600)


class _LinePeer(jsonrpc.LineBasedPeer):
    def __init__(self):
        jsonrpc.LineBasedPeer.__init__(self)
        self.lines = []

    def lineReceived(self, line):
        self.lines.append(line)


class TestStratumLineLimit(unittest.TestCase):
    def _peer(self):
        peer = _LinePeer()
        transport = StringTransport()
        peer.makeConnection(transport)
        return peer, transport

    def test_exact_limit_is_accepted(self):
        peer, transport = self._peer()
        line = b'x' * jsonrpc.MAX_STRATUM_LINE_SIZE
        peer.dataReceived(line + b'\n')
        self.assertEqual(peer.lines, [line])
        self.assertFalse(transport.disconnecting)

    def test_over_limit_disconnects_without_dispatch(self):
        peer, transport = self._peer()
        peer.dataReceived(b'x' * (jsonrpc.MAX_STRATUM_LINE_SIZE + 1) + b'\n')
        self.assertEqual(peer.lines, [])
        self.assertTrue(transport.disconnecting)

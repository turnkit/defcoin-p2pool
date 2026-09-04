'''
Generic message-based protocol used by Bitcoin and P2Pool for P2P communication
'''

import hashlib
import struct

from twisted.internet import protocol
from twisted.python import log

import p2pool
from p2pool.util import datachunker, variable
from p2pool.util.py3 import bytes_to_hex, ensure_bytes

class TooLong(Exception):
    pass

class StopReceiving(Exception):
    pass

class Protocol(protocol.Protocol):
    def __init__(self, message_prefix, max_payload_length, traffic_happened=None, ignore_trailing_payload=False):
        traffic_happened = variable.Event() if traffic_happened is None else traffic_happened
        if isinstance(message_prefix, (tuple, list)):
            self._message_prefixes = tuple(ensure_bytes(prefix) for prefix in message_prefix)
            self._message_prefix = self._message_prefixes[0]
        else:
            self._message_prefixes = (ensure_bytes(message_prefix),)
            self._message_prefix = ensure_bytes(message_prefix)
        self._message_prefix_len = max(list(map(len, self._message_prefixes)))
        self._max_payload_length = max_payload_length
        self.dataReceived2 = datachunker.DataChunker(self.dataReceiver())
        self.traffic_happened = traffic_happened
        self.ignore_trailing_payload = ignore_trailing_payload
    
    def dataReceived(self, data):
        self.traffic_happened.happened('p2p/in', len(data))
        try:
            self.dataReceived2(data)
        except StopReceiving:
            self.dataReceived2 = lambda data: None
    
    def dataReceiver(self):
        while True:
            start = b''
            while start not in self._message_prefixes:
                start = (start + (yield 1))[-self._message_prefix_len:]
                for prefix in self._message_prefixes:
                    if start.endswith(prefix):
                        start = prefix
                        break
            self._message_prefix = start
            
            try:
                command = (yield 12).rstrip(b'\0').decode('ascii')
            except UnicodeDecodeError:
                print('invalid non-ASCII command')
                self.badPeerHappened()
                raise StopReceiving()
            length, = struct.unpack('<I', (yield 4))
            if length > self._max_payload_length:
                print('length too large')
                self.badPeerHappened()
                raise StopReceiving()
            checksum = yield 4
            payload = yield length
            
            if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
                print('invalid hash for', self.transport.getPeer().host, repr(command), length, bytes_to_hex(checksum))
                if p2pool.DEBUG:
                    print(bytes_to_hex(hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]), bytes_to_hex(payload))
                self.badPeerHappened()
                raise StopReceiving()
            
            type_ = getattr(self, 'message_' + command, None)
            if type_ is None:
                if p2pool.DEBUG:
                    print('no type for', repr(command))
                continue
            
            try:
                self.packetReceived(command, type_.unpack(payload, self.ignore_trailing_payload))
            except:
                print('RECV', command, bytes_to_hex(payload[:100]) + ('...' if len(payload) > 100 else ''))
                log.err(None, 'Error handling message: (see RECV line)')
                self.disconnect()
                raise StopReceiving()
    
    def packetReceived(self, command, payload2):
        handler = getattr(self, 'handle_' + command, None)
        if handler is None:
            if p2pool.DEBUG:
                print('no handler for', repr(command))
            return
        
        if getattr(self, 'connected', True) and not getattr(self, 'disconnecting', False):
            handler(**payload2)
    
    def disconnect(self):
        if hasattr(self.transport, 'abortConnection'):
            # Available since Twisted 11.1
            self.transport.abortConnection()
        else:
            # This doesn't always close timed out connections! warned about in main
            self.transport.loseConnection()
    
    def badPeerHappened(self):
        self.disconnect()
    
    def sendPacket(self, command, payload2):
        if len(command) >= 12:
            raise ValueError('command too long')
        type_ = getattr(self, 'message_' + command, None)
        if type_ is None:
            raise ValueError('invalid command')
        #print 'SEND', command, repr(payload2)[:500]
        payload = type_.pack(payload2)
        if len(payload) > self._max_payload_length:
            raise TooLong('payload too long')
        data = self._message_prefix + struct.pack('<12sI', ensure_bytes(command, 'ascii'), len(payload)) + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] + payload
        self.traffic_happened.happened('p2p/out', len(data))
        self.transport.write(data)
    
    def __getattr__(self, attr):
        prefix = 'send_'
        if attr.startswith(prefix):
            command = attr[len(prefix):]
            return lambda **payload2: self.sendPacket(command, payload2)
        #return protocol.Protocol.__getattr__(self, attr)
        raise AttributeError(attr)

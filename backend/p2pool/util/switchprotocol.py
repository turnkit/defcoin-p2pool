from twisted.internet import protocol, reactor

FIRST_BYTE_TIMEOUT = 30

class FirstByteSwitchProtocol(protocol.Protocol):
    def connectionMade(self):
        self.p = None
        self._first_byte_timeout = self.factory.reactor.callLater(
            FIRST_BYTE_TIMEOUT, self._first_byte_timed_out)

    def _cancel_first_byte_timeout(self):
        if self._first_byte_timeout is not None:
            if self._first_byte_timeout.active():
                self._first_byte_timeout.cancel()
            self._first_byte_timeout = None

    def _first_byte_timed_out(self):
        self._first_byte_timeout = None
        if hasattr(self.transport, 'abortConnection'):
            self.transport.abortConnection()
        else:
            self.transport.loseConnection()

    def dataReceived(self, data):
        if self.p is None:
            if not data: return
            self._cancel_first_byte_timeout()
            serverfactory = self.factory.first_byte_to_serverfactory.get(data[0], self.factory.default_serverfactory)
            self.p = serverfactory.buildProtocol(self.transport.getPeer())
            if self.p is None:
                self.transport.loseConnection()
                return
            self.p.makeConnection(self.transport)
        self.p.dataReceived(data)
    def connectionLost(self, reason):
        self._cancel_first_byte_timeout()
        if self.p is not None:
            self.p.connectionLost(reason)

class FirstByteSwitchFactory(protocol.ServerFactory):
    protocol = FirstByteSwitchProtocol
    
    def __init__(self, first_byte_to_serverfactory, default_serverfactory,
                 reactor=reactor):
        self.first_byte_to_serverfactory = dict(
            (self._normalize_first_byte(first_byte), serverfactory)
            for first_byte, serverfactory in first_byte_to_serverfactory.items())
        self.default_serverfactory = default_serverfactory
        self.reactor = reactor

    @staticmethod
    def _normalize_first_byte(first_byte):
        if isinstance(first_byte, int):
            return first_byte
        if isinstance(first_byte, bytes):
            if len(first_byte) != 1:
                raise ValueError('first-byte switch keys must be exactly one byte')
            return first_byte[0]
        if isinstance(first_byte, str):
            if len(first_byte) != 1:
                raise ValueError('first-byte switch keys must be exactly one character')
            return ord(first_byte)
        raise TypeError('unsupported first-byte switch key type: %s' % (type(first_byte).__name__,))
    
    def startFactory(self):
        for f in list(self.first_byte_to_serverfactory.values()) + [self.default_serverfactory]:
            f.doStart()
    
    def stopFactory(self):
        for f in list(self.first_byte_to_serverfactory.values()) + [self.default_serverfactory]:
            f.doStop()

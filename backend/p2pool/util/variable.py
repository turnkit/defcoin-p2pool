import itertools
import weakref

from twisted.internet import defer, reactor
from twisted.python import failure, log

class Event(object):
    def __init__(self):
        self.observers = {}
        self.id_generator = itertools.count()
        self._once = None
        self.times = 0
    
    def run_and_watch(self, func):
        func()
        return self.watch(func)
    def watch_weakref(self, obj, func):
        # func must not contain a reference to obj!
        watch_id = self.watch(lambda *args: func(obj_ref(), *args))
        obj_ref = weakref.ref(obj, lambda _: self.unwatch(watch_id))
    def watch(self, func):
        id = next(self.id_generator)
        self.observers[id] = func
        return id
    def unwatch(self, id):
        self.observers.pop(id)
    
    @property
    def once(self):
        res = self._once
        if res is None:
            res = self._once = Event()
        return res
    
    def happened(self, *event):
        self.times += 1
        
        once, self._once = self._once, None
        
        for id, func in sorted(self.observers.items()):
            try:
                func(*event)
            except:
                log.err(None, "Error while processing Event callbacks:")
        
        if once is not None:
            once.happened(*event)
    
    def get_deferred(self, timeout=None):
        once = self.once
        state = dict(watch_id=None, delay=None)

        def cleanup():
            if state['watch_id'] is not None:
                once.observers.pop(state['watch_id'], None)
                state['watch_id'] = None
            if state['delay'] is not None:
                if state['delay'].active():
                    state['delay'].cancel()
                state['delay'] = None

        def cancel(df):
            cleanup()

        df = defer.Deferred(cancel)

        def happened(*event):
            cleanup()
            if not df.called:
                df.callback(event)

        state['watch_id'] = once.watch(happened)
        if timeout is not None:
            def do_timeout():
                state['delay'] = None
                if state['watch_id'] is not None:
                    once.observers.pop(state['watch_id'], None)
                    state['watch_id'] = None
                if not df.called:
                    df.errback(failure.Failure(defer.TimeoutError('in Event.get_deferred')))
            state['delay'] = reactor.callLater(timeout, do_timeout)
        return df

class Variable(object):
    def __init__(self, value):
        self.value = value
        self.changed = Event()
        self.transitioned = Event()
    
    def set(self, value):
        if value == self.value:
            return
        
        oldvalue = self.value
        self.value = value
        self.changed.happened(value)
        self.transitioned.happened(oldvalue, value)
    
    @defer.inlineCallbacks
    def get_when_satisfies(self, func):
        while True:
            if func(self.value):
                defer.returnValue(self.value)
            yield self.changed.once.get_deferred()
    
    def get_not_none(self):
        return self.get_when_satisfies(lambda val: val is not None)

class VariableDict(Variable):
    def __init__(self, value):
        Variable.__init__(self, value)
        self.added = Event()
        self.removed = Event()
    
    def add(self, values):
        new_items = dict([item for item in values.items() if not item[0] in self.value or self.value[item[0]] != item[1]])
        self.value.update(values)
        self.added.happened(new_items)
        # XXX call self.changed and self.transitioned
    
    def remove(self, values):
        gone_items = dict([item for item in values.items() if item[0] in self.value])
        for key in gone_items:
            del self.value[key]
        self.removed.happened(gone_items)
        # XXX call self.changed and self.transitioned

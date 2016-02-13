
'''
Copyright (c) 2016, Theodor-Iulian Ciobanu
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''

from collections import OrderedDict
from threading import RLock, Thread, Event
from time import time
import pickle

class TrivialCache(object):
    def __init__(self, threshold = 500, timeout = 300):
        self._cache = OrderedDict()
        self.clear = self._cache.clear
        self._threshold = threshold
        self._timeout = timeout
        self._lock = RLock()
        self.autopurge = self._setautopurge()

    def size(self):
        return len(self._cache)

    def has(self, key):
        with self._lock:
            if key in self._cache:
                exp, _ = self._cache[key]
                if (not exp) or (exp > time()):
                    return True
                else:
                    self._delete(key)

            return False

    def get(self, key):
        with self._lock:
            if key in self._cache:
                exp, val = self._cache[key]
                if (not exp) or (exp > time()):
                    return pickle.loads(val)
                else:
                    self._delete(key)

            return None

    def pop(self, key):
        with self._lock:
            return self._cache.pop(key, None)

    def set(self, key, value, timeout = None):
        with self._lock:
            timeout = timeout or self._timeout
            if timeout:
                exp = time() + timeout
            else:
                exp = None

            if len(self._cache) + (not key in self._cache) > self._threshold:
                self.purge()
                if len(self._cache) + (not key in self._cache) > self._threshold:
                    return False
            else:
                self.purge()

            pickled = pickle.dumps(value, pickle.HIGHEST_PROTOCOL)
            size = len(pickled) + 1

            self._cache[key] = (exp, pickled)

            return True

    def _delete(self, key):
        del self._cache[key]

    def delete(self, key, autopurge = True):
        with self._lock:
            if autopurge:
                self.purge()

            if key in self._cache:
                _, val = self._cache[key]
                self._delete(key)
                return True
            else:
                return False

    def purge(self, aggressive = False):
        with self._lock:
            size = len(self._cache)
            threshold = (self._threshold or size) * (2 + (not aggressive)) / 3
            if not(aggressive or (size > threshold)):
                return False

            purged = 0
            now = time()
            for k, (exp, _) in self._cache.items():
                if (exp and (exp <= now)):
                    self._delete(key)
                    size -= 1
                    purged += 1

            if aggressive:
                while (size > threshold):
                    self._cache.popitem(False)
                    size -= 1
                    purged += 1

            return purged

    def _setautopurge(self):
        stopped = Event()

        def loop():
            while not stopped.wait(300):
                self.purge()

        thread = Thread(target = loop)
        thread.daemon = True
        thread.start()

        return stopped

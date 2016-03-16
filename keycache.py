#!/usr/bin/env python

'''
Copyright (c) 2015-2016, Theodor-Iulian Ciobanu
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

from Crypto import Random
from collections import Counter
import zlib
import base64
import struct
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Random import random
import uuid

class KeyCache(object):
    ERROR_KEY_INVALID = 0x1
    ERROR_KEY_CORRUPT = 0x2
    ERROR_INSTANCEID_INVALID = 0x3
    ERROR_CRYPTINDEX_INVALID = 0x4
    ERROR_VIEWCOUNT_INVALID = 0x5
    ERROR_MSGINDEX_INVALID = 0x6
    ERROR_EXTRA_MISMATCH = 0x7
    ERROR_MESSAGE_CORRUPT = 0x8
    ERROR_CACHE_NOTFOUND = 0x9
    ERROR_CACHE_NOTSET = 0x10

    # how may bytes are needed to store 'num'
    def _bytesize(self, num):
        size = 0
        while (num > 0):
            size += 1
            num >>= 8

        return size

    # pack an int to a binary string
    def _intpack(self, num, length):
        res = [chr(0)] * length
        i = 1
        while (num > 0) and (i <= length):
            res[length - i] = chr(num & 255)
            i += 1
            num >>= 8

        return ''.join(res)

    # unpack an int from a binary string
    def _intunpack(self, string):
        num = 0
        for c in string:
            num = (num << 8) + ord(c)

        return num

    # compress data
    def _deflate(self, data):
        return zlib.compress(data, 9) #[2:-4]

    # decompress data
    def _inflate(self, data):
        return zlib.decompress(data, 15) #-15)

    # decrement number of views for a key
    def _decviews(self, views, msgidx, cryptidx):
        views -= 1
        if (views == 0):
            self._msgkey[msgidx]['count'] -= 1
            if (self._msgkey[msgidx]['count'] == 0):
                self._msgkey[msgidx]['key'] = Random.new().read(self._keysize)
                if self._debug:
                    print('msgkey[%d]: %s' % (msgidx, self._msgkey[msgidx]['key'].encode('hex')))

            self._cryptkey[cryptidx]['count'] -= 1
            if (self._cryptkey[cryptidx]['count'] == 0):
                self._cryptkey[cryptidx]['key'] = Random.new().read(self._keysize)
                if self._debug:
                    print('cryptkey[%d]: %s' % (cryptidx, self._cryptkey[cryptidx]['key'].encode('hex')))

        return views

    def __init__(self, settings):
        # debug
        self._debug = ('DEBUG' in settings) and settings['DEBUG'] or False
        # unique id
        self._instanceid = ('INSTANCEID' in settings) and settings['INSTANCEID'] or Random.new().read(1)
        self._iidsize = len(self._instanceid)
        # max number of messages to store
        self._threshold = ('THRESHOLD' in settings) and settings['THRESHOLD'] or 1024
        # message ttl
        self._timeout = ('TIMEOUT' in settings) and settings['TIMEOUT'] or 302400
        # key pool size
        self._keycount = ('KEYCOUNT' in settings) and settings['KEYCOUNT'] or 256
        self._kcsize = self._bytesize(self._keycount - 1)
        # key size
        self._keysize = ('KEYSIZE' in settings) and settings['KEYSIZE'] or 32
        # compress messages bigger than this (None to disable)
        self._mincompsize = ('MINCOMPSIZE' in settings) and settings['MINCOMPSIZE'] or 128
        # number of views allowed
        self._views = ('VIEWS' in settings) and settings['VIEWS'] or 1
        # view attempts with a wrong 'extra' count
        self._extrascount = ('EXTRASCOUNT' in settings) and settings['EXTRASCOUNT'] or True

        # init backend and view counter
        self._cache = settings['BACKEND'](self._threshold, self._timeout)

        # key pool
        self._msgkey = [{'key': Random.new().read(self._keysize), 'count': 0} for _ in xrange(self._keycount)]
        self._cryptkey = [{'key': Random.new().read(self._keysize), 'count': 0} for _ in xrange(self._keycount)]
        if self._debug:
            print('instanceid: ' + str(self._intunpack(self._instanceid)))
            print('msgkey: ' + ', '.join(key['key'].encode('hex') for key in self._msgkey))
            print('cryptkey: ' + ', '.join(key['key'].encode('hex') for key in self._cryptkey))

    def get(self, key = '', extra = '', compressed = False):
        if self._debug:
            print('key: ' + key)
            print('extra: ' + extra)

        try:
            key = base64.urlsafe_b64decode(key + '=' * (4 - len(key) % 4))
        except:
            return (None, self.ERROR_KEY_INVALID)

        fmt = '%ds %ds %ds %ds' % (self._iidsize, self._kcsize, AES.block_size, AES.block_size)
        if (len(key) != struct.calcsize(fmt)):
            return (None, self.ERROR_KEY_CORRUPT)

        instid, cryptidx, cryptiv, uid = struct.unpack(fmt, key)
        cryptidx = self._intunpack(cryptidx)
        if self._debug:
            print('instanceid: ' + str(self._intunpack(instid)))
            print('cryptidx: ' + str(cryptidx))
            print('cryptiv: ' + cryptiv.encode('hex'))
        if (instid != self._instanceid):
            return (None, self.ERROR_INSTANCEID_INVALID)
        elif (self._cryptkey[cryptidx]['count'] < 1):
            return (None, self.ERROR_CRYPTINDEX_INVALID)

        cryptcipher = AES.new(self._cryptkey[cryptidx]['key'], AES.MODE_CFB, cryptiv)

        uid = cryptcipher.decrypt(uid)
        if self._debug:
            print('uid: ' + uid.encode('hex'))

        cryptmsg, views = self._cache.get(uid)
        if cryptmsg:
            if (views < 1):
                self._cache.delete(uid)
                return (None, self.ERROR_VIEWCOUNT_INVALID)

            if self._debug:
                print('views: ' + str(views))

            fmt = '%ds %ds %ds' % (SHA256.digest_size, self._kcsize, AES.block_size)
            digest, msgidx, msgiv = struct.unpack(fmt, cryptmsg[:struct.calcsize(fmt)])

            msgidx = self._intunpack(msgidx)
            if (self._msgkey[msgidx]['count'] < 1):
                return (None, self.ERROR_MSGINDEX_INVALID)

            if (digest != HMAC.new(extra, cryptmsg[SHA256.digest_size:], SHA256).digest()):
                if self._extrascount:
                    views = self._decviews(views, msgidx, cryptidx)
                    if views:
                        self._cache.update(uid, (cryptmsg, views))
                return (None, self.ERROR_EXTRA_MISMATCH)

            if self._debug:
                print('msgidx: ' + str(msgidx))
                print('msgiv: ' + msgiv.encode('hex'))

            msgcipher = AES.new(self._msgkey[msgidx]['key'], AES.MODE_CFB, msgiv)
            signedmsg = msgcipher.decrypt(cryptmsg[struct.calcsize(fmt):])

            fmt = '%ds %ds' % (SHA256.digest_size, SHA256.digest_size)
            salt, digest = struct.unpack(fmt, signedmsg[:struct.calcsize(fmt)])
            message = signedmsg[struct.calcsize(fmt):]

            views = self._decviews(views, msgidx, cryptidx)
            if views:
                self._cache.update(uid, (cryptmsg, views))

            if (digest != HMAC.new(salt, message, SHA256).digest()):
                return (None, self.ERROR_MESSAGE_CORRUPT)
            else:
                if (message[0] == '\x01') and (not compressed):
                    return (self._inflate(message[1:]), False)
                else:
                    return (message[1:], (message[0] == '\x01'))
        else:
            return (None, self.ERROR_CACHE_NOTFOUND)

    def set(self, message, extra, views, compress = True):
        extra = extra or ''
        views = views or self._views
        if (views < 1):
            views = 1
        msglen = len(message)
        if self._debug:
            print('message: ' + message)
            print('messagelen: ' + str(msglen))
            print('extra: ' + str(extra))
            print('views: ' + str(views))

        if compress and (msglen > self._mincompsize):
            message = '\x01' + self._deflate(message)
            if self._debug:
                print('compressed: ' + str(len(message)))
        else:
            message = '\x00' + message

        while True:
            uid = uuid.uuid4().bytes
            if not self._cache.has(uid):
                break
        if self._debug:
            print('uid: ' + uid.encode('hex'))

        msgidx = random.randint(0, self._keycount - 1)
        msgiv = Random.new().read(AES.block_size)
        if self._debug:
            print('msgidx: ' + str(msgidx))
            print('msgiv: ' + msgiv.encode('hex'))

        msgcipher = AES.new(self._msgkey[msgidx]['key'], AES.MODE_CFB, msgiv)
        self._msgkey[msgidx]['count'] += 1
        salt = Random.new().read(SHA256.digest_size)
        cryptmsg = self._intpack(msgidx, self._kcsize) + msgiv + msgcipher.encrypt(salt) + msgcipher.encrypt(HMAC.new(salt, message, SHA256).digest()) + msgcipher.encrypt(message)

        if self._cache.set(uid, (HMAC.new(extra, cryptmsg, SHA256).digest() + cryptmsg, views)):
            cryptiv = Random.new().read(AES.block_size)
            cryptidx = random.randint(0, self._keycount - 1)
            if self._debug:
                print('cryptidx: ' + str(cryptidx))
                print('cryptiv: ' + cryptiv.encode('hex'))

            cryptcipher = AES.new(self._cryptkey[cryptidx]['key'], AES.MODE_CFB, cryptiv)
            self._cryptkey[cryptidx]['count'] += 1

            return (base64.urlsafe_b64encode(self._instanceid + self._intpack(cryptidx, self._kcsize) + cryptiv + cryptcipher.encrypt(uid)).rstrip('='), None)
        else:
            return (None, self.ERROR_CACHE_NOTSET)

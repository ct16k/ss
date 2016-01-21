#!/usr/bin/env python

'''
Copyright (c) 2015, Theodor-Iulian Ciobanu
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

import uuid
from Crypto import Random
from Crypto.Random import random
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
import struct
import zlib
import base64
import logging

from flask import Flask, request, render_template_string, Response, make_response
from werkzeug.contrib.cache import SimpleCache

# default configuration
DEBUG = False
SERVERID = Random.new().read(1)
URLPREFIX = 'https'
LISTENADDR = '192.168.214.252'
LISTENPORT = 29555
THRESHOLD = 1024
TIMEOUT = 302400
KEYSIZE = 32
KEYCOUNT = 256
MINCOMPSIZE = 128

MAX_CONTENT_LENGTH = 1024 * 1024

# utils
def bytesize(num):
    size = 0
    while (num > 0):
        size += 1
        num >>= 8

    return size

def inttostr(num, length):
    res = [chr(0)] * length
    i = 1
    while i <= length:
        res[length - i] = chr(num % 256)
        i += 1
        num >>= 8

    return ''.join(res)

def strtoint(string):
    num = 0
    for c in string:
        num = (num << 8) + ord(c)

    return num

def deflate(data):
    return zlib.compress(data, 9) #[2:-4]

def inflate(data):
    return zlib.decompress(data, 15) #-15)

# app init
app = Flask(__name__, static_url_path='')
app.config.from_object(__name__)
app.config.from_envvar('SS_CONFIG', silent = True)
logger = logging.getLogger('werkzeug')

# globals
cache = None
sidsize = len(app.config['SERVERID'])
kcsize = bytesize(app.config['KEYCOUNT'] - 1)

msgkey = [{'key': Random.new().read(app.config['KEYSIZE']), 'count': 0} for _ in xrange(app.config['KEYCOUNT'])]
urlkey = [{'key': Random.new().read(app.config['KEYSIZE']), 'count': 0} for _ in xrange(app.config['KEYCOUNT'])]
if app.config['DEBUG']:
    print('serverid: ' + str(strtoint(app.config['SERVERID'])))
    print('msgkey: ' + ', '.join(key['key'].encode('hex') for key in msgkey))
    print('urlkey: ' + ', '.join(key['key'].encode('hex') for key in urlkey))

@app.route('/')
def index():
    return Response(render_template_string('''<html>
  <head>
    <title>ss</title>
  </head>
  <body>
    <form action="{{ urlprefix }}://{{ host }}/set" method="post">
      <table  style="border: 0; padding: 0; border-spacing: 0;">
        <tr>
          <td style="vertical-align: top;">
            <dl>
              <dt>message:</dt>
              <dd><textarea name="message" rows=5 cols=40 autofocus="autofocus"></textarea></dd>
              <dt>extra:</dt>
              <dd><input type="text" name="extra" size=30 /></dd>
            </dl>
          </td>
          <td style="vertical-align: top;">
            <dl>
              <dt>copies:</dt>
              <dd><input type="text" name="copies" size=10 /></dd>
              <!--
              <dt>views:</dt>
              <dd><input type="text" name="views" size=10 /></dd>
              -->
            </dl>
          </td>
        </tr>
        <tr>
          <td>
            <input type="submit" value="Share" />
          </td>
        </tr>
      </table>
    </form>
  </body>
</html>''', host = request.host, urlprefix = app.config['URLPREFIX']), mimetype = 'text/html')

def get_form(arg):
    return Response(render_template_string('''<html>
  <head>
    <title>ss</title>
  </head>
  <body>
    <form action="{{ urlprefix }}://{{ host }}/get/" method="post">
      <dl>
        <dt>id:</dt>
        <dd><input type="text" name="arg" size=60 value="{{ msgid }}"/></dd>
        <dt>extra:</dt>
        <dd><input type="text" name="extra" size=30 /></dd>
      </dl>
      <input type="submit" value="Retrieve" />
    </form>
  </body>
</html>''', host = request.host, urlprefix = app.config['URLPREFIX'], msgid = arg), mimetype = 'text/html')

@app.route('/get', methods = ['GET', 'POST'], defaults = {'arg': None})
@app.route('/get/', methods = ['GET', 'POST'], defaults = {'arg': None})
@app.route('/get/<arg>', methods = ['GET', 'POST'])
def get_key(arg):
    if not arg:
        arg = request.form.get('arg')
        if not arg:
            return get_form(''.join(request.args.keys()))

    arg = arg.encode('ascii')
    extra = request.values.get('extra', '').encode('utf-8')
    if app.config['DEBUG']:
        print('arg: ' + arg)
        print('extra: ' + extra)
    arg = base64.urlsafe_b64decode(arg + '=' * (4 - len(arg) % 4))

    fmt = '%ds %ds %ds %ds' % (sidsize, kcsize, AES.block_size, AES.block_size)
    if len(arg) != struct.calcsize(fmt):
        return Response('Erm', mimetype = 'text/plain')

    srvid, urlidx, urliv, uid = struct.unpack(fmt, arg)
    urlidx = strtoint(urlidx)
    if app.config['DEBUG']:
        print('serverid: ' + str(strtoint(srvid)))
        print('urlidx: ' + str(urlidx))
        print('urliv: ' + urliv.encode('hex'))
    if srvid != app.config['SERVERID']:
        return Response('Eh?', mimetype = 'text/plain')
    elif urlkey[urlidx]['count'] < 1:
        return Response('Err', mimetype = 'text/plain')

    urlcipher = AES.new(urlkey[urlidx]['key'], AES.MODE_CFB, urliv)

    uid = urlcipher.decrypt(uid)
    if app.config['DEBUG']:
        print('uid: ' + uid.encode('hex'))

    urlkey[urlidx]['count'] -= 1
    if urlkey[urlidx]['count'] == 0:
        urlkey[urlidx]['key'] = Random.new().read(app.config['KEYSIZE'])
        if app.config['DEBUG']:
            print('urlkey[%d]: %s' % (urlidx, urlkey[urlidx]['key'].encode('hex')))

    cryptmsg = cache.get(uid)
    if cryptmsg:
        fmt = '%ds %ds %ds' % (SHA256.digest_size, kcsize, AES.block_size)
        digest, msgidx, msgiv = struct.unpack(fmt, cryptmsg[:struct.calcsize(fmt)])

        if digest != HMAC.new(extra, cryptmsg[SHA256.digest_size:], SHA256).digest():
            return Response('Nope', mimetype = 'text/plain')

        msgidx = strtoint(msgidx)
        if msgkey[msgidx]['count'] < 1:
            return Response('Hmm', mimetype = 'text/plain')

        if app.config['DEBUG']:
            print('msgidx: ' + str(msgidx))
            print('msgiv: ' + msgiv.encode('hex'))

        msgcipher = AES.new(msgkey[msgidx]['key'], AES.MODE_CFB, msgiv)
        signedmsg = msgcipher.decrypt(cryptmsg[struct.calcsize(fmt):])

        msgkey[msgidx]['count'] -= 1
        if msgkey[msgidx]['count'] == 0:
            msgkey[msgidx]['key'] = Random.new().read(app.config['KEYSIZE'])
            if app.config['DEBUG']:
                print('msgkey[%d]: %s' % (msgidx, msgkey[msgidx]['key'].encode('hex')))

        fmt = '%ds %ds' % (SHA256.digest_size, SHA256.digest_size)
        salt, digest = struct.unpack(fmt, signedmsg[:struct.calcsize(fmt)])
        message = signedmsg[struct.calcsize(fmt):]
        if digest != HMAC.new(salt, message, SHA256).digest():
            return Response('Wot', mimetype = 'text/plain')
        else:
            if not app.config['DEBUG']:
                cache.delete(uid)

            if message[0] == '\x01':
                if 'deflate' not in request.headers.get('Accept-Encoding', '').lower():
                    return Response(inflate(message[1:]), mimetype = 'text/plain')
                else:
                    res = make_response(message[1:])

                    res.mimetype = 'text/plain'
                    res.headers['Content-Encoding'] = 'deflate'
                    res.headers['Content-Length'] = res.content_length

                    return res
            else:
                return Response(message[1:], mimetype = 'text/plain')
    else:
        return Response('No get', mimetype = 'text/plain')

def set_key(message, msglen, extra, views):
    while True:
        uid = uuid.uuid4().bytes
        if not cache.get(uid):
            break
    if app.config['DEBUG']:
        print('uid: ' + uid.encode('hex'))

    msgidx = random.randint(0, app.config['KEYCOUNT'] - 1)
    msgiv = Random.new().read(AES.block_size)
    if app.config['DEBUG']:
        print('msgidx: ' + str(msgidx))
        print('msgiv: ' + msgiv.encode('hex'))

    msgcipher = AES.new(msgkey[msgidx]['key'], AES.MODE_CFB, msgiv)
    msgkey[msgidx]['count'] += 1
    salt = Random.new().read(SHA256.digest_size)
    cryptmsg = inttostr(msgidx, kcsize) + msgiv + msgcipher.encrypt(salt) + msgcipher.encrypt(HMAC.new(salt, message, SHA256).digest()) + msgcipher.encrypt(message)

    if cache.set(uid, HMAC.new(extra, cryptmsg, SHA256).digest() + cryptmsg):
        urliv = Random.new().read(AES.block_size)
        urlidx = random.randint(0, app.config['KEYCOUNT'] - 1)
        if app.config['DEBUG']:
            print('urlidx: ' + str(urlidx))
            print('urliv: ' + urliv.encode('hex'))
        urlcipher = AES.new(urlkey[urlidx]['key'], AES.MODE_CFB, urliv)
        urlkey[urlidx]['count'] += 1
        if extra:
            extraflag = '?'
        else:
            extraflag = ''
        return '%s://%s/get/%s%s' % (app.config['URLPREFIX'], request.host, extraflag, base64.urlsafe_b64encode(app.config['SERVERID'] + inttostr(urlidx, kcsize) + urliv + urlcipher.encrypt(uid)).rstrip('='))
    else:
        return 'No set'

@app.route('/set', methods = ['POST'])
def set_keys():
    message = request.form['message'].encode('utf-8')
    msglen = len(message)
    extra = request.form.get('extra', '').encode('utf-8')
    copies = request.form.get('copies', 1, type = int)
    views = request.form.get('views', 1, type = int)

    if app.config['DEBUG']:
        print('message: ' + message)
        print('messagelen: ' + str(msglen))
        print('extra: ' + str(extra))

    if msglen > app.config['MINCOMPSIZE']:
        message = '\x01' + deflate(message)
        if app.config['DEBUG']:
            print('compressed: ' + str(len(message)))
    else:
        message = '\x00' + message

    result = [set_key(message, msglen, extra) for _ in xrange(copies)]
    return Response('\n'.join(result), mimetype = 'text/plain')

@app.route('/src', methods = ['GET', 'POST'])
def get_src():
    with open(__file__) as srcfile:
        return Response(''.join(line for line in srcfile), mimetype = 'text/plain')

@app.before_request
def before_request():
	route = None
	if 'X-Forwarded-For' in request.headers:
		route = request.headers.getlist('X-Forwarded-For')
	elif 'Forwarded-For' in request.headers:
		route = request.headers.getlist('Forwarded-For')
	elif 'X-Real-Ip' in request.headers:
		route = request.headers.getlist('X-Real-Ip')
	if route:
		logger.info("access_route: " + ', '.join(route[-4:]))

if __name__ == '__main__':
    cache = SimpleCache(app.config['THRESHOLD'], app.config['TIMEOUT'])
    app.run(host = app.config['LISTENADDR'], port = app.config['LISTENPORT'], debug = app.config['DEBUG'])

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

from os import getpid
from threading import current_thread, local
import logging
from Crypto import Random
from flask import Flask, request, render_template, render_template_string, Response, make_response
from keycache import KeyCache
from trivialcache import TrivialCache

# default configuration
DEBUG = False
BACKEND = TrivialCache
INSTANCEID = None
TEMPLATENAME = None
URLPREFIX = 'https'
LISTENADDR = '192.168.214.252'
LISTENPORT = 29555
THRESHOLD = 1024
TIMEOUT = 302400
KEYSIZE = 32
KEYCOUNT = 256
MINCOMPSIZE = 128

MAX_CONTENT_LENGTH = 1024 * 1024

DEFCOPIES = 1
MAXCOPIES = 16
DEFVIEWS = 1
MAXVIEWS = 16
EXTRASCOUNT = True

GENKEYS = 1
GENKEYLEN = 16
GENKEYCHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"

# app init
app = Flask(__name__, static_url_path='')
app.config.from_object(__name__)
app.config.from_envvar('SS_CONFIG', silent = True)
logger = logging.getLogger('werkzeug')


tls = local()
tls.template = None
tls.cache = None

@app.before_first_request
def before_first_request():
    # 16bit hash of a list of ints
    def _geniid(nums):
        hash = 0
        for i in nums:
            while (i > 0):
                hash = (hash + (hash << 5)) ^ (i & 0xFF)
                i >>= 8
        hash = (hash ^ (hash >> 16)) &0xFFFF

        return '%c%c' % (chr(hash >> 8), chr(hash & 0xFF))

    if not app.config['INSTANCEID']:
        app.config['INSTANCEID'] = _geniid([getpid(), current_thread().ident])
    if app.config['DEBUG']:
        print('init: %d %d' % (getpid(), current_thread().ident))

    if app.config['TEMPLATENAME']:
        import json

        with open(app.config['TEMPLATENAME']) as template_json:
            tls.template = json.load(template_json)
        if app.config['DEBUG']:
            from pprint import pprint

            print('template: ' + app.config['TEMPLATENAME'])
            pprint(tls.template)

    tls.cache = KeyCache(app.config)

def rendertemplate(tmpl, **kwargs):
    if tmpl['type'] and (tmpl['type'] == 'inline'):
        return render_template_string(tmpl['template'], **kwargs)
    else:
        return render_template(tmpl['template'], **kwargs)

@app.route('/')
def index():
    if tls.template and ('index' in tls.template):
        return Response(rendertemplate(tls.template['index'], host = request.host, urlprefix = app.config['URLPREFIX']), mimetype = tls.template['index']['type'] or 'text/html')
    else:
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
              <dt>views:</dt>
              <dd><input type="text" name="views" size=10 /></dd>
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
    if tls.template and ('getform' in tls.template):
        return Response(rendertemplate(tls.template['getform'], host = request.host, urlprefix = app.config['URLPREFIX'], msgid = arg), mimetype = tls.template['getform']['type'] or 'text/html')
    else:
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

    compressed = not(tls.template and ('getkey' in tls.template)) and ('deflate' in request.headers.get('Accept-Encoding', '').lower())
    message, err = tls.cache.get(arg, extra, compressed)
    if message:
        if compressed and err:
            res = make_response(message)

            res.mimetype = 'text/plain'
            res.headers['Content-Encoding'] = 'deflate'
            res.headers['Content-Length'] = res.content_length

            return res
        elif tls.template and ('getkey' in tls.template):
            return Response(rendertemplate(tls.template['getkey'], message = message), mimetype = tls.template['getkey']['type'] or 'text/plain')
        else:
            return Response(message, mimetype = 'text/plain')
    else:
        errmsg = {
            tls.cache.ERROR_KEY_INVALID: 'Wat',
            tls.cache.ERROR_KEY_CORRUPT: 'Erm',
            tls.cache.ERROR_INSTANCEID_INVALID: 'Eh?',
            tls.cache.ERROR_CRYPTINDEX_INVALID: 'Err',
            tls.cache.ERROR_VIEWCOUNT_INVALID: 'Hmpf',
            tls.cache.ERROR_MSGINDEX_INVALID: 'Hmm',
            tls.cache.ERROR_EXTRA_MISMATCH: 'Nope',
            tls.cache.ERROR_MESSAGE_CORRUPT: 'Wot',
            tls.cache.ERROR_CACHE_NOTFOUND: 'No get'
        }
        if tls.template and ('errorpage' in tls.template):
            return Response(rendertemplate(tls.template['errorpage'], error = err, errormsg = errmsg.get(err, '?')), mimetype = tls.template['errorpage']['type'] or 'text/html')
        else:
            return Response(errmsg.get(err, '?'), mimetype = 'text/plain')

def set_key(message, extra = '', views = app.config['DEFVIEWS']):
    if app.config['DEBUG']:
        print('message: ' + message)
        print('extra: ' + str(extra))
        print('views: ' + str(views))

    urlkey, err = tls.cache.set(message, extra, views)
    if urlkey:
        if extra:
            extraflag = '?'
        else:
            extraflag = ''
        if tls.template and ('setkey' in tls.template):
            return rendertemplate(tls.template['setkey'], host = request.host, urlprefix = app.config['URLPREFIX'], key = urlkey, extra = extraflag)
        else:
            return '%s://%s/get/%s%s' % (app.config['URLPREFIX'], request.host, extraflag, urlkey)
    else:
        errmsg = {
            tls.cache.ERROR_CACHE_NOTSET: 'No set'
        }
        if tls.template and ('errormsg' in tls.template):
            return rendertemplate(tls.template['errormsg'], error = err, errormsg = errmsg.get(err, '?'))
        else:
            return errmsg.get(err, '?')

@app.route('/set/', methods = ['POST'])
@app.route('/set', methods = ['POST'])
def set_keys():
    message = request.form['message'].encode('utf-8')
    msglen = len(message)
    extra = request.form.get('extra', '').encode('utf-8')

    copies = request.form.get('copies', app.config['DEFCOPIES'], type = int)
    if (copies < 1):
        copies = 1
    elif (copies > app.config['MAXCOPIES']):
        copies=  app.config['MAXCOPIES']

    views = request.form.get('views', app.config['DEFVIEWS'], type = int)
    if (views < 1):
        views = 1
    elif (views > app.config['MAXVIEWS']):
        views = app.config['MAXVIEWS']

    if app.config['DEBUG']:
        print('message: ' + message)
        print('messagelen: ' + str(msglen))
        print('extra: ' + str(extra))
        print('copies: ' + str(copies))
        print('views: ' + str(views))

    result = [set_key(message, extra, views) for _ in xrange(copies)]
    if tls.template and ('setkeys' in tls.template):
        return Response(rendertemplate(tls.template['setkeys'], keys = result), mimetype = tls.template['setkeys']['type'] or 'text/html')
    else:
        return Response('\n'.join(result), mimetype = 'text/plain')

def gen_key(keycharslen, keylen, copies, views, extra = ''):
    genkey = ''.join([app.config['GENKEYCHARS'][ord(c) % keycharslen] for c in Random.new().read(keylen)])

    result = [set_key(genkey, extra, views) for _ in xrange(copies)]
    if tls.template and ('genkey' in tls.template):
        return rendertemplate(tls.template['genkey'], keys = result)
    else:
        return '\n'.join(result)

@app.route('/gen/', methods = ['GET', 'POST'], defaults = {'count': None, 'keylen': None, 'copies': None, 'views': None})
@app.route('/gen', methods = ['GET', 'POST'], defaults = {'count': None, 'keylen': None, 'copies': None, 'views': None})
@app.route('/gen/<int:count>/', methods = ['GET', 'POST'], defaults = {'keylen': None, 'copies': None, 'views': None})
@app.route('/gen/<int:count>', methods = ['GET', 'POST'], defaults = {'keylen': None, 'copies': None, 'views': None})
@app.route('/gen/<int:count>/<int:keylen>/', methods = ['GET', 'POST'], defaults = {'copies': None, 'views': None})
@app.route('/gen/<int:count>/<int:keylen>', methods = ['GET', 'POST'], defaults = {'copies': None, 'views': None})
@app.route('/gen/<int:count>/<int:keylen>/<int:copies>/', methods = ['GET', 'POST'], defaults = {'views': None})
@app.route('/gen/<int:count>/<int:keylen>/<int:copies>', methods = ['GET', 'POST'], defaults = {'views': None})
@app.route('/gen/<int:count>/<int:keylen>/<int:copies>/<int:views>/', methods = ['GET', 'POST'])
@app.route('/gen/<int:count>/<int:keylen>/<int:copies>/<int:views>', methods = ['GET', 'POST'])
def gen_keys(count, keylen, copies, views):

    if not count:
        count = request.values.get('count', app.config['GENKEYS'], type = int)
        if not count or (count < 1):
            count = app.config['GENKEYS']
    if app.config['DEBUG']:
        print('count: ' + str(count))

    if not keylen:
        keylen = request.values.get('keylen', app.config['GENKEYLEN'], type = int)
        if (not keylen) or (keylen < 1) or (keylen > app.config['MAX_CONTENT_LENGTH']):
            keylen = app.config['GENKEYLEN']
    if app.config['DEBUG']:
        print('keylen: ' + str(keylen))

    if not copies:
        copies = request.values.get('copies', app.config['DEFCOPIES'], type = int)
        if not copies:
            copies = app.config['DEFCOPIES']
        elif copies < 1:
            copies = 1
        elif copies > app.config['MAXCOPIES']:
            copies = app.config['MAXCOPIES']
    if app.config['DEBUG']:
        print('copies: ' + str(copies))

    if not views:
        views = request.values.get('views', app.config['DEFVIEWS'], type = int)
        if not views:
            views = app.config['DEFVIEWS']
        elif views < 1:
            views = 1
        elif views > app.config['MAXVIEWS']:
            views = app.config['MAXVIEWS']
    if app.config['DEBUG']:
        print('views: ' + str(views))

    keycharslen = len(app.config['GENKEYCHARS'])
    if app.config['DEBUG']:
        print('keycharslen: ' + str(keycharslen))

    extra = request.values.get('extra', '').encode('utf-8')

    result = [gen_key(keycharslen, keylen, copies, views, extra) for _ in xrange(count)]
    if tls.template and ('genkeys' in tls.template):
        return Response(rendertemplate(tls.template['genkeys'], keys = result), mimetype = tls.template['genkeys']['type'] or 'text/html')
    else:
        return Response('\n\n'.join(result), mimetype = 'text/plain')

@app.route('/src/', methods = ['GET', 'POST'])
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
    app.run(host = app.config['LISTENADDR'], port = app.config['LISTENPORT'], debug = app.config['DEBUG'])

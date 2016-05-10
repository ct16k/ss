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

from os import getenv, getpid
from threading import current_thread, local
import logging
import re
import ipaddress
import urllib2
from Crypto import Random
from flask import Flask, request, Response, g
from werkzeug.routing import BaseConverter
from keycache import KeyCache
from trivialcache import TrivialCache
from trivialtemplate import TrivialTemplate
from datetime import datetime, timedelta
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# default configuration
DEBUG = False
BACKEND = TrivialCache
INSTANCEID = getenv('SS_INSTANCEID', None)
TEMPLATES = {}
DEFAULTTEMPLATE = '_builtin'
TEMPLATENAME = DEFAULTTEMPLATE
URLPREFIX = 'https'
LISTENADDR = '127.0.0.1'
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

ADMINIPS = [ '127.0.0.1' ]
BLOCKEDUA = []

EMAIL = None

GENKEYS = 1
GENMAXKEYS = 32
GENKEYLEN = 16
GENKEYCHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"

# default template
builtintmpl = {
    'index': {
        'type': 'inline',
        'template': '''<html>
  <head>
    <title>ss</title>
  </head>
  <body>
    <form action="{{ data.urlprefix }}://{{ data.host }}/set" method="post">
      <table style="border: 0; padding: 0; border-spacing: 0;">
        <tr>
          <td style="vertical-align: top;">
            <dl style="margin: 0; padding: 0">
              <dt>message:</dt>
              <dd><textarea name="message" rows=6 cols=40 autofocus="autofocus"></textarea></dd>
            </dl>
          </td>
          <td style="vertical-align: top;">
            <dl style="margin: 0; padding: 0">
              <dt>copies:</dt>
              <dd><input type="text" name="copies" size=10 /></dd>
              <dt>views:</dt>
              <dd><input type="text" name="views" size=10 /></dd>
            </dl>
          </td>
        </tr>
        <tr>
          <td style="vertical-align: top;">
            <dl style="margin: 0; padding: 0">
              <dt>extra:</dt>
              <dd><input type="password" name="extra" size=30 /></dd>
            </dl>
          </td>
        </tr>
        {%- if data.canemail %}
        <tr>
          <td style="vertical-align: top;">
            <dl style="margin: 0; padding: 0">
              <dt>email:</dt>
              <dd><input type="text" name="email" size=40 /></dd>
            </dl>
          </td>
        </tr>
        <tr>
          <td style="vertical-align: top;">
            <dl style="margin: 0; padding: 0">
              <dt>email note:</dt>
              <dd><textarea name="note" rows=3 cols=40></textarea></dd>
            </dl>
          </td>
        </tr>
        {%- endif %}
      </table>
      <br />
      <input type="submit" value="Share" />
    </form>
  </body>
</html>''',
        'mimetype': 'text/html'
    },
    'getform': {
        'type': 'inline',
        'template': '''<html>
  <head>
    <title>ss</title>
  </head>
  <body>
    <form action="{{ data.urlprefix }}://{{ data.host }}/get/" method="post">
      <dl style="margin: 0; padding: 0">
        <dt>id:</dt>
        <dd><input type="text" name="arg" size=60 value="{{ data.msgid }}"/></dd>
        <dt>extra:</dt>
        <dd><input type="password" name="extra" size=30 /></dd>
      </dl>
      <br />
      <input type="submit" value="Retrieve" />
    </form>
  </body>
</html>''',
        'mimetype': 'text/html'
    },
    'getkey': {
        'type': 'inline',
        'template': '''{{ data.message }}''',
        'mimetype': 'text/plain'
    },
    'setkey': {
        'type': 'inline',
        'template': '{{ data.urlprefix }}://{{ data.host }}/get/{{ data.extra }}{{ data.keyid }}',
        'mimetype': 'text/plain'
    },
    'setkeys': {
        'type': 'inline',
        'template': '''{%- for keyid, err in data.keyids -%}
{% if keyid is defined %}{{ keyid }}{% else %}{{ err.errmsg }}{% endif %}
{% endfor %}
{%- if data.mailres -%}
    {%- for to, (errcode, errmsg) in data.mailres.items() -%}
{{ to }}: {{ errcode }} - {{ errmsg }}
    {%- endfor -%}
{%- endif %}''',
        'mimetype': 'text/plain'
    },
    'genkey': {
        'type': 'inline',
        'template': '''{%- for keyid, err in data.keyids -%}
{% if keyid is defined %}{{ keyid }}{% else %}{{ err.errmsg }}{% endif %}
{% endfor %}
{%- if data.mailres -%}
    {%- for to, (errcode, errmsg) in data.mailres.items() -%}
{{ to }}: {{ errcode }} - {{ errmsg }}
    {%- endfor -%}
{%- endif %}''',
        'mimetype': 'text/plain'
    },
    'genkeys': {
        'type': 'inline',
        'template': '''{%- for keyid in data.keyids -%}
{{ keyid }}
{% endfor %}''',
        'mimetype': 'text/plain'
    },
    'geterror': {
        'type': 'inline',
        'template': '''{{ data.errormsg }}''',
        'mimetype': 'text/plain'
    },
    'mailsubject': {
        'type': 'inline',
        'template': '''{{ data.keycount }} message(s) on {{ data.host }} at {{ time_now() }}''',
    },
    'mailplain': {
        'type': 'inline',
        'template': '''{%- if data.note -%}
{{ data.note }}

{% endif -%}
{%- for keyid, err in data.keyids -%}
{% if keyid is defined %}{{ keyid }}{% else %}{{ err.errmsg }}{% endif %}
{% endfor %}'''
    },
    'adminmsg': {
        'type': 'inline',
        'template': '''{{ data.message }}''',
        'mimetype': 'text/plain'
    },
    'adminerror': {
        'type': 'inline',
        'template': '''{{ data.errormsg }}''',
        'mimetype': 'text/plain'
    },
    'blockget': {
        'type': 'inline',
        'template': '',
        'mimetype': 'text/plain',
        'statuscode': 204
    }
}

# app init
app = Flask(__name__, static_url_path='')

app.config.from_object(__name__)
app.config.from_envvar('SS_CONFIG', silent = True)
app.debug = app.config['DEBUG']
app.config['TEMPLATES']['_builtin'] = builtintmpl

logger = logging.getLogger('werkzeug')

tls = local()
tls.cache = None
tls.template = None
tls.uaregex = None
tls.adminips = None
tls.emailips = None

def calc_subnets(subnets):
    result = {}

    for net in subnets:
        net = ipaddress.ip_network(unicode(net, 'utf-8'))
        mask = int(net.netmask)
        if mask not in result:
            result[mask] = []

        result[mask].append(int(net.network_address))

    return result

def is_allowed(ipaddr, subnets):
    ipaddr = int(ipaddress.ip_address(ipaddr))

    for mask, nets in subnets.items():
        if (ipaddr & mask) in nets:
            return True

    return False

# regex mapper
class RegexConverter(BaseConverter):
    def __init__(self, url_map, *items):
        super(RegexConverter, self).__init__(url_map)
        self.regex = items[0]

app.url_map.converters['regex'] = RegexConverter

app.jinja_env.globals.update(time_now = lambda:datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

def loaduaregexps():
    uaregex = []

    if app.config['BLOCKEDUA']:
        if isinstance(app.config['BLOCKEDUA'], list):
            uaiter = iter(app.config['BLOCKEDUA'])
        else:
            with open(app.config['BLOCKEDUA'], 'rU') as f:
                uaiter = f.readlines()

        for useragent in uaiter:
            uaregex.append(re.compile(useragent.rstrip('\r\n')))
            if app.config['DEBUG']:
                print('block: ' + useragent.rstrip('\r\n'))

    return uaregex

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

    tls.cache = KeyCache(app.config)
    tls.template = TrivialTemplate(app.config)

    tls.adminips = calc_subnets(app.config['ADMINIPS'] or [])
    if app.config['DEBUG']:
        print('adminips: ' + str(tls.adminips))
    tls.uaregex = loaduaregexps()

    if app.config['EMAIL']:
        tls.emailips = calc_subnets(app.config['EMAIL']['allowed'] or [])
        if app.config['DEBUG']:
            print('emailips: ' + str(tls.emailips))

@app.route('/', methods = ['GET', 'POST'])
def index():
    templatename = request.values.get('template', app.config['TEMPLATENAME'])
    if (templatename.lower() == 'none'):
        templatename = app.config['DEFAULTTEMPLATE']
    if app.config['DEBUG']:
        print('templatename: ' + templatename)

    return tls.template.renderresponse('index', templatename, host = request.host, urlprefix = app.config['URLPREFIX'],
        canemail = g.canemail)

def get_form(arg, templatename = app.config['TEMPLATENAME']):
    return tls.template.renderresponse('getform', templatename, host = request.host, urlprefix = app.config['URLPREFIX'], msgid = arg)

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
    templatename = request.values.get('template', app.config['TEMPLATENAME'])
    if (templatename.lower() == 'none'):
        templatename = app.config['DEFAULTTEMPLATE']
    if app.config['DEBUG']:
        print('arg: ' + arg)
        print('extra: ' + extra)
        print('templatename: ' + templatename)

    if tls.uaregex:
        uastr = request.user_agent.string
        for uaregex in tls.uaregex:
            if uaregex.search(uastr):
                if app.config['DEBUG']:
                    print('blocked: ' + uastr)
                return tls.template.renderresponse('blockget', templatename, msgid = arg, errormsg = 'Mhh')

    message, err = tls.cache.get(arg, extra)
    if not err:
        return tls.template.renderresponse('getkey', templatename, msgid = arg, message = message)
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
        return tls.template.renderresponse('geterror', templatename, msgid = arg, error = err, errormsg = errmsg.get(err, '?'))

def set_key(message, extra = '', views = app.config['DEFVIEWS'], templatename = app.config['TEMPLATENAME']):
    if app.config['DEBUG']:
        print('message: ' + message)
        print('extra: ' + str(extra))
        print('views: ' + str(views))
        print('templatename: ' + templatename)

    urlkey, err = tls.cache.set(message, extra, views)
    if urlkey:
        if extra:
            extraflag = '?'
        else:
            extraflag = ''
        return tls.template.rendertemplate('setkey', templatename, host = request.host, urlprefix = app.config['URLPREFIX'], keyid = urlkey, extra = extraflag, views = views), None
    else:
        errmsg = {
            tls.cache.ERROR_CACHE_NOTSET: 'No set'
        }
        return None, {'errnum': err, 'errmsg': errmsg.get(err, '?')}

def mail_keys(templatename, host, emails, keyids, copies, views, emailnote):
    smtpopts = {}
    if 'host' in app.config['EMAIL']:
        smtpopts['host'] = app.config['EMAIL']['host']
    if 'port' in app.config['EMAIL']:
        smtpopts['port'] = app.config['EMAIL']['port']
    if 'hostname' in app.config['EMAIL']:
        smtpopts['hostname'] = app.config['EMAIL']['hostname']

    if ('ssl' in app.config['EMAIL']) and (app.config['EMAIL']['ssl'] == True):
        if 'keyfile' in app.config['EMAIL']:
            smtpopts['keyfile'] = app.config['EMAIL']['keyfile']
        if 'certfile' in app.config['EMAIL']:
            smtpopts['certfile'] = app.config['EMAIL']['certfile']

        smtp = smtplib.SMTP_SSL(**smtpopts)
        if 'host' not in app.config['EMAIL']:
            smtp.connect()
    else:
        smtp = smtplib.SMTP(**smtpopts)
        if 'host' not in app.config['EMAIL']:
            smtp.connect()

        if ('starttls' in app.config['EMAIL']) and (app.config['EMAIL']['starttls'] == True):
            smtpopts = {}

            if 'keyfile' in app.config['EMAIL']:
                smtpopts['keyfile'] = app.config['EMAIL']['keyfile']
            if 'certfile' in app.config['EMAIL']:
                smtpopts['certfile'] = app.config['EMAIL']['certfile']

            smtp.starttls(**smtpopts)

    if ('user' in app.config['EMAIL']) and ('password' in app.config['EMAIL']):
        smtp.login(app.config['EMAIL']['user'], app.config['EMAIL']['password'])

    sender = app.config['EMAIL']['from']
    result = {}

    for to in emails:
        if '@' not in to:
            continue

        expires = str(timedelta(seconds=app.config['TIMEOUT']))

        if tls.template.hastemplate('mailplain', templatename):
            msgplain = MIMEText(tls.template.rendertemplate('mailplain', templatename, host = host, urlprefix = app.config['URLPREFIX'],
                sender = sender, to = to, keyids = keyids, copies = copies, views = views, expires = expires, note = emailnote), 'plain')
        else:
            msgplain = None

        if tls.template.hastemplate('mailhtml', templatename):
            msghtml = MIMEText(tls.template.rendertemplate('mailhtml', templatename, host = host, urlprefix = app.config['URLPREFIX'],
                sender = sender, to = to, keyids = keyids, copies = copies, views = views, expires = expires, note = emailnote), 'html')
        else:
            msghtml = None

        if msgplain and msghtml:
            msg = msg = MIMEMultipart('alternative')
            msg.attach(msgplain)
            msg.attach(msghtml)
        else:
            msg = msgplain or msghtml

        if sender:
            msg['From'] = sender
        msg['To'] = to
        msg['Subject'] = tls.template.rendertemplate('mailsubject', templatename, host = host, urlprefix = app.config['URLPREFIX'], sender = sender, to = to, keycount = len(keyids))

        if (app.config['DEBUG']):
            print(msg.as_string())

        try:
            smtp.sendmail(sender, [to], msg.as_string())
        except smtplib.SMTPRecipientsRefused as e:
            result.update(e.recipients)
        except smtplib.SMTPException as e:
            if 'smtp_error' in e:
                result[to] = e.smtp_error
            else:
                result[to] = 'Ugh'

    smtp.quit()
    return result

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

    email = re.split('[,;\s]*', request.form.get('email', '').encode('utf-8'))
    emailnote = request.form.get('note', '').encode('utf-8')

    templatename = request.values.get('template', app.config['TEMPLATENAME'])
    if (templatename.lower() == 'none'):
        templatename = app.config['DEFAULTTEMPLATE']

    if app.config['DEBUG']:
        print('message: ' + message)
        print('messagelen: ' + str(msglen))
        print('extra: ' + extra)
        print('copies: ' + str(copies))
        print('views: ' + str(views))
        print('email: ' + str(email))
        print('note: ' + emailnote)
        print('templatename: ' + templatename)

    result = [set_key(message, extra, views, templatename) for _ in xrange(copies)]

    if app.config['EMAIL'] and email and g.canemail:
        mailres = mail_keys(templatename, request.host, email, result, copies, views, emailnote)
    else:
        mailres = None

    return tls.template.renderresponse('setkeys', templatename, keyids = result, copies = copies, views = views, mailres = mailres)

def gen_key(keycharslen, keylen, copies, views, extra = '', templatename = app.config['TEMPLATENAME'], email = None, emailnote = None):
    genkey = ''.join([app.config['GENKEYCHARS'][ord(c) % keycharslen] for c in Random.new().read(keylen)])

    result = [set_key(genkey, extra, views, templatename) for _ in xrange(copies)]
    if email:
        mailres = mail_keys(templatename, request.host, email, result, copies, views, emailnote)
    else:
        mailres = None

    return tls.template.rendertemplate('genkey', templatename, keyids = result, keylen = keylen, copies = copies, views = views, mailres = mailres)

@app.route('/gen/', methods = ['GET', 'POST'], defaults = {'count': None, 'keylen': None, 'copies': None, 'views': None})
@app.route('/gen', methods = ['GET', 'POST'], defaults = {'count': None, 'keylen': None, 'copies': None, 'views': None})
@app.route('/gen/<count>/', methods = ['GET', 'POST'], defaults = {'keylen': None, 'copies': None, 'views': None})
@app.route('/gen/<count>', methods = ['GET', 'POST'], defaults = {'keylen': None, 'copies': None, 'views': None})
@app.route('/gen/<count>/<int:keylen>/', methods = ['GET', 'POST'], defaults = {'copies': None, 'views': None})
@app.route('/gen/<count>/<int:keylen>', methods = ['GET', 'POST'], defaults = {'copies': None, 'views': None})
@app.route('/gen/<count>/<int:keylen>/<int:copies>/', methods = ['GET', 'POST'], defaults = {'views': None})
@app.route('/gen/<count>/<int:keylen>/<int:copies>', methods = ['GET', 'POST'], defaults = {'views': None})
@app.route('/gen/<count>/<int:keylen>/<int:copies>/<int:views>/', methods = ['GET', 'POST'])
@app.route('/gen/<count>/<int:keylen>/<int:copies>/<int:views>', methods = ['GET', 'POST'])
def gen_keys(count, keylen, copies, views):
    if not count:
        count = urllib2.unquote(request.values.get('count', app.config['GENKEYS']))
        if not count:
            count = app.config['GENKEYS']
    if '@' in count:
        count = re.split(';+\s*', count)
        if not(app.config['EMAIL'] and g.canemail):
            count = len(count)
    else:
        count = int(count)

    if isinstance(count, int):
        if count < 1:
            count = app.config['GENKEYS']
        elif count > app.config['GENMAXKEYS']:
            count = app.config['GENMAXKEYS']

    if not keylen:
        keylen = request.values.get('keylen', app.config['GENKEYLEN'], type = int)
        if (not keylen) or (keylen < 1) or (keylen > app.config['MAX_CONTENT_LENGTH']):
            keylen = app.config['GENKEYLEN']

    if not copies:
        copies = request.values.get('copies', app.config['DEFCOPIES'], type = int)
        if not copies:
            copies = app.config['DEFCOPIES']
        elif copies < 1:
            copies = 1
        elif copies > app.config['MAXCOPIES']:
            copies = app.config['MAXCOPIES']

    if not views:
        views = request.values.get('views', app.config['DEFVIEWS'], type = int)
        if not views:
            views = app.config['DEFVIEWS']
        elif views < 1:
            views = 1
        elif views > app.config['MAXVIEWS']:
            views = app.config['MAXVIEWS']

    keycharslen = len(app.config['GENKEYCHARS'])

    extra = request.values.get('extra', '').encode('utf-8')

    emailnote = request.values.get('note', '').encode('utf-8')

    templatename = request.values.get('template', app.config['TEMPLATENAME'])
    if (templatename.lower() == 'none'):
        templatename = app.config['DEFAULTTEMPLATE']

    if app.config['DEBUG']:
        print('count: ' + str(count))
        print('note: ' + emailnote)
        print('keylen: ' + str(keylen))
        print('copies: ' + str(copies))
        print('views: ' + str(views))
        print('keycharslen: ' + str(keycharslen))
        print('templatename: ' + templatename)

    if isinstance(count, int):
        result = [gen_key(keycharslen, keylen, copies, views, extra, templatename) for _ in xrange(count)]
    else:
        result = [gen_key(keycharslen, keylen, copies, views, extra, templatename, re.split(',+\s*', email), emailnote) for email in count]
    return tls.template.renderresponse('genkeys', templatename, keyids = result, count = count, keylen = keylen, copies = copies, views = views)

@app.route('/admin/<regex("clearcache|reload(tmpl|ua)"):command>', methods = ['GET', 'POST'])
@app.route('/admin/<regex("clearcache|reload(tmpl|ua)"):command>/<param>', methods = ['GET', 'POST'])
def admin_cmds(command = '', param = ''):
    templatename = request.values.get('template', app.config['TEMPLATENAME'])
    if (templatename.lower() == 'none'):
        templatename = app.config['DEFAULTTEMPLATE']

    if app.config['DEBUG']:
        print('admin: ' + command)
        print('param: ' + param)
        print('templatename: ' + templatename)

    if not g.isadmin:
        return tls.template.renderresponse('adminerror', templatename, 403, errormsg = "Access denied")

    if command == 'clearcache':
        tls.cache.clear()
    elif (command == 'reloadtmpl'):
        if not param:
            param = templatename
        tls.template.loadtemplate(param)
    elif (command == 'reloadua'):
        loaduaregexps()
    else:
        return tls.template.renderresponse('adminerror', templatename, 400, errormsg = "Bad request")

    return tls.template.renderresponse('adminmsg', templatename, message = command)

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
        logger.info("accessroute: " + ', '.join(route))
        g.remoteaddr = route[-1]
    else:
        g.remoteaddr = unicode(request.remote_addr,'utf-8')

    g.isadmin = is_allowed(g.remoteaddr, tls.adminips)
    g.canemail = app.config['EMAIL'] and is_allowed(g.remoteaddr, tls.emailips)

    logger.info('useragent: ' + request.user_agent.string)

if __name__ == '__main__':
    app.run(host = app.config['LISTENADDR'], port = app.config['LISTENPORT'], debug = app.config['DEBUG'])

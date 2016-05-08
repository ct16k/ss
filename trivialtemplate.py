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

from flask import render_template_string, Response
from trivialcache import TrivialCache
import json
from pprint import pprint

class TrivialTemplate(object):
    def __init__(self, settings):
        # debug
        self._debug = ('DEBUG' in settings) and settings['DEBUG'] or False
        # cache ttl
        self._timeout = settings['TIMEOUT'] if ('TIMEOUT' in settings) else 7200
        # template list
        self._templatelist = settings['TEMPLATES']
        self._templates = TrivialCache(timeout = self._timeout)
        # default template, cached indefinitely
        self._deftmplname = settings['DEFAULTTEMPLATE'] if ('DEFAULTTEMPLATE' in settings) else list(settings['TEMPLATES'].keys())[0]
        self.loadtemplate(self._deftmplname)
        # cache templates
        for tmplname in self._templatelist:
            if tmplname != self._deftmplname:
                self.loadtemplate(tmplname)

    def _loadtemplate(self, templatename, templateconfig):
        if self._debug:
            print('load template config: ' + templatename)

        # load all template pages to memory
        for pagename in templateconfig:
            if ('type' not in templateconfig[pagename]) or (templateconfig[pagename]['type'] != 'inline'):
                with open(templateconfig[pagename]['template']) as pagetmpl:
                    templateconfig[pagename]['template'] = pagetmpl.read()
                    templateconfig[pagename]['type'] = 'inline'

        # fill in blanks from default
        if templatename != self._deftmplname:
            template = self.get(self._deftmplname)
        else:
            template = {}
        template.update(templateconfig)

        self._templates.set(templatename, template)
        if self._debug:
            pprint(template)

        return template

    def loadtemplate(self, templatename):
        if self._debug:
            print('load template: ' + templatename)

        tmplconfig = self._templatelist[templatename]
        if type(tmplconfig) is str:
            if self._debug:
                print('from file: ' + tmplconfig)

            with open(tmplconfig) as tmpljson:
                tmplconfig = json.load(tmpljson)

        return self._loadtemplate(templatename, tmplconfig)

    def get(self, templatename):
        return (self._templates.get(templatename) or self.loadtemplate(templatename))

    def hastemplate(self, pagename, templatename = None):
        templatename = templatename or self._deftmplname
        return (pagename in self.get(templatename))

    def rendertemplate(self, pagename, templatename = None, **kwargs):
        templatename = templatename or self._deftmplname
        template = self.get(templatename)[pagename]

        return render_template_string(template['template'], data = kwargs)

    def renderresponse(self, pagename, templatename = None, statuscode = None, **kwargs):
        templatename = templatename or self._deftmplname
        template = self.get(templatename)[pagename]

        if not statuscode:
            statuscode = template['statuscode'] if ('statuscode' in template) else 200

        return Response(render_template_string(template['template'], data = kwargs), status = statuscode, mimetype = template['mimetype'] if ('mimetype' in template) else 'text/html')

    def getmimetype(self, pagename, templatename = None):
        templatename = templatename or self._deftmplname
        template = self.get(templatename)[pagename]

        return template['mimetype'] if ('mimetype' in template) else 'text/html'

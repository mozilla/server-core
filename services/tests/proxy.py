# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is Sync Server
#
# The Initial Developer of the Original Code is the Mozilla Foundation.
# Portions created by the Initial Developer are Copyright (C) 2010
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Tarek Ziade (tarek@mozilla.com)
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.
#
# ***** END LICENSE BLOCK *****
"""Proxy that can be used to record and replay requests
"""
from wsgiref.simple_server import make_server
import threading
import shelve
import atexit

from services.util import proxy
from webob.dec import wsgify
from webob.exc import HTTPBadRequest


_DATA = None
_SERVER = None


def _open_data(path):
    global _DATA
    _DATA = shelve.open(path)


def _close_data():
    if _DATA is None:
        return
    _DATA.close()


atexit.register(_close_data)


class ProxyApp(object):
    def __init__(self, config):
        self.config = config
        _open_data(self.config['data'])

    @wsgify
    def __call__(self, request):
        if config['proxy']:
            scheme = config.get('scheme', 'http')
            netloc = config['netloc']
            print 'Proxying to %s' % netloc
            response = proxy(request, scheme, netloc)
            _DATA[str(request)] = response
            _DATA.sync()
            return response

        req = str(request)
        if req not in _DATA:
            raise HTTPBadRequest()

        return _DATA[req]


class ThreadedServer(threading.Thread):
    def __init__(self, server):
        threading.Thread.__init__(self)
        self.server = server

    def run(self):
        self.server.serve_forever()

    def join(self):
        self.server.shutdown()
        threading.Thread.join(self)


def start(config, background=True, beforestart=None):
    server = make_server('', -1, ProxyApp(config))
    port = server.server_address[-1]
    if not background:
        if beforestart is not None:
            beforestart(port)
        server.serve_forever()
    else:
        global _SERVER
        if _SERVER is not None:
            return
        _SERVER = ThreadedServer(server)
        _SERVER.start()
        return port


def stop():
    global _SERVER
    if _SERVER is None:
        return
    _SERVER.join()
    _SERVER = None


if __name__ == '__main__':
    config = {'proxy': False,
              'netloc': 'localhost:5000',
              'data': 'data'}

    try:

        def _start(port):
            print 'Running on localhost:%d' % port

        start(config, background=False, beforestart=_start)
    except KeyboardInterrupt:
        pass

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
"""
Application entry point.
"""
import time

from paste.translogger import TransLogger
from paste.exceptions.errormiddleware import ErrorMiddleware

from routes import Mapper

from webob.dec import wsgify
from webob.exc import HTTPNotFound, HTTPBadRequest
from webob import Response

from services.util import convert_config
from services.wsgiauth import Authentication


class SyncServerApp(object):
    """ BaseServerApp dispatches the request to the right controller
    by using Routes.
    """

    def __init__(self, urls, controllers, config=None,
                 auth_class=Authentication):
        self.mapper = Mapper()
        if config is not None:
            self.config = config
        else:
            self.config = {}

        # loading the authentication tool
        self.auth = auth_class(self.config)

        # loading and connecting controllers
        self.controllers = dict([(name, klass(self)) for name, klass in
                                 controllers.items()])

        for url in urls:
            if len(url) == 4:
                verbs, match, controller, method = url
                extras = {}
            elif len(url) == 5:
                verbs, match, controller, method, extras = url
            else:
                msg = "Each URL description needs 4 or 5 elements. Got %s" \
                    % str(url)
                raise ValueError(msg)

            if isinstance(verbs, str):
                verbs = [verbs]

            self.mapper.connect(None, match, controller=controller,
                                method=method, conditions=dict(method=verbs),
                                **extras)

        # loads host-specific configuration
        self._host_configs = {}

    def _before_call(self, request):
        return {}

    def _host_specific(self, request, config):
        """Will compute host-specific requests"""
        if request.host in self._host_configs:
            return self._host_configs[request.host]

        # overrides the original value with the host-specific value
        host_section = 'host:%s.' % request.host
        host_config = {}
        overriden_keys = []
        for key, value in config.items():
            if key in overriden_keys:
                continue

            if key.startswith(host_section):
                key = key[len(host_section):]
                overriden_keys.append(key)
            host_config[key] = value

        self._host_configs[request.host] = host_config
        return host_config

    @wsgify
    def __call__(self, request):
        if request.method in ('HEAD',):
            raise HTTPBadRequest('"%s" not supported' % request.method)

        request.server_time = round(time.time(), 2)

        # gets request-specific config
        request.config = self._host_specific(request, self.config)

        # pre-hook
        before_headers = self._before_call(request)

        # XXX
        # removing the trailing slash - ambiguity on client side
        url = request.path_info.rstrip('/')
        if url != '':
            request.environ['PATH_INFO'] = request.path_info = url
        match = self.mapper.routematch(environ=request.environ)

        if match is None:
            return HTTPNotFound()

        match, __ = match

        # authentication control
        self.auth.check(request, match)

        function = self._get_function(match['controller'], match['method'])
        if function is None:
            raise HTTPNotFound('Unkown URL %r' % request.path_info)

        # extracting all the info from the headers and the url
        request.sync_info = match

        # the GET mapping is filled on GET and DELETE requests
        if request.method in ('GET', 'DELETE'):
            params = dict(request.GET)
        else:
            params = {}

        result = function(request, **params)

        if isinstance(result, basestring):
            response = Response(result)
        else:
            # result is already a Response
            response = result

        # setting up the X-Weave-Timestamp
        response.headers['X-Weave-Timestamp'] = str(request.server_time)
        response.headers.update(before_headers)
        return response

    def _get_function(self, controller, method):
        """Return the method of the right controller."""
        try:
            controller = self.controllers[controller]
        except KeyError:
            return None
        return getattr(controller, method)


def set_app(urls, controllers, klass=SyncServerApp, auth_class=Authentication,
            wrapper=None):
    """make_app factory."""
    def make_app(global_conf, **app_conf):
        """Returns a Sync Server Application."""
        global_conf.update(app_conf)
        params = convert_config(global_conf)
        app = klass(urls, controllers, params, auth_class)

        if params.get('debug', False):
            app = TransLogger(app, logger_name='syncserver',
                              setup_console_handler=True)

        if params.get('profile', False):
            from repoze.profile.profiler import AccumulatingProfileMiddleware
            app = AccumulatingProfileMiddleware(app,
                                          log_filename='profile.log',
                                          cachegrind_filename='cachegrind.out',
                                          discard_first_request=True,
                                          flush_at_shutdown=True,
                                          path='/__profile__')

        if params.get('client_debug', False):
            app = ErrorMiddleware(app, debug=True,
                                  show_exceptions_in_wsgi_errors=True)

        if wrapper is not None:
            app = wrapper(app)
        return app
    return make_app

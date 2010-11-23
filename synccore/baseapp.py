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
from webob.exc import HTTPNotFound, HTTPUnauthorized, HTTPBadRequest
from webob import Response

from synccore.util import authenticate_user, convert_config
from synccore.auth import WeaveAuth

# pre-loading auth plugins the project provides to ease configuration
from synccore.auth.sql import SQLAuth
WeaveAuth.register(SQLAuth)

try:
    from synccore.auth.ldapsql import LDAPAuth
    WeaveAuth.register(LDAPAuth)
except ImportError:
    pass

from synccore.auth.dummy import DummyAuth
WeaveAuth.register(DummyAuth)

# URL dispatching happens here
# methods / match / controller / controller method / auth ?

# _API_ is replaced by {api:1.0|1}
# _COLLECTION_ is replaced by {collection:[a-zA-Z0-9._-]+}
# _USERNAME_ is replaced by {username:[a-zA-Z0-9._-]+}
# _ITEM_ is replaced by {item:[\\a-zA-Z0-9._?#~-]+}


class SyncServerApp(object):
    """ BaseServerApp dispatches the request to the right controller
    by using Routes.
    """

    def __init__(self, urls, controllers, config=None):
        self.mapper = Mapper()
        if config is not None:
            self.config = config
        else:
            self.config = {}

        # loading the authentication backend
        self.authtool = WeaveAuth.get_from_config(self.config)

        # loading and connecting controllers
        self.controllers = dict([(name, klass(self)) for name, klass in
                                 controllers.items()])

        for verbs, match, controller, method, auth in urls:
            if isinstance(verbs, str):
                verbs = [verbs]
            for pattern, replacer in (('_API_', '{api:1.0|1}'),
                                      ('_COLLECTION_',
                                       '{collection:[a-zA-Z0-9._-]+}'),
                                      ('_USERNAME_',
                                       '{username:[a-zA-Z0-9._-]+}'),
                                      ('_ITEM_',
                                       r'{item:[\\a-zA-Z0-9._?#~-]+}')):
                match = match.replace(pattern, replacer)

            self.mapper.connect(None, match, controller=controller,
                                method=method, conditions=dict(method=verbs),
                                auth=auth)

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

        if match['auth'] == 'True':
            # needs auth
            user_id = authenticate_user(request, self.authtool,
                                        self.config, match.get('username'))
            if user_id is None:
                raise HTTPUnauthorized

            match['user_id'] = user_id

        function = self._get_function(match['controller'], match['method'])
        if function is None:
            raise HTTPNotFound('Unkown URL %r' % request.path_info)

        # extracting all the info from the headers and the url
        request.sync_info = match

        if request.method in ('GET', 'DELETE'):
            # XXX DELETE fills the GET dict.
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


def set_app(urls, controllers, klass=SyncServerApp):
    """make_app factory."""
    def make_app(global_conf, **app_conf):
        """Returns a Sync Server Application."""
        global_conf.update(app_conf)
        params = convert_config(global_conf)
        app = klass(urls, controllers, params)

        if params.get('translogger', False):
            app = TransLogger(app, logger_name='weaveserver',
                              setup_console_handler=True)

        if params.get('profile', False):
            from repoze.profile.profiler import AccumulatingProfileMiddleware
            app = AccumulatingProfileMiddleware(app,
                                          log_filename='profile.log',
                                          cachegrind_filename='cachegrind.out',
                                          discard_first_request=True,
                                          flush_at_shutdown=True,
                                          path='/__profile__')

        if params.get('debug', False):
            app = ErrorMiddleware(app, debug=True,
                                show_exceptions_in_wsgi_errors=True)

        return app
    return make_app

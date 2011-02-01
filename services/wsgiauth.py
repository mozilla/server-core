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
Authentication class.
"""
import binascii
import base64

from webob.exc import HTTPUnauthorized, HTTPBadRequest

from services.auth import get_auth
from services.cef import log_cef
from services.util import extract_username


class Authentication(object):
    """Authentication tool. defines the authentication strategy"""
    def __init__(self, config):
        self.config = config
        self.backend = get_auth(self.config)

    def check(self, request, match):
        """Checks if the current request/match can be viewed.

        This function can raise an UnauthorizedError, or
        redirect to a login page.

        """
        if match.get('auth') != 'True':
            return

        user_id = self.authenticate_user(request, self.config,
                                         match.get('username'))
        if user_id is None:
            headers = [('WWW-Authenticate', 'Basic realm="Sync"'),
                       ('Content-Type', 'text/plain')]
            raise HTTPUnauthorized(headerlist=headers)

        match['user_id'] = user_id

    def authenticate_user(self, request, config, username=None):
        """Authenticates a user and returns his id.

        "request" is the request received.
        The function makes sure that the user name found in the headers
        is compatible with the username if provided.

        It returns the user id from the database, if the password is the right
        one.
        """
        environ = request.environ

        if 'REMOTE_USER' in environ:
            # already authenticated
            return environ['REMOTE_USER']

        auth = environ.get('HTTP_AUTHORIZATION')
        if auth is not None:
            # for now, only supporting basic authentication
            # let's decipher the base64 encoded value
            if not auth.startswith('Basic '):
                raise HTTPUnauthorized('Invalid token')

            auth = auth[len('Basic '):].strip()
            try:
                user_name, password = base64.decodestring(auth).split(':')
            except (binascii.Error, ValueError):
                raise HTTPUnauthorized('Invalid token')

            # let's reject the call if the url is not owned by the user
            if (username is not None and user_name != username):
                log_cef('Username Does Not Match URL', 7, environ, config)
                raise HTTPUnauthorized()

            # if this is an email, hash it. Save the original for logging and
            #  debugging.
            if "@" in user_name:
                remote_user_original = user_name
            try:
                user_name = extract_username(user_name)
            except UnicodeError:
                log_cef('Invalid characters specified in username ', 5,
                            environ, config)
                raise HTTPBadRequest('Invalid characters specified in ' +
                                     'username', {}, 'Username must be BIDI ' +
                                     'compliant UTF-8')

            # let's try an authentication
            user_id = self.backend.authenticate_user(user_name, password)
            if user_id is None:
                err = 'Authentication Failed for Backend service ' + user_name
                if remote_user_original is not None and \
                    user_name != remote_user_original:
                        err += ' (%s)' % (remote_user_original)
                log_cef(err, 5, environ, config)
                raise HTTPUnauthorized()

            # we're all clear ! setting up REMOTE_USER
            request.remote_user = environ['REMOTE_USER'] = user_name

            # we also want to keep the password in clear text to reuse it
            # and remove it from the environ
            request.user_password = password
            request._authorization = environ['HTTP_AUTHORIZATION']
            del environ['HTTP_AUTHORIZATION']
            return user_id

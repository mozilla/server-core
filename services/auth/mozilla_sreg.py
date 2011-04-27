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
""" Mozilla Authentication using a two-tier system
"""
import simplejson as json
import urlparse

from services.util import BackendError, get_url
from services.auth.ldapsql import LDAPAuth
from services import logger
from services.auth.ldapconnection import StateConnector
from services.auth import NoEmailError, InvalidCodeError
from services.respcodes import WEAVE_NO_EMAIL_ADRESS, WEAVE_INVALID_RESET_CODE


class MozillaAuth(LDAPAuth):
    """LDAP authentication."""

    def __init__(self, ldapuri, sreg_location, sreg_path, sreg_scheme='https',
                 use_tls=False, bind_user='binduser',
                 bind_password='binduser', admin_user='adminuser',
                 admin_password='adminuser', users_root='ou=users,dc=mozilla',
                 users_base_dn=None, pool_size=100, pool_recycle=3600,
                 reset_on_return=True, single_box=False, ldap_timeout=-1,
                 nodes_scheme='https', check_account_state=True,
                 create_tables=False, ldap_pool_size=10, ldap_use_pool=False,
                 connector_cls=StateConnector, **kw):

        super(MozillaAuth, self).__init__(ldapuri, None, use_tls, bind_user,
                                     bind_password, admin_user,
                                     admin_password, users_root,
                                     users_base_dn, pool_size, pool_recycle,
                                     reset_on_return, single_box, ldap_timeout,
                                     nodes_scheme, check_account_state,
                                     create_tables, ldap_pool_size,
                                     ldap_use_pool, connector_cls)

        self.sreg_location = sreg_location
        self.sreg_scheme = sreg_scheme
        self.sreg_path = sreg_path

    def _proxy(self, method, url, data=None, headers=None):
        """Proxies and return the result from the other server.

        - scheme: http or https
        - netloc: proxy location
        """
        if data is not None:
            data = json.dumps(data)

        status, headers, body = get_url(url, method, data, headers)

        if body:
            try:
                body = json.loads(body)
            except Exception:
                logger.error("bad json body from sreg (%s): %s" %
                                                        (url, body))

        return status, body

    @classmethod
    def get_name(self):
        """Returns the name of the authentication backend"""
        return 'mozilla_sreg'

    def create_user(self, username, password, email):
        """Creates a user. Returns True on success."""
        payload = {'password': password, 'email': email}
        url = self.generate_url(username)
        status, body = self._proxy('PUT', url, payload)
        if status != 200:
            raise BackendError()

        # the result is the username on success
        return body == username

    def generate_reset_code(self, user_id, overwrite=True):
        """Sends a reset code by e-mail

        Args:
            user_id: user id
            overwrite: if True, overwrites an existing code

        Returns:
            True if reset code was generated and sent to user, False otherwise
        """
        username = self._get_username(user_id)
        status, body = self._proxy('GET',
                             self.generate_url(username,
                                               'password_reset_code'))
        if status == 200:
            return body == 0

        if status == 400:
            if body == WEAVE_NO_EMAIL_ADRESS:
                raise NoEmailError()

        raise BackendError()

    def verify_reset_code(self, user_id, code):
        """Verify a reset code

        Args:
            user_id: user id
            code: reset code

        Returns:
            True or False
        """
        raise NotImplementedError()

    def clear_reset_code(self, user_id):
        """Clears the reset code

        Args:
            user_id: user id

        Returns:
            True if the change was successful, False otherwise
        """
        # handled by sreg
        username = self._get_username(user_id)
        status, body = self._proxy('DELETE', self.generate_url(username,
                                                        'password_reset_code'))
        if status != 200:
            raise BackendError()

        return body == 0

    def get_user_node(self, user_id, assign=True):
        if self.single_box:
            return None

        node = super(MozillaAuth, self).get_user_node(user_id,
                                                      assign=False)
        if node is not None or assign is False:
            return node

        username = self._get_username(user_id)
        url = self.generate_url(username, 'node/weave')
        status, body = self._proxy('GET', url)
        if status != 200:
            raise BackendError()

        return body

    def update_password(self, user_id, new_password,
                        old_password=None, key=None):
        """Change the user password.

        Uses the admin bind or the user bind if the old password is provided.

        Args:
            user_id: user id
            password: new password
            old_password: old password of the user (optional)
            key: the reset code

        Returns:
            True if the change was successful, False otherwise
        """
        if old_password is not None:
            return super(MozillaAuth, self).update_password(user_id,
                                              new_password,
                                              old_password=old_password)

        if not key:
            logger.error("Calling update password without password or key")
            return False

        payload = {'reset_code': key, 'password': new_password}
        username = self._get_username(user_id)
        url = self.generate_url(username, 'password')
        status, body = self._proxy('POST', url, payload)
        if status == 200:
            return body == 0
        elif status == 400:
            if body == WEAVE_INVALID_RESET_CODE:
                raise InvalidCodeError()

        raise BackendError()

    def generate_url(self, username, additional_path=None):
        path = "%s/%s" % (self.sreg_path, username)
        if additional_path:
            path = "%s/%s" % (path, additional_path)

        url = urlparse.urlunparse([self.sreg_scheme, self.sreg_location,
                                  path,
                                  None, None, None])
        return url

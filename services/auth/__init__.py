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
""" Authentication tool
"""
import abc
from services.pluginreg import PluginRegistry


class NodeAttributionError(Exception):
    """Raised when the node attribution fails."""
    pass


class ServicesAuth(PluginRegistry):
    """Abstract Base Class for the authentication APIs."""
    plugin_type = 'auth'

    @abc.abstractmethod
    def get_name(self):
        """Returns the name of the plugin.

        Must be a class method.

        Args:
            None

        Returns:
            The plugin name
        """

    @abc.abstractmethod
    def get_user_id(self, user_name):
        """Returns the id for a user name.

        Args:
            user_name: user name

        Returns:
            user id. None if not found.
        """

    @abc.abstractmethod
    def create_user(self, user_name, password, email):
        """Creates a user

        Args:
            - user_name: the user name
            - password: the password associated with the user
            - email: the email associated with the user

        Returns:
            True or False, depending if the creation was successfull
        """

    @abc.abstractmethod
    def authenticate_user(self, user_name, password):
        """Authenticates a user.

        Args:
            - user_name: string
            - password: password

        Returns:
            The user id in case of success. None otherwise.
        """

    @abc.abstractmethod
    def generate_reset_code(self, user_id, overwrite=False):
        """Generates a password reset code

        Args:
            user_id: user id
            overwrite: if True, overwrites an existing code

        Returns:
            a reset code
        """

    @abc.abstractmethod
    def verify_reset_code(self, user_id, code):
        """Verifies a password reset code

        Args:
            - user_id: user id
            - code: reset code

        Returns:
            True or False
        """

    @abc.abstractmethod
    def clear_reset_code(self, user_id):
        """Clears the password reset code

        Args:
            user_id: user id

        Returns:
            None
        """

    @abc.abstractmethod
    def get_user_info(self, user_id):
        """Returns user info

        Args:
            user_id: user id

        Returns:
            tuple: username, email
        """

    @abc.abstractmethod
    def update_email(self, user_id, email):
        """Change the user e-mail

        Args:
            - user_id: user id
            - email: new email

        Returns:
            True if the change was successful, False otherwise
        """

    @abc.abstractmethod
    def delete_user(self, user_id, password=None):
        """Deletes a user

        Args:
            user_id: user id
            password: user password if needed

        Returns:
            True if the deletion was successful, False otherwise
        """

    @abc.abstractmethod
    def get_user_node(self, user_id, assign=True):
        """Returns the node of the user.

        This method is also responsible to initialize the user's node
        location. If the backend is unable to attribute a node, it will raise a
        NodeAttributionError. If the backend is configured for a single box, it
        will return None.

        Args:
            user_id: user id

        Returns:
            The node URL. None if the auth does not support node location.
            None is returned on single-boxe setups.
        """


def get_auth(config):
    """Returns an auth backend instance, given a config.

    "config" is a mapping, containing the configuration.
    All keys that starts with "auth." are used in the function.


    - "auth.backend" must be present and contain a fully qualified name of a
      backend class to be used, or the name of any backend services provides.
      "sql", "ldap" or "dummy".

    - other keys that starts with "auth." are passed to the backend
      constructor -- with the prefix stripped.
    """
    # pre-loading auth plugins services provides to ease configuration
    try:
        from services.auth.sql import SQLAuth
        ServicesAuth.register(SQLAuth)
    except ImportError:
        pass

    try:
        from services.auth.ldapsql import LDAPAuth
        ServicesAuth.register(LDAPAuth)
    except ImportError:
        pass

    try:
        from services.auth.mozilla import MozillaAuth
        ServicesAuth.register(MozillaAuth)
    except ImportError:
        pass

    from services.auth.dummy import DummyAuth
    ServicesAuth.register(DummyAuth)

    return ServicesAuth.get_from_config(config)

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
""" LDAP Connection Pool.
"""
import time
from contextlib import contextmanager
from threading import RLock

from ldap.ldapobject import ReconnectLDAPObject
import ldap

from services.util import BackendError, BackendTimeoutError


class MaxConnectionReachedError(Exception):
    pass


class StateConnector(ReconnectLDAPObject):
    """Just remembers who is connected, and if connected"""

    def simple_bind_s(self, who='', cred='', serverctrls=None,
                      clientctrls=None):
        res = ReconnectLDAPObject.simple_bind_s(self, who, cred, serverctrls,
                                                clientctrls)
        self.connected = True
        self.who = who
        self.cred = cred
        return res

    def unbind_ext_s(self, serverctrls=None, clientctrls=None):
        try:
            return ReconnectLDAPObject.unbind_ext_s(self, serverctrls,
                                                    clientctrls)
        finally:
            self.connected = False
            self.who = None
            self.cred = None

    def add_s(self, *args, **kwargs):
        return self._apply_method_s(ReconnectLDAPObject.add_s, *args,
                                    **kwargs)

    def modify_s(self, *args, **kwargs):
        return self._apply_method_s(ReconnectLDAPObject.modify_s, *args,
                                    **kwargs)


class ConnectionManager(object):
    """LDAP Connection Manager.

    Provides a context manager for LDAP connectors.
    """
    def __init__(self, uri, bind=None, passwd=None, size=10, retry_max=3,
                 retry_delay=.1, use_tls=False, single_box=False, timeout=-1,
                 connector_cls=StateConnector, use_pool=False):
        self._pool = []
        self.size = size
        self.retry_max = retry_max
        self.retry_delay = retry_delay
        self.uri = uri
        self.bind = bind
        self.passwd = passwd
        self._pool_lock = RLock()
        self.use_tls = False
        self.timeout = timeout
        self.connector_cls = connector_cls
        self.use_pool = use_pool

    def __len__(self):
        return len(self._pool)

    def _match(self, bind, passwd):
        with self._pool_lock:
            for conn in list(self._pool):
                if conn.active:
                    continue

                # any connection w/ no creds matches
                if conn.who is None:
                    conn.active = True
                    return conn

                # we found a connector for this bind, that can be used
                if conn.who == bind and conn.cred == passwd:
                    try:
                        conn.unbind_ext_s()
                    except ldap.LDAPError:
                        # avoid error on invalid state
                        pass
                    try:
                        conn.simple_bind_s(bind, passwd)
                    except ldap.LDAPError:
                        # invalid connector, to be discarded
                        self._pool.remove(conn)
                        continue
                    else:
                        conn.active = True
                        return conn

        return None

    def _create_connector(self, bind, passwd):
        """Creates a connector, binds it, and returns it"""
        conn = self.connector_cls(self.uri, retry_max=self.retry_max,
                                  retry_delay=self.retry_delay)
        conn.timeout = self.timeout

        if self.use_tls:
            conn.start_tls_s()

        # let's bind
        if bind is not None:
            tries = 0
            connected = False
            e = None
            while tries < self.retry_max and not connected:
                try:
                    conn.simple_bind_s(bind, passwd)
                except ldap.TIMEOUT, e:
                    raise BackendTimeoutError(str(e))
                except (ldap.SERVER_DOWN, ldap.OTHER), e:
                    try:
                        conn.unbind_ext_s()
                    except ldap.LDAPError:
                        # invalid connection
                        pass
                    time.sleep(self.retry_delay)
                    tries += 1
                else:
                    # we're good
                    connected = True

            if not connected:
                raise BackendError(str(e))

        conn.active = True
        return conn

    def _get_connection(self, bind=None, passwd=None):
        if bind is None:
            bind = self.bind
        if passwd is None:
            passwd = self.passwd

        if self.use_pool:
            # let's try to recycle an existing one
            conn = self._match(bind, passwd)
            if conn is not None:
                return conn

            # the pool is full
            if len(self._pool) >= self.size:
                raise MaxConnectionReachedError(self.uri)

        # we need to create a new connector
        conn = self._create_connector(bind, passwd)

        # adding it to the pool
        if self.use_pool:
            with self._pool_lock:
                self._pool.append(conn)

        return conn

    def _release_connection(self, connection):
        if self.use_pool:
            with self._pool_lock:
                if not connection.connected:
                    # unconnected connector, let's drop it
                    self._pool.remove(connection)
                else:
                    # can be reused - let's mark is as not active
                    connection.active = False

        # in any case, try to unbind it
        try:
            connection.unbind_ext_s()
        except ldap.LDAPError:
            # avoid error on invalid state
            pass

    @contextmanager
    def connection(self, bind=None, passwd=None):
        tries = 0
        conn = None
        while tries < self.retry_max:
            try:
                conn = self._get_connection(bind, passwd)
            except MaxConnectionReachedError:
                tries += 1
                time.sleep(0.1)
                # removing the first inactive connector
                with self._pool_lock:
                    for index, conn_ in enumerate(list(self._pool)):
                        if not conn_.active:
                            self._pool.pop(index)
                            break
            else:
                break

        if conn is None:
            raise MaxConnectionReachedError(self.uri)

        try:
            yield conn
        finally:
            self._release_connection(conn)

    def purge(self, bind, passwd=None):
        if self.use_pool:
            return

        with self._pool_lock:
            for conn in list(self._pool):
                if conn.who != bind:
                    continue
                if passwd is not None and conn.cred == passwd:
                    continue
                # let's drop it
                try:
                    conn.unbind_ext_s()
                except ldap.LDAPError:
                    # invalid state
                    pass
                self._pool.remove(conn)

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
from contextlib import contextmanager
from threading import RLock
from ldap.ldapobject import ReconnectLDAPObject


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
        return res

    def unbind_ext_s(self, serverctrls=None, clientctrls=None):
        res = ReconnectLDAPObject.unbind_ext_s(self, serverctrls, clientctrls)
        self.connected = False
        self.who = None
        return res


class ConnectionPool(object):
    """LDAP Connector pool.
    """

    def __init__(self, uri, bind=None, passwd=None, size=100, retry_max=10,
                 retry_delay=1., use_tls=False, single_box=False):
        self._pool = []
        self.size = size
        self.retry_max = retry_max
        self.retry_delay = retry_delay
        self.uri = uri
        self.bind = bind
        self.passwd = passwd
        self._pool_lock = RLock()
        self.use_tls = False

    def _get_connection(self, bind=None, passwd=None):
        if bind is None:
            bind = self.bind
        if passwd is None:
            passwd = self.passwd

        self._pool_lock.acquire()
        try:
            for conn in self._pool:
                if not conn.active and (conn.who is None or conn.who == bind):
                    # we found a connector for this bind, that can be used
                    conn.active = True
                    return conn
        finally:
            self._pool_lock.release()

        # the pool is full
        if len(self._pool) >= self.size:
            raise MaxConnectionReachedError(self.uri)

        # we need to create a connector
        conn = StateConnector(self.uri, retry_max=self.retry_max,
                              retry_delay=self.retry_delay)

        if self.use_tls:
            conn.start_tls_s()

        if bind is not None:
            conn.simple_bind_s(bind, passwd)

        conn.active = True
        self._pool_lock.acquire()
        try:
            self._pool.append(conn)
        finally:
            self._pool_lock.release()
        return conn

    def _release_connection(self, connection):
        if not connection.connected:
            # unconnected connector, let's drop it
            self._pool.remove(connection)
        else:
            # can be reused - let's mark is as not active
            connection.active = False

    @contextmanager
    def connection(self, bind=None, passwd=None):
        conn = None
        try:
            conn = self._get_connection(bind, passwd)
            yield conn
        finally:
            if conn is not None:
                self._release_connection(conn)

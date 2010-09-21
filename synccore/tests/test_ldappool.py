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
import unittest
import threading

try:
    import ldap
    from synccore.auth.ldapsql import (ConnectionPool, StateConnector,
                                       MaxConnectionReachedError)
    LDAP = True
except ImportError:
    LDAP = False

if LDAP:
    # patching StateConnector
    StateConnector.users = {'uid=tarek,ou=users,dc=mozilla':
                                        {'uidNumber': ['1'],
                                         'account-enabled': ['Yes'],
                                         'mail': ['tarek@mozilla.com'],
                                         'cn': ['tarek']},
                            'cn=admin,dc=mozilla': {'cn': ['admin'],
                                                    'mail': ['admin'],
                                                    'uidNumber': ['100']}}

    def _simple_bind(self, who, *args):
        self.connected = True
        self.who = who

    StateConnector.simple_bind_s = _simple_bind

    def _search(self, dn, *args, **kw):
        if dn in self.users:
            return [(dn, self.users[dn])]
        elif dn == 'ou=users,dc=mozilla':
            uid = kw['filterstr'].split('=')[-1][:-1]
            for dn_, value in self.users.items():
                if value['uidNumber'][0] != uid:
                    continue
                return [(dn_, value)]

        raise ldap.NO_SUCH_OBJECT

    StateConnector.search_s = _search

    def _add(self, dn, user):
        self.users[dn] = {}
        for key, value in user:
            if not isinstance(value, list):
                value = [value]
            self.users[dn][key] = value

        return ldap.RES_ADD, ''

    StateConnector.add_s = _add

    def _modify(self, dn, user):
        if dn in self.users:
            for type_, key, value in user:
                if not isinstance(value, list):
                    value = [value]
                self.users[dn][key] = value
        return ldap.RES_MODIFY, ''

    StateConnector.modify_s = _modify

    def _delete(self, dn):
        if dn in self.users:
            del self.users[dn]
        return ldap.RES_DELETE, ''

    StateConnector.delete_s = _delete


class LDAPWorker(threading.Thread):

    def __init__(self, pool):
        threading.Thread.__init__(self)
        self.pool = pool
        self.results = []

    def run(self):
        dn = 'cn=admin,dc=mozilla'
        for i in range(10):
            with self.pool.connection() as conn:
                res = conn.search_s(dn, ldap.SCOPE_BASE,
                                    attrlist=['cn'])
                self.results.append(res)


class TestLDAPSQLAuth(unittest.TestCase):

    def test_pool(self):
        if not LDAP:
            return
        dn = 'uid=adminuser,ou=logins,dc=mozilla'
        passwd = 'adminuser'
        pool = ConnectionPool('ldap://localhost', dn, passwd)
        workers = [LDAPWorker(pool) for i in range(10)]

        for worker in workers:
            worker.start()

        for worker in workers:
            worker.join()
            self.assertEquals(len(worker.results), 10)
            cn = worker.results[0][0][1]['cn']
            self.assertEquals(cn, ['admin'])

    def test_pool_full(self):
        if not LDAP:
            return
        dn = 'uid=adminuser,ou=logins,dc=mozilla'
        passwd = 'adminuser'
        pool = ConnectionPool('ldap://localhost', dn, passwd, size=0)

        def tryit():
            with pool.connection() as conn:  # NOQA
                pass

        self.assertRaises(MaxConnectionReachedError, tryit)

    def test_pool_reuse(self):
        if not LDAP:
            return
        dn = 'uid=adminuser,ou=logins,dc=mozilla'
        passwd = 'adminuser'
        pool = ConnectionPool('ldap://localhost', dn, passwd)

        with pool.connection() as conn:
            self.assertTrue(conn.active)

        self.assertFalse(conn.active)
        self.assertTrue(conn.connected)

        with pool.connection() as conn2:
            pass

        self.assertTrue(conn is conn2)

        with pool.connection() as conn:
            conn.connected = False

        with pool.connection() as conn2:
            pass

        self.assertTrue(conn is not conn2)
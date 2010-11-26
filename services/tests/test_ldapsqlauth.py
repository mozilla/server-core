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
try:
    import ldap
    from services.auth.ldappool import StateConnector
    from services.auth.ldapsql import LDAPAuth
    LDAP = True
except ImportError:
    LDAP = False

if LDAP:
    # memory ldap connector for the tests

    class MemoryStateConnector(StateConnector):

        users = {'uid=tarek,ou=users,dc=mozilla':
                {'uidNumber': ['1'],
                 'account-enabled': ['Yes'],
                 'mail': ['tarek@mozilla.com'],
                 'cn': ['tarek']},
                 'cn=admin,dc=mozilla': {'cn': ['admin'],
                 'mail': ['admin'],
                 'uidNumber': ['100']}}

        def __init__(self):
            pass

        def simple_bind_s(self, who, *args):
            self.connected = True
            self.who = who

        def search_st(self, dn, *args, **kw):
            if dn in self.users:
                return [(dn, self.users[dn])]
            elif dn == 'ou=users,dc=mozilla':
                uid = kw['filterstr'].split('=')[-1][:-1]
                for dn_, value in self.users.items():
                    if value['uidNumber'][0] != uid:
                        continue
                    return [(dn_, value)]
            raise ldap.NO_SUCH_OBJECT

        def add_s(self, dn, user):
            self.users[dn] = {}
            for key, value in user:
                if not isinstance(value, list):
                    value = [value]
                self.users[dn][key] = value
            return ldap.RES_ADD, ''

        def modify_s(self, dn, user):
            if dn in self.users:
                for type_, key, value in user:
                    if not isinstance(value, list):
                        value = [value]
                    self.users[dn][key] = value
            return ldap.RES_MODIFY, ''

        def delete_s(self, dn):
            if dn in self.users:
                del self.users[dn]
            return ldap.RES_DELETE, ''

    from contextlib import contextmanager

    @contextmanager
    def _conn(self, bind=None, password=None):
        yield MemoryStateConnector()

    LDAPAuth._conn = _conn


class TestLDAPSQLAuth(unittest.TestCase):

    def test_ldap_auth(self):
        if not LDAP:
            return
        auth = LDAPAuth('ldap://localhost',
                        'sqlite:///:memory:')

        auth.create_user('tarek', 'tarek', 'tarek@ziade.org')
        uid = auth.get_user_id('tarek')

        auth_uid = auth.authenticate_user('tarek', 'tarek')
        self.assertEquals(auth_uid, uid)

        # reset code APIs
        code = auth.generate_reset_code(uid)
        self.assertFalse(auth.verify_reset_code(uid, 'beh'))
        self.assertFalse(auth.verify_reset_code(uid, 'XXXX-XXXX-XXXX-XXXX'))
        self.assertTrue(auth.verify_reset_code(uid, code))
        auth.clear_reset_code(uid)
        self.assertFalse(auth.verify_reset_code(uid, code))

        # e-mail update
        auth.update_email(uid, 'new@email.com')
        name, email = auth.get_user_info(uid)
        self.assertEquals(email, 'new@email.com')

        # update password
        auth.update_password(uid, 'xxxx')
        #auth_uid = auth.authenticate_user('tarek', 'tarek')
        #self.assertEquals(auth_uid, None)
        #auth_uid = auth.authenticate_user('tarek', 'xxxx')
        #self.assertEquals(auth_uid, ui)
        auth.delete_user(uid, 'xxxx')
        auth_uid = auth.authenticate_user('tarek', 'xxxx')
        self.assertEquals(auth_uid, None)

    def test_node_attribution(self):
        if not LDAP:
            return

        # let's set up some nodes in the SQL DB
        auth = LDAPAuth('ldap://localhost',
                        'sqlite:///:memory:')

        sql = ('insert into available_nodes (node, ct, actives) '
                'values("%s", %d, %d)')

        for node, ct, actives in (('node1', 10, 101),
                                  ('node2', 0, 100),
                                  ('node3', 1, 89)):

            auth._engine.execute(sql % (node, ct, actives))

        auth.create_user('tarek', 'tarek', 'tarek@ziade.org')
        uid = auth.get_user_id('tarek')

        # first call will set it up
        self.assertEquals(auth.get_user_node(uid), 'https://node3/')
        self.assertEquals(auth.get_user_node(uid), 'https://node3/')

        # node3 is full now. Next user should be on node1
        auth.create_user('tarek2', 'tarek2', 'tarek@ziade.org')
        uid = auth.get_user_id('tarek2')
        self.assertEquals(auth.get_user_node(uid), 'https://node1/')

    def test_md5_dn(self):
        if not LDAP:
            return
        auth = LDAPAuth('ldap://localhost', 'sqlite:///:memory:',
                        users_root='md5',
                        users_base_dn='dc=mozilla')

        wanted = 'uid=tarek,dc=17507,dc=7507,dc=507,dc=07,dc=7,dc=mozilla'
        self.assertEquals(auth._get_dn('tarek'), wanted)

        # now make sure the code hapilly uses this setting
        auth.create_user('tarek', 'tarek', 'tarek@ziade.org')
        uid = auth.get_user_id('tarek')
        auth_uid = auth.authenticate_user('tarek', 'tarek')
        self.assertEquals(auth_uid, uid)

    def _create_user(self, auth, user_name, password, email):
        from services.auth.ldapsql import *   # NOQA
        user_name = str(user_name)
        user_id = auth._get_next_user_id()
        password_hash = ssha(password)
        key = '%s%s' % (random.randint(0, 9999999), user_name)
        key = sha1(key).hexdigest()

        user = {'cn': user_name,
                'sn': user_name,
                'uid': user_name,
                'uidNumber': str(user_id),
                'primaryNode': 'weave:',
                'rescueNode': 'weave:',
                'userPassword': password_hash,
                'account-enabled': 'XXXX',
                'mail': email,
                'mail-verified': key,
                'objectClass': ['dataStore', 'inetOrgPerson']}

        user = user.items()
        dn = auth._get_dn(user_name)

        with auth._conn(auth.admin_user, auth.admin_password) as conn:
            try:
                res, __ = conn.add_s(dn, user)
            except ldap.TIMEOUT:
                raise BackendTimeoutError()

        return res == ldap.RES_ADD

    def test_no_disabled_check(self):
        if not LDAP:
            return
        auth = LDAPAuth('ldap://localhost', 'sqlite:///:memory:',
                        users_base_dn='dc=mozilla',
                        check_account_state=False)

        self._create_user(auth, 'tarek', 'tarek', 'tarek@ziade.org')
        uid = auth.authenticate_user('tarek', 'tarek')
        self.assertTrue(uid is not None)

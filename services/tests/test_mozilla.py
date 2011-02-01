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
import wsgi_intercept
from webob import Response
from wsgi_intercept.urllib2_intercept import install_opener
install_opener()

try:
    import ldap
    from services.auth.ldappool import StateConnector
    from services.auth.ldapsql import LDAPAuth
    from services.auth.mozilla import MozillaAuth
    LDAP = True
except ImportError:
    LDAP = False

if LDAP:
    # memory ldap connector for the tests

    class MemoryStateConnector(StateConnector):

        users = {'uid=tarek,ou=users,dc=mozilla':
                {'uidNumber': ['1'],
                 'uid': ['tarek'],
                 'account-enabled': ['Yes'],
                 'mail': ['tarek@mozilla.com'],
                 'cn': ['tarek']},
                 'cn=admin,dc=mozilla': {'cn': ['admin'],
                 'mail': ['admin'],
                 'uid': ['admin'],
                 'uidNumber': ['100']}}

        def __init__(self):
            pass

        def simple_bind_s(self, who, *args):
            self.connected = True
            self.who = who

        def search_st(self, dn, *args, **kw):
            if dn in self.users:
                return [(dn, self.users[dn])]
            elif dn in ('ou=users,dc=mozilla', 'dc=mozilla', 'md5'):
                key, field = kw['filterstr'][1:-1].split('=')
                for dn_, value in self.users.items():
                    if value[key][0] != field:
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

        def delete_s(self, dn, **kw):
            if dn in self.users:
                del self.users[dn]
            elif dn in ('ou=users,dc=mozilla', 'md5'):
                key, field = kw['filterstr'][1:-1].split('=')
                for dn_, value in self.users.items():
                    if value[key][0] == field:
                        del value[key]
                        return ldap.RES_DELETE, ''
            return ldap.RES_DELETE, ''

    from contextlib import contextmanager

    @contextmanager
    def _conn(self, bind=None, password=None):
        yield MemoryStateConnector()

    LDAPAuth._conn = _conn


# returns a body that has all the responses we need
def fake_response():
    return Response('{"success": 1, "code": "AAAA-AAAA-AAAA-AAAA"}')


# returns a body that has all the responses we need
def bad_reset_code_response():
    return Response("")


class TestLDAPSQLAuth(unittest.TestCase):

    def test_mozilla_auth(self):
        if not LDAP:
            return

        wsgi_intercept.add_wsgi_intercept('localhost', 80, fake_response)
        auth = MozillaAuth('ldap://localhost',
                        'localhost', 'this_path', 'http')

        auth.create_user('tarek', 'tarek', 'tarek@ziade.org')
        uid = auth.get_user_id('tarek')

        auth_uid = auth.authenticate_user('tarek', 'tarek')
        self.assertEquals(auth_uid, uid)

        # reset code APIs
        code = auth.generate_reset_code(uid)

        wsgi_intercept.add_wsgi_intercept('localhost', 80,
                                          bad_reset_code_response)
        self.assertFalse(auth.verify_reset_code(uid, 'beh'))
        self.assertFalse(auth.verify_reset_code(uid, 'XXXX-XXXX-XXXX-XXXX'))

        wsgi_intercept.add_wsgi_intercept('localhost', 80, fake_response)
        self.assertTrue(auth.verify_reset_code(uid, code))

        auth.clear_reset_code(uid)


def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestLDAPSQLAuth))
    return suite


if __name__ == "__main__":
    unittest.main(defaultTest="test_suite")

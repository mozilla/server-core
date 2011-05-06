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
from webob import Response
from services.auth import NoEmailError, InvalidCodeError
from services.respcodes import WEAVE_NO_EMAIL_ADRESS, WEAVE_INVALID_RESET_CODE


try:
    from services.auth.mozilla_sreg import MozillaAuth
    from services.tests.test_ldapsqlauth import MemoryStateConnector, users
    import wsgi_intercept
    from wsgi_intercept.urllib2_intercept import install_opener
    install_opener()
    DO_TESTS = True
except ImportError:
    DO_TESTS = False

from services.util import ssha

_CPT = 0


# returns a body for every request (sequential)
def fake_response():
    global _CPT
    if _CPT == 0:
        r = Response('"tarek"')
    elif _CPT == 1:
        r = Response('0')
    elif _CPT == 2:
        r = Response('0')
    else:
        r = Response('"foo"')

    _CPT += 1
    return r


def fake_response2():
    global _CPT
    if _CPT == 0:
        r = Response()
        r.status = '400 Bad Request'
        r.body = str(WEAVE_NO_EMAIL_ADRESS)
    elif _CPT == 1:
        r = Response()
        r.status = '400 Bad Request'
        r.body = str(WEAVE_INVALID_RESET_CODE)

    _CPT += 1
    return r


# returns a body that has all the responses we need
def bad_reset_code_resp():
    return Response("")


_USER = {'uidNumber': ['1234'],
         'userPassword': [ssha('tarek')],
         'uid': ['tarek'],
         'account-enabled': ['Yes'],
         'mail': ['tarek@mozilla.com'],
         'cn': ['tarek'],
         'primaryNode': ['weave:'],
         'rescueNode': ['weave:']}


class TestMozillaSRegAuth(unittest.TestCase):

    def setUp(self):
        global _CPT
        _CPT = 0

    def test_mozilla_auth(self):
        if not DO_TESTS:
            return

        wsgi_intercept.add_wsgi_intercept('localhost', 80, fake_response)
        auth = MozillaAuth('ldap://localhost',
                           'localhost', 'this_path', 'http',
                           admin_user='uid=adminuser,ou=users,dc=mozilla',
                           admin_password='admin',
                           bind_user='uid=binduser,ou=users,dc=mozilla',
                           bind_password='bind',
                           connector_cls=MemoryStateConnector)

        self.assertTrue(auth.create_user('tarek', 'tarek',
                                         'tarek@ziade.org'))

        # simulates a insertion in ldap
        users['uid=tarek,ou=users,dc=mozilla'] = _USER

        uid = auth.get_user_id('tarek')
        auth_uid = auth.authenticate_user('tarek', 'tarek')
        self.assertEquals(auth_uid, uid)

        # password change with no old password (sreg)
        self.assertTrue(auth.generate_reset_code(uid))
        self.assertTrue(auth.update_password(uid, 'newpass', key='foo'))

        # password change with old password (ldap)
        self.assertTrue(auth.update_password(uid, 'newpass', 'tarek'))
        auth_uid = auth.authenticate_user('tarek', 'newpass')
        self.assertEquals(auth_uid, uid)

        self.assertEquals(auth.get_user_node(uid), 'foo')

        auth.clear_reset_code(uid)
        wsgi_intercept.add_wsgi_intercept('localhost', 80, bad_reset_code_resp)
        self.assertFalse(auth.update_password(uid, 'newpass', key='foo'))

    def test_no_email_no_reset_code(self):
        if not DO_TESTS:
            return
        wsgi_intercept.add_wsgi_intercept('localhost', 80, fake_response2)
        auth = MozillaAuth('ldap://localhost',
                           'localhost', 'this_path', 'http',
                           admin_user='uid=adminuser,ou=users,dc=mozilla',
                           admin_password='admin',
                           bind_user='uid=binduser,ou=users,dc=mozilla',
                           bind_password='bind',
                           connector_cls=MemoryStateConnector)

        self.assertRaises(NoEmailError, auth.generate_reset_code, 'xxx')
        self.assertRaises(InvalidCodeError,  auth.update_password, 'xxx',
                          'xxx', key='xxx')


def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestMozillaSRegAuth))
    return suite


if __name__ == "__main__":
    unittest.main(defaultTest="test_suite")

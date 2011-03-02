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
from services.controllers import StandardController


_ENVIRON = {'HTTP_COOKIE': 'somecookie', 'SCRIPT_NAME': '',
           'webob.adhoc_attrs':
        {'config':
            {'cef.vendor': 'mozilla',
             'cef.device_version': '1.3',
             'smtp.port': 25, 'auth.sqluri':
             'mysql://xxxx:xxxx@localhost/sync',
             'storage.quota_size': 5120,
             'captcha.use': False,
             'storage.pool_size': 100,
             'storage.pool_recycle': 3600,
             'smtp.host': 'localhost',
             'auth.ldap_use_pool': True,
             'auth.backend': 'sql',
             'storage.standard_collections': True,
             'cef.product': 'weave',
             'storage.cache_servers': 'localhost:11211',
             'storage.sqluri': 'mysql://xxxx:xxxx@localhost/sync',
             'cef.use': True,
             'smtp.sender': 'weave@mozilla.com',
             'cef.version': 0,
             'auth.pool_size': 100,
             'profile': False,
             'storage.display_config': True,
             '__file__': 'development.ini',
             'here': 'again',
             'captcha.use_ssl': False,
             'storage.backend': 'memcached',
             'global.debug_page': '__debug__',
             'captcha.private_key': 'xxxx',
             'storage.use_quota': True,
             'translogger': False,
             'cef.file': 'syslog',
             'auth.pool_recycle': 3600,
             'debug': True,
             'storage.reset_on_return': True,
             'captcha.public_key': 'xxxx'},
        'server_time': object(),
        'response': object()},
      'REQUEST_METHOD': 'GET',
      'PATH_INFO': '/__debug__',
      'SERVER_PROTOCOL': 'HTTP/1.1',
      'QUERY_STRING': '',
      'CONTENT_LENGTH': '0',
      'HTTP_ACCEPT_CHARSET':
         'ISO-8859-1,utf-8;q=0.7,*;q=0.7',
      'HTTP_USER_AGENT':
        ('Mozilla/5.0 (X11; Linux x86_64; rv:2.0b13pre)'
         ' Gecko/20110301 Firefox/4.0b13pre'),
      'HTTP_CONNECTION': 'keep-alive',
      'SERVER_NAME': '0.0.0.0',
      'REMOTE_ADDR': '127.0.0.1',
      'wsgi.url_scheme': 'http',
      'SERVER_PORT': '5000',
      'wsgi.input': object(),
      'HTTP_HOST': 'localhost:5000',
      'wsgi.multithread': True,
      'HTTP_ACCEPT':
         ('text/html,application/xhtml+xml,application/xml'
          ';q=0.9,*/*;q=0.8'),
      'wsgi.version': (1, 0),
      'wsgi.run_once': False,
      'wsgi.errors': object(),
      'wsgi.multiprocess': False,
      'HTTP_ACCEPT_LANGUAGE': 'en-us,en;q=0.5',
      'CONTENT_TYPE': '',
      'paste.httpserver.thread_pool': object(),
      'HTTP_ACCEPT_ENCODING': 'gzip, deflate',
      'HTTP_KEEP_ALIVE': '115'}


class _Request(object):
    def __init__(self):
        self.environ = _ENVIRON


class TestStandardController(unittest.TestCase):

    def test_obfuscation(self):
        req = _Request()
        controller = StandardController(None)

        def _more_secret(*args):
            return ['stuff', 'and', 'mysql://xxxx:xxxx@localhost/sync']

        controller._debug_server = _more_secret
        debug = controller._debug(req)

        # make sure we don't have any password left
        self.assertTrue('xxxx' not in debug.body)


def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestStandardController))
    return suite

if __name__ == "__main__":
    unittest.main(defaultTest="test_suite")

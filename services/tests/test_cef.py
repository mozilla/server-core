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
import os
from tempfile import mkstemp

from services.cef import log_failure


class TestWeaveLogger(unittest.TestCase):

    def test_cef_logging(self):
        # just make sure we escape "|" when appropriate
        environ = {'REMOTE_ADDR': '127.0.0.1', 'HTTP_HOST': '127.0.0.1',
                   'PATH_INFO': '/', 'REQUEST_METHOD': 'GET',
                   'HTTP_USER_AGENT': 'MySuperBrowser'}

        config = {'cef.version': '0', 'cef.vendor': 'mozilla',
                  'cef.device_version': '3', 'cef.product': 'weave',
                  'cef': True}

        filename = config['cef.file'] = mkstemp()[1]

        try:
            # should not fail
            log_failure('xx|x', 5, environ, config)
            with open(filename) as f:
                content = f.read()
        finally:
            if os.path.exists(filename):
                os.remove(filename)

        self.assertEquals(len(content.split('|')), 9)

        # should not fail and be properly escaped
        environ['HTTP_USER_AGENT'] = "|"
        try:
            # should not fail
            log_failure('xxx', 5, environ, config)
            with open(filename) as f:
                content = f.read()
        finally:
            if os.path.exists(filename):
                os.remove(filename)

        cs = 'cs1Label=requestClientApplication cs1=\| '
        self.assertTrue(cs in content)

        # should fail because extra keys shouldn't have pipes
        self.assertRaises(ValueError, log_failure, 'xxx', 5, environ, config,
                          **{'ba|d': 1})

    def test_cef_syslog(self):
        try:
            import syslog   # NOQA
        except ImportError:
            return

        environ = {'REMOTE_ADDR': '127.0.0.1', 'HTTP_HOST': '127.0.0.1',
                   'PATH_INFO': '/', 'REQUEST_METHOD': 'GET',
                   'HTTP_USER_AGENT': 'MySuperBrowser'}

        config = {'cef.version': '0', 'cef.vendor': 'mozilla',
                  'cef.device_version': '3', 'cef.product': 'weave',
                  'cef': True, 'cef.file': 'syslog',
                  'cef.syslog.priority': 'ERR',
                  'cef.syslog.facility': 'AUTH',
                  'cef.syslog.options': 'PID,CONS'}

        log_failure('xx|x', 5, environ, config)

        # XXX how to get the facility filename via an API ?
        with open('/var/log/auth.log') as f:
            logs = '\n'.join(f.read().split('\n')[-10:])

        self.assertTrue('MySuperBrowser' in logs)

    def test_cef_nohost(self):
        try:
            import syslog   # NOQA
        except ImportError:
            return

        environ = {'REMOTE_ADDR': '127.0.0.1',
                   'PATH_INFO': '/', 'REQUEST_METHOD': 'GET',
                   'HTTP_USER_AGENT': 'MySuperBrowser2'}

        config = {'cef.version': '0', 'cef.vendor': 'mozilla',
                  'cef.device_version': '3', 'cef.product': 'weave',
                  'cef': True, 'cef.file': 'syslog',
                  'cef.syslog.priority': 'ERR',
                  'cef.syslog.facility': 'AUTH',
                  'cef.syslog.options': 'PID,CONS'}

        log_failure('xx|x', 5, environ, config)

        # XXX how to get the facility filename via an API ?
        with open('/var/log/auth.log') as f:
            logs = '\n'.join(f.read().split('\n')[-10:])

        self.assertTrue('MySuperBrowser2' in logs)

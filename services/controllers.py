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
"""
Application entry point.
"""
import re
import pprint
import StringIO

from services.util import html_response, text_response


_DEBUG_TMPL = """
<html>
 <head>
  <title>Debug information</title>
 </head>
 <body>
  <h1>Request environ</h1>
  <pre>
   %(environ)s
  </pre>
  <h1>Additional information</h1>
  <pre>
  %(extra)s
  </pre>
 </body>
</html>"""


class StandardController(object):
    """Standard controller

    Provides default views for all apps.

    - a heartbeat page
    - a debug page
    """
    def __init__(self, app):
        self.app = app

    #
    # Debug page
    #
    def _debug_server(self, request):
        """Can be overriden to provide extra information on debug calls.

        See also _debug
        """
        return []

    def _debug(self, request):
        """Returns a debug page containing useful information about the
        environ.

        Application based on SyncServerApp can implement _debug_server to
        add their own tests.

        IMPORTANT: this page must not be published without any form of
        authentication since it can display sensitive information.

        It is disabled by default.
        """
        res = _DEBUG_TMPL
        sqluri = '(?P<scheme>mysql|sqlite)://(?P<login>.*?:.*)@(?P<url>.*)'
        sqluri = re.compile(sqluri)
        replacer = '\g<scheme>://****:****@\g<url>'

        # cleanup
        if 'webob.adhoc_attrs' in request.environ:
            attrs = request.environ['webob.adhoc_attrs']
            if 'config' in attrs:
                for key, value in attrs['config'].items():
                    if 'password' in key or 'key' in key:
                        attrs['config'][key] = '********'
                    elif key.endswith('sqluri'):
                        new = sqluri.sub(replacer, value)
                        if value != new:
                            attrs['config'][key] = new

        # environ
        out = StringIO.StringIO()
        pprint.pprint(request.environ, out)
        out.seek(0)
        data = {'environ': out.read()}

        # extra info
        extra = '\n'.join(self._debug_server(request))
        if extra == '':
            extra = 'None.'

        # filtering extra info
        data['extra'] = sqluri.sub(replacer, extra)
        return html_response(res % data)

    #
    # Heartbeat page
    #
    def _check_server(self, request):
        """Can be overriden to perform extra tests on heartbeat calls.

        Should raise a HTTPServerUnavailable on failure. See also _heartbeat
        """
        pass

    def _heartbeat(self, request):
        """Performs a health check on the server.

        Returns a 200 on success, a 503 on failure. Application based on
        SyncServerApp can implement _check_server to add their own tests.

        It is enabled by default at __heartbeat__ but does not perform
        any test on the infra unless _check_server is overriden.
        """
        # calls the check if any - this will raise a 503 if anything's wrong
        self._check_server(request)
        return text_response('')

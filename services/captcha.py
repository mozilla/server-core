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
#   Toby Elliott (telliott@mozilla.com)
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

from services import logger
from services.util import BackendError
try:
    from recaptcha.client import captcha
    _NO_CAPTCHA_LIB = False
except ImportError:
    _NO_CAPTCHA_LIB = True


class ServicesCaptcha(object):

    def __init__(self, config):
        if _NO_CAPTCHA_LIB:
            raise ImportError('Recaptcha lib is not installed')
        self.use = config.get('use', False)
        self.private_key = config.get('private_key')
        self.public_key = config.get('public_key')
        self.use_ssl = config.get('use_ssl', True)

        if self.use and (self.private_key is None or self.public_key is None):
            logger.error("No key defined for captcha!")
            raise BackendError()

    def check(self, request):
        # check if captcha info are provided
        if not self.use:
            return True

        challenge = request.params.get('recaptcha_challenge_field')
        response = request.params.get('recaptcha_response_field')
        if challenge is not None and response is not None:
            resp = captcha.submit(challenge, response,
                                  self.private_key,
                                  remoteip=request.remote_addr)
            return resp.is_valid
        logger.error('captcha submitted with no challenge or response')
        return False

    CAPTCHA_TMPL = """
        <div id="captcha" style="background-color: system;">
               <script>var RecaptchaOptions = {theme: "clean"};</script>
               %s
        </div>
        """

    def form(self, template=CAPTCHA_TMPL):
        """returns the captcha form"""
        if not self.use:
            return ""

        return template % captcha.displayhtml(self.public_key,
                                              use_ssl=self.use_ssl)

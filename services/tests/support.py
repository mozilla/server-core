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
from ConfigParser import RawConfigParser
import os
from logging.config import fileConfig
import smtplib
from email import message_from_string

from services.auth import ServicesAuth
from services.util import convert_config
import services


_SYNCDIR = os.path.dirname(services.__file__)
_TOPDIR = os.path.split(_SYNCDIR)[0]


class TestEnv(object):
    """Class to try to establish the base environment for the tests"""
    def __init__(self, base):
        syncdir = os.path.dirname(base)
        self.topdir = os.path.split(syncdir)[0]

        if 'WEAVE_TESTFILE' in os.environ:
            test_filename = 'tests_%s.ini' % os.environ['WEAVE_TESTFILE']
        else:
            test_filename = 'tests.ini'

        while True:

            ini_file = os.path.join(self.topdir, test_filename)
            if os.path.exists(ini_file):
                break

            if ini_file == ("/%s" % test_filename) \
                or ini_file == test_filename:
                raise IOError("cannot locate %s" % test_filename)

            self.topdir = os.path.split(self.topdir)[0]

        cfg = RawConfigParser()
        cfg.read(ini_file)

        # loading loggers
        if cfg.has_section('loggers'):
            fileConfig(ini_file)

        here = {'here': os.path.dirname(os.path.realpath(ini_file))}
        config = dict([(key, value % here) for key, value in
                      cfg.items('DEFAULT') + cfg.items('app:main')])
        self.config = convert_config(config)


def patch_captcha(valid=True):
    """patches captcha for testing to automatically return true or false"""
    from recaptcha.client import captcha

    class Result(object):
        is_valid = valid

    def submit(*args, **kw):
        return Result()

    captcha.submit = submit

    def displayhtml(key, use_ssl=False):
        return """<form>
             key is %s
          </form>""" % key

    captcha.displayhtml = displayhtml


# non-class way of doing this
def initenv(config=None):
    """Reads the config file and instanciates an auth and a storage.

    The WEAVE_TESTFILE=name environment variable can be used to point
    a particular tests_name.ini file.
    """
    topdir = os.path.split(_TOPDIR)[0]

    if 'WEAVE_TESTFILE' in os.environ:
        test_filename = 'tests_%s.ini' % os.environ['WEAVE_TESTFILE']
    else:
        test_filename = 'tests.ini'

    while True:
        ini_file = os.path.join(topdir, test_filename)
        if os.path.exists(ini_file):
            break

        topdir = os.path.split(topdir)[0]
        if topdir == '/':
            break

    if not os.path.exists(ini_file):
        raise IOError("cannot locate %s" % test_filename)

    if config is None:
        config = ini_file

    cfg = RawConfigParser()
    cfg.read(config)

    # loading loggers
    if cfg.has_section('loggers'):
        fileConfig(config)

    here = {'here': os.path.dirname(os.path.realpath(config))}
    config = dict([(key, value % here)for key, value in
                   cfg.items('DEFAULT') + cfg.items('app:main')])
    config = convert_config(config)
    auth = ServicesAuth.get_from_config(config)
    return topdir, config, auth


def get_app(wrapped):
    app = wrapped
    while True:
        if hasattr(app, 'app'):
            app = app.app
        elif hasattr(app, 'application'):
            app = app.application
        else:
            return app


def create_test_app(application):
    """Returns a TestApp instance.

    If TEST_REMOTE is set in the environ, will run against a real server.
    """
    import urlparse
    from wsgiproxy.exactproxy import proxy_exact_request
    from webtest import TestApp

    # runs over a proxy
    if os.environ.get('TEST_REMOTE'):
        parsed = urlparse.urlsplit(os.environ['TEST_REMOTE'])
        if ':' in parsed.netloc:
            loc, port = parsed.netloc.split(':')
        else:
            loc = parsed.netloc
            if parsed.scheme == 'https':
                port = '443'
            else:
                port = '80'

        extra = {'HTTP_HOST': parsed.netloc,
                 'SERVER_NAME': loc,
                 'SERVER_PORT': port,
                 'wsgi.url_scheme': parsed.scheme}

        return TestApp(proxy_exact_request, extra_environ=extra)

    # regular instance
    return TestApp(application)


class _FakeSMTP(object):

    msgs = []

    def __init__(self, *args, **kw):
        pass

    def quit(self):
        pass

    def sendmail(self, sender, rcpts, msg):
        self.msgs.append((sender, rcpts, msg))


def patch_smtp():
    smtplib.old = smtplib.SMTP
    smtplib.SMTP = _FakeSMTP


def unpatch_smtp():
    smtplib.SMTP = smtplib.old


def get_sent_email(index=-1):
    sender, rcpts, msg = _FakeSMTP.msgs[index]
    msg = message_from_string(msg)
    return sender, rcpts, msg

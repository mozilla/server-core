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

from services.auth import ServicesAuth
from services.util import convert_config
import services

_WEAVEDIR = os.path.dirname(services.__file__)
_TOPDIR = os.path.split(_WEAVEDIR)[0]

class TestEnv(object):
"""Class to try to establish the base environment for the tests"""
    def __init__(self, base):
        _WEAVEDIR = os.path.dirname(base)
        self._TOPDIR = os.path.split(_WEAVEDIR)[0]

        if 'WEAVE_TESTFILE' in os.environ:
            test_filename = 'tests_%s.ini' % os.environ['WEAVE_TESTFILE']
        else:
            test_filename = 'tests.ini'
            
        while True:

            _INI_FILE = os.path.join(self._TOPDIR, test_filename)
            if os.path.exists(_INI_FILE):
                break

            if _INI_FILE == ("/%s" % test_filename) \
                or _INI_FILE == test_filename:
                raise IOError("cannot locate %s" % test_filename)

            self._TOPDIR = os.path.split(self._TOPDIR)[0]

        cfg = RawConfigParser()
        cfg.read(_INI_FILE)

        # loading loggers
        if cfg.has_section('loggers'):
            fileConfig(_INI_FILE)

        here = {'here': os.path.dirname(os.path.realpath(_INI_FILE))}
        config = dict([(key, value % here) for key, value in
                      cfg.items('DEFAULT') + cfg.items('app:main')])
        self._CONFIG = convert_config(config)

    def topdir(self):
        return self._TOPDIR

    def config(self):
        return self._CONFIG


#non-class way of doing this
def initenv(config=_INI_FILE):
    """Reads the config file and instanciates an auth and a storage.

    The WEAVE_TESTFILE=name environment variable can be used to point
    a particular tests_name.ini file.
    """
    while True:
        if 'WEAVE_TESTFILE' in os.environ:
            _INI_FILE = os.path.join(_TOPDIR, 'tests_%s.ini' % \
                                     os.environ['WEAVE_TESTFILE'])
        else:
            _INI_FILE = os.path.join(_TOPDIR, 'tests.ini')
    
        if os.path.exists(_INI_FILE):
            break
    
        _TOPDIR = os.path.split(_TOPDIR)[0]

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
    return _TOPDIR, config, auth

def get_app(wrapped):
    app = wrapped
    while True:
        if hasattr(app, 'app'):
            app = app.app
        elif hasattr(app, 'application'):
            app = app.application
        else:
            return app

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
""" Reset code manager.

Stores the reset codes in a SQL Table, per user name.

The storage can be overriden.
"""
import datetime

from sqlalchemy.ext.declarative import declarative_base, Column
from sqlalchemy import String, DateTime
from sqlalchemy.sql import bindparam, select, insert, delete

from services.util import generate_reset_code, check_reset_code, safe_execute
from services import logger


_Base = declarative_base()


class ResetCodes(_Base):
    __tablename__ = 'reset_codes'

    username = Column(String(32), primary_key=True, nullable=False)
    reset = Column(String(32))
    expiration = Column(DateTime())

reset_codes = ResetCodes.__table__

_USER_RESET_CODE = select([reset_codes.c.expiration,
                           reset_codes.c.reset],
              reset_codes.c.username == bindparam('user_name'))


class ResetCodeManager(object):
    """ Implements the reset code methods for auth backends.
    """
    def __init__(self, engine, create_tables=False):
        self._engine = engine
        if engine is not None:
            reset_codes.metadata.bind = engine
            if create_tables:
                reset_codes.create(checkfirst=True)

    #
    # Private methods
    #
    def _get_reset_code(self, user_id):
        res = self._engine.execute(_USER_RESET_CODE, user_name=user_id)
        res = res.fetchone()

        if res is None or res.reset is None or res.expiration is None:
            return None

        if isinstance(res.expiration, basestring):
            exp = datetime.datetime.strptime(res.expiration,
                                             '%Y-%m-%d %H:%M:%S.%f')
        else:
            exp = res.expiration

        if exp < datetime.datetime.now():
            # expired
            self.clear_reset_code(user_id)
            return None

        return res.reset

    def _set_reset_code(self, user_id):
        code, expiration = generate_reset_code()
        query = delete(reset_codes).where(reset_codes.c.username == user_id)
        self._engine.execute(query)

        query = insert(reset_codes).values(reset=code,
                                           expiration=expiration,
                                           username=user_id)

        res = safe_execute(self._engine, query)

        if res.rowcount != 1:
            logger.debug('Unable to add a new reset code in the'
                         ' reset_code table')
            return None  # XXX see if appropriate

        return code

    #
    # Public methods
    #
    def generate_reset_code(self, user_id, overwrite=False):
        if not overwrite:
            stored_code = self._get_reset_code(user_id)
            if stored_code is not None:
                return stored_code

        return self._set_reset_code(user_id)

    def verify_reset_code(self, user_id, code):
        if not check_reset_code(code):
            return False

        stored_code = self._get_reset_code(user_id)
        if stored_code is None:
            return False

        return stored_code == code

    def clear_reset_code(self, user_id):
        if self._engine is None:
            raise NotImplementedError()

        query = delete(reset_codes).where(reset_codes.c.username == user_id)
        res = safe_execute(self._engine, query)
        return res.rowcount > 0

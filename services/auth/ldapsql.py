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
""" LDAP Authentication
"""
from hashlib import sha1, md5
import random

import ldap

from sqlalchemy.ext.declarative import declarative_base, Column
from sqlalchemy import Integer, String
from sqlalchemy import create_engine, SmallInteger
from sqlalchemy.sql import select, insert, update, and_

from services.util import BackendError, ssha
from services.auth import NodeAttributionError
from services.auth.ldappool import ConnectionPool
from services.auth.resetcode import ResetCodeManager
from services import logger

#
# Custom SQL tables:
#   - user_ids: autoinc for the userId field
#   - available_nodes: table that manages the nodes
#
_Base = declarative_base()


class UserIds(_Base):
    __tablename__ = 'user_ids'

    id = Column(Integer, primary_key=True, autoincrement=True)

userids = UserIds.__table__


class AvailableNodes(_Base):
    __tablename__ = 'available_nodes'
    # XXX the table has more fields we don't user yet
    node = Column(String(256), primary_key=True, default='')
    available_assignments = Column(SmallInteger)
    downed = Column(SmallInteger, default=0)
    backoff = Column(SmallInteger, default=0)
    actives = Column(Integer(11))

available_nodes = AvailableNodes.__table__

tables = [userids, available_nodes]


class LDAPAuth(ResetCodeManager):
    """LDAP authentication."""

    def __init__(self, ldapuri, sqluri, use_tls=False, bind_user='binduser',
                 bind_password='binduser', admin_user='adminuser',
                 admin_password='adminuser', users_root='ou=users,dc=mozilla',
                 users_base_dn=None, pool_size=100, pool_recycle=3600,
                 reset_on_return=True, single_box=False, ldap_timeout=-1,
                 nodes_scheme='https', check_account_state=True,
                 create_tables=True, ldap_pool_size=10, **kw):
        self.check_account_state = check_account_state
        self.ldapuri = ldapuri
        self.sqluri = sqluri
        self.bind_user = bind_user
        self.bind_password = bind_password
        self.admin_user = admin_user
        self.admin_password = admin_password
        self.use_tls = use_tls
        self.users_root = users_root
        self.users_base_dn = users_base_dn
        self.single_box = single_box
        self.nodes_scheme = nodes_scheme
        self.ldap_timeout = ldap_timeout
        # by default, the ldap connections use the bind user
        self.pool = ConnectionPool(ldapuri, bind_user, bind_password,
                                   use_tls=use_tls, timeout=ldap_timeout,
                                   size=ldap_pool_size)
        sqlkw = {'pool_size': int(pool_size),
                 'pool_recycle': int(pool_recycle),
                 'logging_name': 'weaveserver'}

        if self.sqluri is not None:
            if self.sqluri.startswith('mysql'):
                sqlkw['reset_on_return'] = reset_on_return
            engine = create_engine(sqluri, **sqlkw)
            for table in tables:
                table.metadata.bind = engine
                if create_tables:
                    table.create(checkfirst=True)
        else:
            engine = None

        ResetCodeManager.__init__(self, engine)

    def _conn(self, bind=None, passwd=None):
        return self.pool.connection(bind, passwd)

    @classmethod
    def get_name(self):
        """Returns the name of the authentication backend"""
        return 'ldap'

    def _get_dn(self, uid):
        if self.users_root != 'md5':
            return 'uid=%s,%s' % (uid, self.users_root)

        # the dn is calculate with a hash of the user name
        hash = md5(uid).hexdigest()[:5]
        dcs = ['dc=%s' % hash[pos:] for pos in range(5)]
        dcs.append(self.users_base_dn)
        return 'uid=%s,%s' % (uid, ','.join(dcs))

    def _get_username(self, user_id):
        """Returns the name for a user id"""
        dn = self.users_root
        if dn == 'md5':
            dn = self.users_base_dn
        scope = ldap.SCOPE_SUBTREE
        filter = '(uidNumber=%s)' % user_id

        with self._conn() as conn:
            try:
                user = conn.search_st(dn, scope, filterstr=filter,
                                      attrlist=['uid'],
                                      timeout=self.ldap_timeout)
            except (ldap.TIMEOUT, ldap.SERVER_DOWN, ldap.OTHER), e:
                logger.debug('Could not get the user info from ldap')
                raise BackendError(str(e))
            except ldap.NO_SUCH_OBJECT:
                return None

        if user is None or len(user) == 0:
            return None

        user = user[0][1]
        return user['uid'][0]

    def get_user_id(self, user_name):
        """Returns the id for a user name"""
        dn = self.users_root
        if dn == 'md5':
            dn = self.users_base_dn
        scope = ldap.SCOPE_SUBTREE
        filter = '(uid=%s)' % user_name

        with self._conn() as conn:
            try:
                user = conn.search_st(dn, scope, filterstr=filter,
                                      attrlist=['uidNumber'],
                                      timeout=self.ldap_timeout)
            except (ldap.TIMEOUT, ldap.ERROR, ldap.OTHER), e:
                logger.debug('Could not get the user id from ldap.')
                raise BackendError(str(e))
            except ldap.NO_SUCH_OBJECT:
                return None

        if user is None or len(user) == 0:
            return None
        user = user[0][1]
        return user['uidNumber'][0]

    def _get_next_user_id(self):
        """Returns the next user id"""
        # XXX see if we could use back-sql instead to deal with autoinc
        res = self._engine.execute(insert(userids))
        return res.inserted_primary_key[0]

    def create_user(self, user_name, password, email):
        """Creates a user. Returns True on success."""
        user_name = str(user_name)   # XXX only ASCII
        user_id = self._get_next_user_id()
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
                'account-enabled': 'Yes',
                'mail': email,
                'mail-verified': key,
                'objectClass': ['dataStore', 'inetOrgPerson']}

        user = user.items()
        dn = self._get_dn(user_name)

        with self._conn(self.admin_user, self.admin_password) as conn:
            try:
                res, __ = conn.add_s(dn, user)
            except (ldap.TIMEOUT, ldap.SERVER_DOWN, ldap.OTHER), e:
                logger.debug('Could not create the user.')
                raise BackendError(str(e))

        return res == ldap.RES_ADD

    def authenticate_user(self, user_name, passwd):
        """Authenticates a user given a user_name and password.

        Returns the user id in case of success. Returns None otherwise."""
        dn = self._get_dn(user_name)
        attrs = ['uidNumber']
        if self.check_account_state:
            attrs.append('account-enabled')

        try:
            with self._conn(dn, passwd) as conn:
                user = conn.search_st(dn, ldap.SCOPE_BASE,
                                      attrlist=attrs,
                                      timeout=self.ldap_timeout)
        except (ldap.NO_SUCH_OBJECT, ldap.INVALID_CREDENTIALS):
            return None
        except (ldap.TIMEOUT, ldap.SERVER_DOWN, ldap.OTHER), e:
            logger.debug('Could not authenticate the user.')
            raise BackendError(str(e))

        if user is None:
            return None

        user = user[0][1]
        if self.check_account_state and user['account-enabled'][0] != 'Yes':
            return None

        return user['uidNumber'][0]

    def get_user_info(self, user_id):
        """Returns user info

        Args:
            user_id: user id

        Returns:
            tuple: username, email
        """
        user_name = self._get_username(user_id)
        dn = self._get_dn(user_name)
        scope = ldap.SCOPE_BASE

        with self._conn() as conn:
            try:
                res = conn.search_st(dn, scope, attrlist=['mail'],
                                     timeout=self.ldap_timeout)
            except (ldap.TIMEOUT, ldap.SERVER_DOWN, ldap.OTHER), e:
                logger.debug('Could not get the user info in ldap.')
                raise BackendError(str(e))
            except ldap.NO_SUCH_OBJECT:
                return None, None

        if res is None or len(res) == 0:
            return None, None

        res = res[0][1]
        return user_name, res['mail'][0]

    def update_email(self, user_id, email, password=None):
        """Change the user e-mail

        Args:
            user_id: user id
            email: new email

        Returns:
            True if the change was successful, False otherwise
        """
        if password is None:
            return False   # we need a password

        user = [(ldap.MOD_REPLACE, 'mail', [email])]
        user_name = self._get_username(user_id)
        dn = self._get_dn(user_name)

        with self._conn(dn, password) as conn:
            try:
                res, __ = conn.modify_s(dn, user)
            except (ldap.TIMEOUT, ldap.SERVER_DOWN, ldap.OTHER), e:
                logger.debug('Could not update the email field in ldap.')
                raise BackendError(str(e))

        return res == ldap.RES_MODIFY

    def update_password(self, user_id, password, old_password=None):
        """Change the user password.

        Uses the admin bind or the user bind if the old password is provided.

        Args:
            user_id: user id
            password: new password
            old_password: old password of the user (optional)

        Returns:
            True if the change was successful, False otherwise
        """
        user_name = self._get_username(user_id)
        user_dn = self._get_dn(user_name)

        if old_password is None:
            # we will use admin auth
            dn = self.admin_user
            ldap_password = self.admin_password
        else:
            # user auth
            dn = user_dn
            ldap_password = old_password
            # we need a password

        password_hash = ssha(password)
        user = [(ldap.MOD_REPLACE, 'userPassword', [password_hash])]

        with self._conn(dn, ldap_password) as conn:
            try:
                res, __ = conn.modify_s(user_dn, user)
            except (ldap.TIMEOUT, ldap.SERVER_DOWN, ldap.OTHER), e:
                logger.debug('Could not update the password in ldap.')
                raise BackendError(str(e))

        return res == ldap.RES_MODIFY

    def delete_user(self, user_id, password=None):
        """Deletes a user

        Args:
            user_id: user id
            password: user password

        Returns:
            True if the deletion was successful, False otherwise
        """
        user_name = self._get_username(user_id)
        dn = self._get_dn(user_name)
        if password is None:
            return False   # we need a password

        try:
            with self._conn(dn, password) as conn:
                try:
                    res, __ = conn.delete_s(dn)
                except ldap.NO_SUCH_OBJECT:
                    return False
                except (ldap.TIMEOUT, ldap.SERVER_DOWN, ldap.OTHER), e:
                    logger.debug('Could not delete the user in ldap')
                    raise BackendError(str(e))
        except ldap.INVALID_CREDENTIALS:
            return False

        return res == ldap.RES_DELETE

    def get_user_node(self, user_id, assign=True):
        if self.single_box:
            return None

        user_name = self._get_username(user_id)
        dn = self._get_dn(user_name)

        # getting the list of primary nodes
        with self._conn() as conn:
            try:
                res = conn.search_st(dn, ldap.SCOPE_BASE,
                                     attrlist=['primaryNode'],
                                     timeout=self.ldap_timeout)
            except (ldap.TIMEOUT, ldap.SERVER_DOWN, ldap.OTHER), e:
                logger.debug('Could not get the user node in ldap')
                raise BackendError(str(e))

        res = res[0][1]

        for node in res['primaryNode']:
            node = node[len('weave:'):]
            if node == '':
                continue
            # we want to return the URL
            return '%s://%s/' % (self.nodes_scheme, node)

        if not assign:
            return None

        # the user don't have a node yet, let's pick the most bored node
        where = and_(available_nodes.c.available_assignments > 0,
                     available_nodes.c.downed == 0)
        query = select([available_nodes]).where(where)
        query = query.order_by(available_nodes.c.actives).limit(1)

        res = self._engine.execute(query)
        res = res.fetchone()
        if res is None:
            # unable to get a node
            logger.debug('Unable to get a node for user id: %s' % str(user_id))
            raise NodeAttributionError(user_id)

        node = str(res.node)
        available = res.available_assignments
        actives = res.actives

        # updating LDAP now
        user = [(ldap.MOD_REPLACE, 'primaryNode',
                ['weave:%s' % node])]

        with self._conn(self.admin_user, self.admin_password) as conn:
            try:
                ldap_res, __ = conn.modify_s(dn, user)
            except (ldap.TIMEOUT, ldap.SERVER_DOWN, ldap.OTHER), e:
                logger.debug('Could not update the server node in LDAP')
                raise BackendError(str(e))

        if ldap_res != ldap.RES_MODIFY:
            # unable to set the node in LDAP
            logger.debug('Unable to set the newly attributed node in LDAP '
                         'for %s' % str(user_id))
            raise NodeAttributionError(user_id)

        # node is set at this point
        try:
            # book-keeping in sql
            query = update(available_nodes)
            query = query.where(available_nodes.c.node == node)
            query = query.values(available_assignments=available - 1,
                                 actives=actives + 1)
            self._engine.execute(query)
        finally:
            # we want to return the node even if the sql update fails
            return '%s://%s/' % (self.nodes_scheme, node)

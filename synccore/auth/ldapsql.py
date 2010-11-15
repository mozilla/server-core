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
import datetime

import ldap
from ldap.modlist import addModlist

try:
    from memcache import Client
except ImportError:
    Client = None   # NOQA

from sqlalchemy.ext.declarative import declarative_base, Column
from sqlalchemy import Integer, String, DateTime
from sqlalchemy import create_engine, SmallInteger
from sqlalchemy.sql import bindparam, select, insert, delete, update

from synccore.util import (generate_reset_code, check_reset_code, ssha,
                           BackendTimeoutError)
from synccore.auth import NodeAttributionError
from synccore.auth.ldappool import ConnectionPool

_Base = declarative_base()


class ResetCodes(_Base):
    __tablename__ = 'reset_codes'

    username = Column(String(32), primary_key=True, nullable=False)
    reset = Column(String(32))
    expiration = Column(DateTime())

reset_codes = ResetCodes.__table__


class UserIds(_Base):
    __tablename__ = 'user_ids'

    id = Column(Integer, primary_key=True, autoincrement=True)

userids = UserIds.__table__


class AvailableNodes(_Base):
    __tablename__ = 'available_nodes'

    id = Column(Integer, primary_key=True, autoincrement=True)
    ct = Column(SmallInteger)
    actives = Column(Integer(11))
    node = Column(String(256))

available_nodes = AvailableNodes.__table__

tables = [reset_codes, userids, available_nodes]

_USER_RESET_CODE = select([reset_codes.c.expiration,
                           reset_codes.c.reset],
              reset_codes.c.username == bindparam('user_name'))


class LDAPAuth(object):
    """LDAP authentication."""

    def __init__(self, ldapuri, sqluri, use_tls=False, bind_user='binduser',
                 bind_password='binduser', admin_user='adminuser',
                 admin_password='adminuser', users_root='ou=users,dc=mozilla',
                 users_base_dn=None, pool_size=100, pool_recycle=3600,
                 reset_on_return=True, single_box=False, ldap_timeout=-1,
                 nodes_scheme='https', cache_servers=None,
                 check_account_state=True,
                 **kw):
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
                                   use_tls=use_tls, timeout=ldap_timeout)
        sqlkw = {'pool_size': int(pool_size),
                 'pool_recycle': int(pool_recycle),
                 'logging_name': 'weaveserver'}

        if self.sqluri.startswith('mysql'):
            sqlkw['reset_on_return'] = reset_on_return
        self._engine = create_engine(sqluri, **sqlkw)
        for table in tables:
            table.metadata.bind = self._engine
            table.create(checkfirst=True)
        kw = dict([('cache.%s' % key[6:], value) for key, value in kw.items()
                   if key.startswith('cache_')])

        if Client is not None:
            if isinstance(cache_servers, str):
                cache_servers = [cache_servers]
            elif cache_servers is None:
                cache_servers = ['127.0.0.1:11211']
            self.cache = Client(cache_servers)
        else:
            self.cache = None

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

    def get_user_id(self, user_name):
        """Returns the id for a user name"""
        user_name = str(user_name)   # XXX only ASCII
        # the user id in LDAP is "uidNumber", and the use name is "uid"
        dn = self._get_dn(user_name)

        with self._conn() as conn:
            try:
                res = conn.search_st(dn, ldap.SCOPE_BASE,
                                     attrlist=['uidNumber'],
                                     timeout=self.ldap_timeout)
            except ldap.NO_SUCH_OBJECT:
                return None
            except ldap.TIMEOUT:
                raise BackendTimeoutError()

        if res is None:
            return None
        return res[0][1]['uidNumber'][0]

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

        user = addModlist(user)
        dn = self._get_dn(user_name)

        with self._conn(self.admin_user, self.admin_password) as conn:
            try:
                res, __ = conn.add_s(dn, user)
            except ldap.TIMEOUT:
                raise BackendTimeoutError()

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
        except ldap.TIMEOUT:
            raise BackendTimeoutError()

        if user is None:
            return None

        user = user[0][1]
        if self.check_account_state and user['account-enabled'][0] != 'Yes':
            return None

        return user['uidNumber'][0]

    def generate_reset_code(self, user_id):
        """Generates a reset code

        Args:
            user_id: user id

        Returns:
            a reset code, or None if the generation failed
        """
        code, expiration = generate_reset_code()
        user_name, __ = self.get_user_info(user_id)

        # XXX : use onupdate when its mysql
        # otherwise an update
        query = delete(reset_codes).where(reset_codes.c.username == user_name)
        self._engine.execute(query)

        query = insert(reset_codes).values(reset=code,
                                           expiration=expiration,
                                           username=user_name)

        res = self._engine.execute(query)

        if res.rowcount != 1:
            return None  # XXX see if appropriate

        return code

    def verify_reset_code(self, user_id, code):
        """Verify a reset code

        Args:
            user_id: user id
            code: reset code

        Returns:
            True or False
        """
        if not check_reset_code(code):
            return False

        user_name, __ = self.get_user_info(user_id)
        res = self._engine.execute(_USER_RESET_CODE, user_name=user_name)
        res = res.fetchone()

        if res is None or res.reset is None or res.expiration is None:
            return False

        # XXX SQLALchemy should turn it into a datetime for us
        # but that does not occur with sqlite
        if isinstance(res.expiration, basestring):
            exp = datetime.datetime.strptime(res.expiration,
                                             '%Y-%m-%d %H:%M:%S.%f')
        else:
            exp = res.expiration

        if exp < datetime.datetime.now():
            # expired
            return False

        if res.reset != code:
            # wrong code
            return False

        return True

    def clear_reset_code(self, user_id):
        """Clears the reset code

        Args:
            user_id: user id

        Returns:
            True if the change was successful, False otherwise
        """
        user_name, __ = self.get_user_info(user_id)
        query = delete(reset_codes)
        query = query.where(reset_codes.c.username == user_name)
        res = self._engine.execute(query)
        return res.rowcount > 0

    def get_user_info(self, user_id):
        """Returns user info

        Args:
            user_id: user id

        Returns:
            tuple: username, email
        """
        def _get_user_info():
            if self.users_root != 'md5':
                dn = self.users_root
                scope = ldap.SCOPE_SUBTREE
            else:
                dn = self._get_dn(user_id)
                scope = ldap.SCOPE_BASE

            with self._conn(self.admin_user, self.admin_password) as conn:
                try:
                    res = conn.search_st(dn, scope,
                                         filterstr='(uidNumber=%s)' % user_id,
                                         attrlist=['cn', 'mail'],
                                         timeout=self.ldap_timeout)
                except ldap.TIMEOUT:
                    raise BackendTimeoutError()

            if res is None or len(res) == 0:
                return None, None

            res = res[0][1]
            return res['cn'][0], res['mail'][0]

        if self.cache is None:
            return _get_user_info()

        key = 'info:%s' % user_id
        res = self.cache.get(key)
        if res is not None:
            return res

        res = _get_user_info()
        try:
            self.cache.set(key, res)
        finally:
            return res

    def update_email(self, user_id, email):
        """Change the user e-mail

        Args:
            user_id: user id
            email: new email

        Returns:
            True if the change was successful, False otherwise
        """
        user_name, __ = self.get_user_info(user_id)
        user = [(ldap.MOD_REPLACE, 'mail', [email])]
        dn = self._get_dn(user_name)

        with self._conn(self.admin_user, self.admin_password) as conn:
            try:
                res, __ = conn.modify_s(dn, user)
            except ldap.TIMEOUT:
                raise BackendTimeoutError()

        if self.cache is not None:
            self.cache.delete('info:%s' % user_id)
        return res == ldap.RES_MODIFY

    def update_password(self, user_id, password):
        """Change the user password

        Args:
            user_id: user id
            password: new password

        Returns:
            True if the change was successful, False otherwise
        """
        password_hash = ssha(password)
        user_name, __ = self.get_user_info(user_id)
        user = [(ldap.MOD_REPLACE, 'userPassword', [password_hash])]
        dn = self._get_dn(user_name)

        with self._conn(self.admin_user, self.admin_password) as conn:
            try:
                res, __ = conn.modify_s(dn, user)
            except ldap.TIMEOUT:
                raise BackendTimeoutError()

        return res == ldap.RES_MODIFY

    def delete_user(self, user_id, password=None):
        """Deletes a user

        Args:
            user_id: user id
            password: user password

        Returns:
            True if the deletion was successful, False otherwise
        """
        user_id = str(user_id)
        user_name, __ = self.get_user_info(user_id)
        if self.cache is not None:
            self.cache.delete('info:%s' % user_id)

        dn = self._get_dn(user_name)
        if password is None:
            return False   # we need a password

        try:
            with self._conn(dn, password) as conn:
                try:
                    res, __ = conn.delete_s(dn)
                except ldap.NO_SUCH_OBJECT:
                    return False
                except ldap.TIMEOUT:
                    raise BackendTimeoutError()
        except ldap.INVALID_CREDENTIALS:
            return False

        return res == ldap.RES_DELETE

    def get_user_node(self, user_id):
        if self.single_box:
            return None

        user_id = str(user_id)
        user_name, __ = self.get_user_info(user_id)
        dn = self._get_dn(user_name)

        # getting the list of primary nodes
        with self._conn() as conn:
            try:
                res = conn.search_st(dn, ldap.SCOPE_BASE,
                                     attrlist=['primaryNode'],
                                     timeout=self.ldap_timeout)
            except ldap.TIMEOUT:
                raise BackendTimeoutError()

        res = res[0][1]

        for node in res['primaryNode']:
            node = node[len('weave:'):]
            if node == '':
                continue
            # we want to return the URL
            return '%s://%s/' % (self.nodes_scheme, node)

        # the user don't have a node yet
        # let's pick the most bored node
        query = select([available_nodes]).where(available_nodes.c.ct > 0)
        query = query.order_by(available_nodes.c.actives).limit(1)

        res = self._engine.execute(query)
        res = res.fetchone()
        if res is None:
            # unable to get a node
            raise NodeAttributionError(user_name)

        node = str(res.node)

        # updating LDAP now
        user = [(ldap.MOD_REPLACE, 'primaryNode',
                ['weave:%s' % node])]

        with self._conn(self.admin_user, self.admin_password) as conn:
            try:
                ldap_res, __ = conn.modify_s(dn, user)
            except ldap.TIMEOUT:
                raise BackendTimeoutError()

        if ldap_res != ldap.RES_MODIFY:
            # unable to set the node in LDAP
            raise NodeAttributionError(user_name)

        # node is set at this point
        try:
            # book-keeping in sql
            query = update(available_nodes)
            query = query.where(available_nodes.c.node == node)
            query = query.values(ct=res.ct - 1, actives=res.actives + 1)
            self._engine.execute(query)
        finally:
            # we want to return the node even if the sql update fails
            return '%s://%s/' % (self.nodes_scheme, node)

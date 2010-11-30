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
Various utilities
"""
import random
import string
from hashlib import sha256, sha1
import base64
import simplejson as json
import itertools
import struct
from email.mime.text import MIMEText
from email.header import Header
import smtplib
import socket
import re
from functools import wraps
import datetime
import os

from webob.exc import HTTPServiceUnavailable, HTTPBadRequest
from webob import Response

from services.config import Config, convert


random.seed()
_RE_CODE = re.compile('[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}')


def randchar(chars=string.digits + string.letters):
    """Generates a random char using urandom.

    If the system does not support it, the function fallbacks on random.choice

    See Haypo's explanation on the used formula to pick a char:
    http://bitbucket.org/haypo/hasard/src/tip/doc/common_errors.rst
    """
    try:
        pos = int(float(ord(os.urandom(1))) * 256. / 255.)
        return chars[pos % len(chars)]
    except NotImplementedError:
        return random.choice(chars)


def text_response(data, **kw):
    """Returns Response containing a plain text"""
    return Response(str(data), content_type='text/plain', **kw)


def json_response(data, **kw):
    """Returns Response containing a json string"""
    return Response(json.dumps(data), content_type='application/json', **kw)


def html_response(data, **kw):
    """Returns Response containing a plain text"""
    return Response(str(data), content_type='text/html', **kw)


def newlines_response(lines, **kw):
    """Returns a Response object containing a newlines output."""

    def _convert(line):
        line = json.dumps(line).replace('\n', '\u000a')
        return '%s\n' % line

    data = [_convert(line) for line in lines]
    return Response(''.join(data), content_type='application/newlines', **kw)


def whoisi_response(lines, **kw):
    """Returns a Response object containing a whoisi output."""

    def _convert(line):
        line = json.dumps(line)
        size = struct.pack('!I', len(line))
        return '%s%s' % (size, line)

    data = [_convert(line) for line in lines]
    return Response(''.join(data), content_type='application/whoisi', **kw)


def convert_response(request, lines, **kw):
    """Returns the response in the appropriate format, depending on the accept
    request."""
    content_type = request.accept.first_match(('application/json',
                                               'application/newlines',
                                               'application/whoisi'))

    if content_type == 'application/newlines':
        return newlines_response(lines, **kw)
    elif content_type == 'application/whoisi':
        return whoisi_response(lines, **kw)

    # default response format is json
    return json_response(lines, **kw)


def time2bigint(value):
    """Encodes a timestamp into a big int."""
    return int(round_time(value) * 100)


def bigint2time(value):
    """Decodes a big int into a timestamp."""
    if value is None:   # unexistant
        return None
    return round_time(float(value) / 100)


def round_time(value):
    """Rounds a timestamp to two digits"""
    if not isinstance(value, float):
        value = float(value)
    return round(value, 2)

_SALT_LEN = 8


def _gensalt():
    """Generates a salt"""
    return ''.join([randchar() for i in range(_SALT_LEN)])


def ssha(password, salt=None):
    """Returns a Salted-SHA password"""
    if salt is None:
        salt = _gensalt()
    ssha = base64.b64encode(sha1(password + salt).digest()
                               + salt).strip()
    return "{SSHA}%s" % ssha


def ssha256(password, salt=None):
    """Returns a Salted-SHA256 password"""
    if salt is None:
        salt = _gensalt()
    ssha = base64.b64encode(sha256(password + salt).digest()
                               + salt).strip()
    return "{SSHA-256}%s" % ssha


def validate_password(clear, hash):
    """Validates a Salted-SHA(256) password"""
    if hash.startswith('{SSHA-256}'):
        real_hash = hash.split('{SSHA-256}')[-1]
        hash_meth = ssha256
    else:
        real_hash = hash.split('{SSHA}')[-1]
        hash_meth = ssha

    salt = base64.decodestring(real_hash)[-_SALT_LEN:]
    password = hash_meth(clear, salt)
    return password == hash


def send_email(sender, rcpt, subject, body, smtp_host='localhost',
               smtp_port=25, smtp_user=None, smtp_password=None):
    """Sends a text/plain email synchronously.

    Args:
        sender: sender address - unicode + utf8
        rcpt: recipient address - unicode + utf8
        subject: subject - unicode + utf8
        body: email body - unicode + utf8
        smtp_host: smtp server -- defaults to localhost
        smtp_port: smtp port -- defaults to 25
        smtp_user: smtp user if the smtp server requires it
        smtp_password: smtp password if the smtp server requires it

    Returns:
        tuple: (True or False, Error Message)
    """
    # preparing the message
    msg = MIMEText(body.encode('utf8'), 'plain', 'utf8')
    msg['From'] = Header(sender, 'utf8')
    msg['To'] = Header(rcpt, 'utf8')
    msg['Subject'] = Header(subject, 'utf8')

    try:
        server = smtplib.SMTP(smtp_host, smtp_port, timeout=5)
    except (smtplib.SMTPConnectError, socket.error), e:
        return False, str(e)

    # auth
    if smtp_user is not None and smtp_password is not None:
        try:
            server.login(smtp_user, smtp_password)
        except (smtplib.SMTPHeloError,
                smtplib.SMTPAuthenticationError,
                smtplib.SMTPException), e:
            return False, str(e)

    # the actual sending
    try:
        server.sendmail(sender, [rcpt], msg.as_string())
    finally:
        server.quit()

    return True, None


_USER = '(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))'
_IP_DOMAIN = '([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
_NAME_DOMAIN = '(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,})'
_DOMAIN = '(%s|%s)' % (_IP_DOMAIN, _NAME_DOMAIN)
_RE_EMAIL = '^%s@%s$' % (_USER, _DOMAIN)
_RE_EMAIL = re.compile(_RE_EMAIL)


def valid_email(email):
    """Checks if the email is well-formed

    Args:
        email: e-mail to check

    Returns:
        True or False
    """
    return _RE_EMAIL.match(email) is not None


def valid_password(user_name, password):
    """Checks a password strength.

    Args:
        user_name: user name associated with the password
        password: password

    Returns:
        True or False
    """
    if len(password) < 8:
        return False
    return user_name.lower().strip() != password.lower().strip()


def convert_config(config):
    """Loads the configuration.

    If a "configuration" option is found, reads it using config.Config.
    Each section/option is then converted to "section.option" in the resulting
    mapping.
    """
    res = {}
    for key, value in config.items():
        if not isinstance(value, basestring) or not value.startswith('file:'):
            res[key] = convert(value)
            continue
        # we load the configuration and inject it in the mapping
        filename = value[len('file:'):]
        if not os.path.exists(filename):
            raise ValueError('The configuration file was not found. "%s"' % \
                            filename)

        conf = Config(filename)
        res.update(conf.get_map())

    return res


def filter_params(namespace, data, replace_dot='_', splitchar='.'):
    """Keeps only params that starts with the namespace.
    """
    params = {}
    for key, value in data.items():
        if splitchar not in key:
            continue
        skey = key.split(splitchar)
        if skey[0] != namespace:
            continue
        params[replace_dot.join(skey[1:])] = value
    return params


def batch(iterable, size=100):
    """Returns the given iterable split into batches, of size."""
    counter = itertools.count()

    def ticker(key):
        return next(counter) // size

    for key, group in itertools.groupby(iter(iterable), ticker):
        yield group


class BackendTimeoutError(Exception):
    """Raised when the backend times out."""
    pass


def raise_503(instance):
    """Will issue a 503 on any exception.

    If the error is a timeout, will add a Retry-After header

    Args:
        instance: any instance of a class

    Response:
        the instance, with its public callables decorated
    """

    def _503_func(func):
        @wraps(func)
        def __503_func(*args, **kw):
            try:
                return func(*args, **kw)
            except BackendTimeoutError, e:
                exc = HTTPServiceUnavailable(str(e))
                exc.headers['Retry-After'] = 120
                raise exc
            except Exception, e:
                raise HTTPServiceUnavailable(str(e))
        return __503_func

    for func in dir(instance):
        if func.startswith('_'):
                continue
        _func = getattr(instance, func)
        if not callable(_func):
            continue
        _func = _503_func(_func)
        setattr(instance, func, _func)

    return instance


def generate_reset_code():
    """Generates a reset code

    Returns:
        reset code, expiration date
    """
    chars = string.ascii_uppercase + string.digits

    def _4chars():
        return ''.join([randchar(chars) for i in range(4)])

    code = '-'.join([_4chars() for i in range(4)])
    expiration = datetime.datetime.now() + datetime.timedelta(hours=6)
    return code, expiration


def check_reset_code(code):
    """Verify a reset code

    Args:
        code: reset code

    Returns:
        True or False
    """
    return _RE_CODE.match(code) is not None


class HTTPJsonBadRequest(HTTPBadRequest):
    """Allow WebOb Exception to hold Json responses.

    XXX Should be fixed in WebOb
    """
    def generate_response(self, environ, start_response):
        if self.content_length is not None:
            del self.content_length

        headerlist = [(key, value) for key, value in
                      list(self.headerlist)
                      if key != 'Content-Type']
        body = json.dumps(self.detail)
        resp = Response(body,
            status=self.status,
            headerlist=headerlist,
            content_type='application/json')
        return resp(environ, start_response)


def extract_username(username):
    """Extracts the user name.

    Takes the username and if it is an email address, munges it down
    to the corresponding 32-character username
    """
    if '@' not in username:
        return username
    hashed = sha1(username.lower()).digest()
    return base64.b32encode(hashed).lower()

#!/usr/bin/python2.4
#
# Copyright 2010 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Provides GORD API with authentication methods."""



import ldap
# pylint: disable-msg=C6204
try:
  import win32security
except ImportError, import_exc:
  raise ImportError(
      import_exc.args[0],
      'required: pywin32 modules or mocked equivalents.')


import common



NO_AUTH_ALLOWED_METHODS = common.AuthConfig.NO_AUTH_METHODS
LDAP_SERVER_URI = common.AuthConfig.LDAP_SERVER_URI
LDAP_SERVER_START_TLS = common.AuthConfig.LDAP_SERVER_START_TLS
LDAP_SERVER_BIND = common.AuthConfig.LDAP_SERVER_BIND
LDAP_SERVER_TLS_REQUIRE_CERT = common.AuthConfig.LDAP_SERVER_TLS_REQUIRE_CERT
TLS_CRL_NONE = 'none'
WINDOWS_LOGIN_ERROR_CODE = 1326
WINDOWS_DOMAIN = common.AuthConfig.WINDOWS_DOMAIN


class AuthBase(object):
  """Class to provide authentication."""

  # Number of parameters needed for auth.
  REQUIRED_PARAM_COUNT = 0
  # Authenticating directly to user database with user credentials?
  # i.e. as opposed to using auth tokens of some kind.
  USER_AUTH = False

  def Auth(self, method, unused_params):
    """Authenticates a session based on requested method name.

    Args:
      method: string method that was called.
      unused_params: list of parameters that were sent to the method.

    Returns:
      Boolean. True if session is authenticated successfully.
    """
    if method in NO_AUTH_ALLOWED_METHODS:
      return True
    return False


class AuthNone(AuthBase):
  """Class that bypasses authentication completely and always allows access."""

  REQUIRED_PARAM_COUNT = 0
  USER_AUTH = False

  def Auth(self, unused_method, unused_params):
    """Always returns True.

    Args:
      unused_method: string method that was called.
      unused_params: list of parameters that were sent to the method.

    Returns:
      Boolean. True always... no matter what.
    """
    return True




class AuthLdap(AuthBase):
  """Authenticate via LDAP."""

  # Number of parameters needed for auth: username and password.
  REQUIRED_PARAM_COUNT = 2
  USER_AUTH = True

  def __init__(
      self,
      ldap_server_uri=LDAP_SERVER_URI,
      ldap_server_bind=LDAP_SERVER_BIND,
      ldap_server_start_tls=LDAP_SERVER_START_TLS,
      ldap_server_tls_require_cert=LDAP_SERVER_TLS_REQUIRE_CERT):
    super(AuthLdap, self).__init__()
    self.ldap_server_uri = ldap_server_uri
    self.ldap_server_bind = ldap_server_bind
    self.ldap_server_start_tls = ldap_server_start_tls
    self.ldap_server_tls_require_cert = ldap_server_tls_require_cert
    self.ldap_con = None

  def Auth(self, method, params):
    """Authenticates a session via LDAP.

    Args:
      method: string method that was called.
      params: list of parameters that were sent to the method.

    Returns:
      Boolean. True if session is authenticated successfully.

    Raises:
      any exceptions from VerifyTicket()
    """
    if super(AuthLdap, self).Auth(method, params):
      return True
    (ldap_user, ldap_password) = params[0:2]
    return self._VerifyLdapAuth(ldap_user, ldap_password)

  def _VerifyLdapAuth(self, username, password):
    """Perform simple LDAP auth.

    Args:
      username: string username
      password: string password

    Returns:
      Boolean. True if authenticated.

    Raises:
      common.AuthenticationError: if LDAP errors occur besides auth failures
    """
    try:
      # need to set_option first, before initialize().
      # this is potentially abusive to other ldap module users.
      if not self.ldap_server_tls_require_cert:
        old_option = ldap.get_option(ldap.OPT_X_TLS_REQUIRE_CERT)
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

      con = ldap.initialize(self.ldap_server_uri)

      if self.ldap_server_start_tls:
        con.start_tls_s()

      if not self.ldap_server_tls_require_cert:
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, old_option)

      con.bind_s(self.ldap_server_bind % username, password)
      self.ldap_con = con
      return True
    except ldap.INVALID_CREDENTIALS, e:
      self.ldap_con = None
      return False
    except ldap.LDAPError, e:
      self.ldap_con = None
      raise common.AuthenticationError(e.__class__.__name__, str(e))

  def _Search(self, base, scope, ldap_filter):
    """Search with ldap connection.

    Args:
      base: str, base like dc=foo,dc=com
      scope: value like ldap.SCOPE_BASE ldap.SCOPE_ONELEVEL ldap.SCOPE_SUBTREE
      ldap_filter: str, ldap filter
    Returns:
      [
        ( dn, dict of ldap record ),
      ]
    """
    return self.ldap_con.search_s(base, scope, ldap_filter)


class AuthWindows(AuthBase):
  """Authenticate against Windows using Win32 APIs."""

  # Number of parameters needed for auth: username and password.
  REQUIRED_PARAM_COUNT = 2
  USER_AUTH = True

  def __init__(self, domain=WINDOWS_DOMAIN):
    super(AuthWindows, self).__init__(self)
    self.domain = domain

  def Auth(self, method, params):
    """Authenticate a user.

    Args:
      method: string method that was called.
      params: list of parameters that were sent to the method.

    Returns:
      Boolean. True if session is authenticated successfully.

    Raises:
      any exceptions from _VerifyWindowsAuth()
    """
    if super(AuthWindows, self).Auth(method, params):
      return True
    (user, password) = params[0:2]
    return self._VerifyWindowsAuth(user, password, self.domain)

  def _VerifyWindowsAuth(self, username, password, domain):
    """Use Win32 APIs to authenticate.

    This uses Win32's LogonUser() which has special privilege
    requirements on some versions of Windows.  Review:
      http://msdn.microsoft.com/en-us/library/aa378184(VS.85).aspx
    Short version: WindowsXP doesn't require anything extra.

    Args:
      username: string username
      password: string password
      domain: string domain

    Returns:
      True if authenticated, False if authentication failed for bad auth

    Raises:
      common.AuthenticationError if other errors occur
    """
    try:
      token = win32security.LogonUser(
          username,
          domain,
          password,
          win32security.LOGON32_LOGON_NETWORK,
          win32security.LOGON32_PROVIDER_DEFAULT)
      return bool(token)
    except win32security.error, e:
      if e.args[0] == WINDOWS_LOGIN_ERROR_CODE:  # login failure
        return False
      else:
        raise common.AuthenticationError(str(e))

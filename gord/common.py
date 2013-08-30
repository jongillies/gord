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

"""Common libraries for GORD servers and clients."""


class Network(object):
  """SMS service network parameters.

  Attributes:
    SERVICE_HOST: String host that server will run on.
    SERVICE_PORT: Integer port that server will run on.
    AUTH_CLASS: String authentication mechanism to use, a class name.
    USE_HTTPS: Boolean whether to use https or not.
    PEM_FILENAME: String filename of server PEM file, or None to use default
      (SERVER_ROOT)/server.pem.
  """
  SERVICE_HOST = 'gordhost.some.com.domain'
  SERVICE_PORT = 8188
  AUTH_CLASS = 'AuthNone'

  USE_HTTPS = False
  PEM_FILENAME = None


class AuthConfig(object):
  """Class holding Auth Class configurations.

  Attributes:
    FAKE_LOGIN_METHODS: List of methods allowed to be called with fake login.
    MAX_AUTHENTICATION_ATTEMPTS: Integer max number of authentication attempts
      before failing.
  """

  FAKE_LOGIN_METHODS = ['HelloWorld', 'Help']
  NO_AUTH_METHODS = ['HelloWorldNoAuth']
  MAX_AUTHENTICATION_ATTEMPTS = 3

  # AuthLdap and derived classes
  LDAP_SERVER_URI = 'ldap://ldap'
  LDAP_SERVER_START_TLS = True
  LDAP_SERVER_BIND = 'uid=%s,ou=People,dc=example,dc=com'
  LDAP_SERVER_TLS_REQUIRE_CERT = False

  # AuthWindows
  WINDOWS_DOMAIN = 'domain'


class Error(Exception):
  """Base exception for common."""


class Fatal(Error):
  """Generic fatal error for sms."""


class NonFatal(Error):
  """Generic non-fatal error for sms."""


class ConnectionError(NonFatal):
  """There was an error opening a connection to the server."""


class TicketExpiredError(NonFatal):
  """The auth ticket has expired."""


class AuthenticationError(Fatal):
  """There was an error authenticating to the ticket service."""


class AccessDenied(AuthenticationError):
  """The auth ticket was valid, but access was denied."""


class InvalidMethod(Fatal):
  """An invalid (non-existent or _private) method was called on GORD."""


class InvalidOption(Fatal):
  """An invalid option was specified to a GORD method."""


class InvalidArgumentsError(Fatal):
  """Invalid arguments were passed."""


class TicketInvalidError(AuthenticationError):
  """The auth ticket is in an invalid format."""


class RPCError(Fatal):
  """If an RPC error occurred during the request, usually recoverable."""


class TransportError(Fatal):
  """An error over whatever transport is being used to connect to SMS."""


class UnknownCollection(TransportError):
  """An unknown collection ID or name was passed."""


class HostNotFound(TransportError):
  """An active host was not found using the passed hostname."""


class HostAlreadyCollectionMember(TransportError):
  """The passed host is already a member of the passed collection."""


class CollectionMembershipError(TransportError):
  """There was an error adding a host to a collection."""


class HostUnreachable(TransportError):
  """The host is not reachable; it either did not resolve or respond to ping."""

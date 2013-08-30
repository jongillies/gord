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

"""Provide a simple client startup library for GORD usage.

When building a par file, you need to include the following options in
your BUILD file for py_binary:
paropts = ['--missing_modules=google,google.appengine.api']

This will ignore the missing modules from appengine when building.
"""



import socket
import sys
import time
import xmlrpclib

from gord.gae_transport import gae_sdchttp
from gord.gae_transport import xmlrpc as gae_xmlrpc
import common


class ExceptionUnmarshaller(xmlrpclib.Unmarshaller):
  """Unmarshaller which re-raises exceptions from server side."""

  # These parameter names mirror those of xmlrpclib.Unmarshaller.
  # pylint: disable-msg=C6409
  def RaiseFault(self, faultCode=0, faultString=None):
    """Raise the appropriate exception given fault parameters.

    Args:
      faultCode: integer
      faultString: string like "*common.ExceptionName: Foo is not Bar"
    Returns:
      none
    Raises:
      common.*: any exception dedfined in the common module.
      xmlrpclib.Fault: if the exception cannot be resolved
    """
    try:
      (e_path, e_arg) = faultString.split(':', 1)
    except ValueError:  # too few :s
      raise xmlrpclib.Fault(faultCode=faultCode, faultString=faultString)

    # in python 2.4, the faultString used to look like:
    #
    #   module.module.ExceptionClass:args
    #
    # in Python 2.6.1 (r26:67517 [MSC v.1500 64 bit (AMD64)]
    # on win32python 2.6, and possibly others, we now see this instead:
    #
    #   <class 'module.module.ExceptionClass'>:args
    #
    # so, we will mangle the string to handle either appearance.
    if e_path.startswith('<class \'') and e_path.endswith('\'>'):
      e_path = e_path[8:-2]
    e_path_parts = e_path.split('.')
    e_module = '.'.join(e_path_parts[:-1])
    e_name = e_path_parts[-1:][0]

    # construct a namespace string for 'common' module relative to this
    # module's namespace.
    this_namespace = __name__.split('.')
    if len(this_namespace) > 1:
      this_base_namespace = '%s.%s.' % (
          '.'.join(this_namespace[:-1]), 'common')
    else:
      this_base_namespace = 'common.'

    if (e_path.startswith(this_base_namespace) and
        e_module in sys.modules and hasattr(sys.modules[e_module], e_name)):
      raise getattr(sys.modules[e_module], e_name)(e_arg)
    else:
      raise xmlrpclib.Fault(faultCode=faultCode, faultString=faultString)

  def close(self):
    """Close the unmarshaller.

    Returns:
      values from xmlrpclib.Unmarshaller.close
    Raises:
      exceptions from RaiseFault
    """
    if self._type == 'fault':
      raise self.RaiseFault(**self._stack[0])
    else:
      return xmlrpclib.Unmarshaller.close(self)


if gae_xmlrpc.IS_APPENGINE:
  gae_sdchttp.FixSDCHTTPS()  # Fix so HTTPS calls go through SDC.
  # pylint: disable-msg=C6409
  BaseTransport = gae_xmlrpc.UrlfetchTransport
else:
  BaseTransport = xmlrpclib.Transport  # pylint: disable-msg=C6409


class ExceptionUnmarshallerTransport(BaseTransport):
  """A transport which uses ExceptionUnmarshaller."""

  def _GetParser(self, target):
    """Return fastest available parser and unmarshalling object.

    This logic is copied from xmlrpclib.Transport.getparser() but
    allows supplying a target (the Unmarshalling object).

    Args:
      target: Unmarshaller object instance
    Returns:
      parser, target = xml parser, Unmarshaller objects
    """
    if xmlrpclib.FastParser:
      parser = xmlrpclib.FastParser(target)
    elif xmlrpclib.SgmlopParser:
      parser = xmlrpclib.SgmlopParser(target)
    elif xmlrpclib.ExpatParser:
      parser = xmlrpclib.ExpatParser(target)
    else:
      parser = xmlrpclib.SlowParser(target)
    return parser, target

  # This method name overrides xmlrpclib.Transport.close.
  # pylint: disable-msg=C6409
  def getparser(self):
    target = ExceptionUnmarshaller()
    return self._GetParser(target)


class GORDClient(object):
  """Convenience client for GORD.

  GORD is accessible via XML-RPC and a special caller is not required.
  However this class self-documents and standardizes getting a ticket
  and calling GORD.

  To use it simply:

  # Either request a ticket with Username,Password
  i = GORDClient('Username', 'Password')
  i.GetTicket()

  # Or stuff one in you already have
  i = GORDClient()
  i.SetTicket('ticket string')

  # Then, call any method on GORD directly
  i.GetComputersByUsername('Foo')  # invoke GORD methods directly against
                                   # this class

  Attributes:
    proxy_uri: String URI to to use for GORD proxy.
    proxy: xmlrpclib proxy instance to GORD.
    ticket: String ticket used for authentication.
    username: String username.
    password: String password.
    fake_login: Boolean True to use fake-login service.
    max_authentication_attempts: Integer maximum number of attempts before
      failing authentication.
    authentication_wait: Integer number of seconds to wait between
      authentication attempts.
  """

  def __init__(self, username=None, password=None,
               fake_login=False, no_auth=False):
    """Create instance of GORDClient.

    If username/password/fake_login parameters are supplied they will later
    be repeatedly used by GetTicket() to acquire/freshen a ticket.

    Args:
      username: String username.
      password: String password.
      fake_login: Boolean True to use fake-login service.
      no_auth: Boolean True to use no-auth (no ticket supplied as first arg)
    """
    self.proxy_uri = 'http://%s:%d/' % (
        common.Network.SERVICE_HOST, common.Network.SERVICE_PORT)
    self.ticket = None
    self.username = username
    self.password = password
    self.fake_login = fake_login
    self.no_auth = no_auth
    self.max_authentication_attempts = (
        common.AuthConfig.MAX_AUTHENTICATION_ATTEMPTS)
    self.authentication_wait = 1
    self.GetProxy()

  def GetProxy(self):
    self.proxy = xmlrpclib.ServerProxy(
        self.proxy_uri, transport=ExceptionUnmarshallerTransport(),
        allow_none=True)

  def GetTicket(self):
    """Get a ticket from a ticket service.


    Given the username, password, fake_login settings, ask the ticket
    service for a ticket for our use.  If fake_login is set, a fake
    ticket is obtained.

    Raises:
      common.AuthenticationError: If authentication failed.
    """
    if self.no_auth:
      return
    if self.username is None:
      raise common.AuthenticationError(
          'Authentication is required and username is None')
    if self.password is None:
      raise common.AuthenticationError(
          'Authentication is required and password is None')
    ticket = None

    self.SetTicket(ticket)

  def SetTicket(self, ticket):
    """Set the ticket(in text form) that will be used for GORD calls.


    Args:
      ticket: String authentication ticket text
    """
    self.ticket = ticket

  def _CallRemoteMethod(self, method_name, *args):
    """Handler to call a method on GORD with arguments, supplying a ticket.

    Args:
      method_name: String method to call on GORD (like RefreshPolicy()).
      args: List of arguments to supply to method.

    Returns:
      Results from method called in GORD.

    Raises:
      common.ConnectionError: If a connection cannot be made to GORD.
      common.RPCError: If there was a problem with the XML request.
      common.TicketInvalidError: If the ticket is in an invalid format.
      common.TicketExpiredError: If the ticket has expired.
    """
    method = getattr(self.proxy, method_name)
    try:
      if self.no_auth:
        return method(*args)
      else:
        return method(self.ticket, *args)
    except socket.error:
      raise common.ConnectionError('Socket could not be opened')
    except common.TicketExpiredError, error:
      raise error
    except xmlrpclib.Error, error:
      raise common.RPCError(error)

  def CallMethod(self, method_name, *args):
    """Handler to call a method on GORD with arguments, supplying a ticket.

    This will automatically attempt to refresh a ticket if GetTicket was not
    called, or the ticket expired.  The best way to deal with exceptions is
    to catch common.Fatal and common.NonFatal exceptions.

    Args:
      method_name: String method to call on GORD (like RefreshPolicy()).
      args: List of arguments to supply to method.

    Returns:
      Results from method called in GORD.

    Raises:
      common.AuthenticationError: If ticket authentication fails.
      common.ConnectionError: If a connection cannot be made to GORD.
      common.RPCError: If there was a problem with the XML request.
      common.TicketInvalidError: If the ticket is in an invalid format.
      common.TicketExpiredError: If the ticket has expired.
    """
    if method_name not in common.AuthConfig.NO_AUTH_METHODS:
      if self.ticket is None:
        self.GetTicket()
    try:
      return self._CallRemoteMethod(method_name, *args)
    except common.TicketExpiredError:
      self.GetTicket()
      return self._CallRemoteMethod(method_name, *args)

  def __getattr__(self, method_name):
    """Handler to make direct calling GORDClient.Method() possible.

    Args:
      method_name: String method to call on GORD (like RefreshPolicy()).
    Returns:
      A function which will invoke the method on GORD when call()d
    """
    return lambda *args: self.CallMethod(method_name, *args)

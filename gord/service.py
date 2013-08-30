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

"""Service method handler code for GORD."""


import base64
import os
import os.path
import SimpleXMLRPCServer
import socket
import SocketServer
import sys
import threading
import time
import types
import xmlrpclib
import zlib

import OpenSSL
import routes
import simplejson
import common
import log
# pylint: disable-msg=C6204
if common.Network.AUTH_CLASS is not None:
  # pylint: disable-msg=C6204
  import auth


# URL path for XMLRPC, copied from xmlrpclib default handler
XMLRPC_PATH = '/RPC2'
# Header for arbitrary authentication details
AUTH_HEADER = 'X-Service-Auth'


class Error(Exception):
  """Base Error class."""


class URLError(Error):
  """URL resource does not exist."""


class AuthRequiredError(Error):
  """Authorization is required for this resource."""


class AuthClassError(Error):
  """An error occured while instantiating the auth class."""


orig_dumps = xmlrpclib.dumps


def _WrapXmlrpclibDumps(*args, **argv):
  """Wrap xmlrpclib.dumps() to use allow_none=1.

  SimpleXMLRPCServer doesn't easily let us access its invocation of dumps().
  In favor of copying entire methods just to add allow_none arguments, wrap it.

  Args:
    args: arguments.
    argv: arguments.

  Returns:
    The original 'dumps' method with 'allow_none=True' forcefully passed.
  """
  argv['allow_none'] = True
  return orig_dumps(*args, **argv)


xmlrpclib.dumps = _WrapXmlrpclibDumps


def RestMethod(url, http_methods):
  """Decorator to define a method's REST URL parameters."""

  def WrapFunction(fn):
    fn.is_rest_method = True
    fn.rest_url = url
    fn.rest_http_methods = http_methods
    return fn
  return WrapFunction


class ServiceDispatcher(SimpleXMLRPCServer.SimpleXMLRPCDispatcher):
  """A dispatcher which scrapes out REST-decorated methods."""

  def __init__(self):
    SimpleXMLRPCServer.SimpleXMLRPCDispatcher.__init__(self)
    self.mapper = routes.Mapper()

  def _dispatch(self, method, params, **kwargs):
    """Dispatch a rpc call to the appropriate method with parameters.

    This method is copied from SimpleXMLRPCServer but adds
    kwargs so that REST methods can receive keyword arguments
    rather than just list of parameters, which is all XMLRPC supports.

    Args:
      method: string, method name
      params: tuple, list of arguments
      kwargs: optional, dict of keyword arguments
    Returns:
      output from the called method
    Raises:
      Exception: if unsupported method is called
    """
    func = None
    try:
      func = self.funcs[method]
    except KeyError:
      if self.instance is not None:
        if hasattr(self.instance, '_dispatch'):
          return self.instance._dispatch(method, params, kwargs)
        else:
          try:
            func = SimpleXMLRPCServer.resolve_dotted_attribute(
                self.instance,
                method,
                self.allow_dotted_names)
          except AttributeError:
            pass
    if func is not None:
      return func(*params, **kwargs)
    else:
      raise Exception('method "%s" is not supported' % method)

  def register_instance(self, instance, allow_dotted_names=None):
    SimpleXMLRPCServer.SimpleXMLRPCDispatcher.register_instance(
        self, instance, allow_dotted_names)
    self.instance = instance
    self._LoadRestMethods(instance)

  def _LoadRestMethods(self, instance):
    for attr_name in dir(instance):
      attr = getattr(instance, attr_name)
      if type(attr) == types.MethodType and hasattr(attr, 'is_rest_method'):
        self.mapper.connect(
            attr.rest_url,
            controller=attr_name,
            conditions=dict(method=attr.rest_http_methods))


class ServiceRequestHandler(
    SimpleXMLRPCServer.SimpleXMLRPCRequestHandler):
  """A request handler adding Event Viewer and deflate support.

  Instead of logging to stderr, log to Windows Event Viewer as an error.
  Support deflate (zlib) compression if requested by the client.
  """

  xmlrpc_path = XMLRPC_PATH

  def setup(self):
    self.connection = self.request
    if self.server.is_https:
      # TODO(user): SSL.Connection.makefile() raises NotImplemented - why?
      self.rfile = socket._fileobject(self.request, 'rb', self.rbufsize)
      self.wfile = socket._fileobject(self.request, 'wb', self.wbufsize)
    else:
      self.rfile = self.connection.makefile('rb', self.rbufsize)
      self.wfile = self.connection.makefile('wb', self.wbufsize)

  def log_error(self, format, *args):
    """Log an error.

    Args:
      format: format string.
      args: arguments to format string.
    """
    log.LogError('%s - - [%s] %s\n' % (
        self.address_string(), self.log_date_time_string(), format % args))

  def log_message(self, format, *args):
    """Log an informational message.

    Args:
      format: format string.
      args: arguments to format string.
    """
    log.LogInfo('%s - - [%s] %s\n' % (
        self.address_string(), self.log_date_time_string(), format % args))

  def _DispatchRoute(self, route, auth_details):
    """Given a route, dispatch it to the controller.

    Args:
      route: url route from routes.Mapper
      auth_details: list of auth details from http
    Returns:
      string response for caller
    """
    response = None
    kwargs = {}
    for k in route:
      # mapper sends us the controller (method name) and action (http method)
      # values in the same dictionary as the method arguments.
      # produce a sanitized kwargs which omits these values and also
      # any keyword args to methods we deem private (start with '_')
      if k not in ['controller', 'action'] and not k.startswith('_'):
        kwargs[k] = route[k]
    try:
      # in the case of a REST call, there are no non-named parameters.
      # we still use this space to send whatever auth details may have been
      # gathered from headers or HTTP auth.
      output = self.server._dispatch(
          route['controller'], auth_details, **kwargs)
    except Exception, e:  # pylint: disable-msg=W0703
      log.FullException('Dispatching to route %s' % str(route))
      output = {'_err': str(e)}
    response = simplejson.dumps(output)
    return response

  def RestDispatch(self, method, auth_details, data):
    """Handle any REST request.

    Args:
      method: str, like GET, POST, etc
      auth_details: authentication details gathered from HTTP
      data: str, data from a POST, etc
    Returns:
      string response for caller
    Raises:
      URLError: if URL is unknown
    """
    environ = {}
    environ['REQUEST_METHOD'] = method
    self.server.mapper.environ = environ
    url_route = self.server.mapper.match(self.path)
    if not url_route:
      raise URLError()
    if data is not None:
      url_route['data'] = data
    response = self._DispatchRoute(url_route, auth_details)
    return response

  def _GetPostData(self):
    """Return the data POSTed to a request.

    Returns:
      string data or None
    """
    content_length = int(self.headers.get('content-length', 0))
    data = None
    if content_length:
      data = self.rfile.read(content_length)
    return data

  def GetHttpBasicAuth(self, b64_auth=None):
    """Handle http basic auth, return auth details.

    Args:
      b64_auth: str, the base64 auth string in http auth format
    Returns:
      (username, password) tuple
    Raises:
      AuthRequiredError: if no valid details were supplied
    """
    try:
      s = base64.b64decode(b64_auth)
      (username, password) = s.split(':', 1)
    except TypeError:
      raise AuthRequiredError
    except ValueError:
      raise AuthRequiredError
    return (username, password)

  def GetHttpServiceAuth(self, b64_auth=None):
    """Handle auth header, returning details.

    Args:
      b64_auth: str, the base64 auth string from http header
    Returns:
      list of auth details
    Raises:
      AuthRequiredError: if no valid details were supplied
    """
    try:
      s = base64.b64decode(b64_auth)
      details = s.split(':')
    except TypeError:
      raise AuthRequiredError
    return details

  def DoHttpGeneric(self, method):
    """Handles the HTTP POST request.

    This code has been heavily copied from SimpleXMLRPCRequestHandler.do_POST.

    Args:
      method: str, http method, like "GET" or "POST"
    """
    deflate = False
    content_type = None
    try:
      required_auth = self.server.instance.GetRequiredAuth()

      data = None
      if method == 'POST':
        data = self._GetPostData()

      encoding = self.headers.get('Accept-Encoding', 'identity').lower()
      deflate = encoding.find('deflate') > -1

      # In previous versions of SimpleXMLRPCServer, _dispatch
      # could be overridden in this class, instead of in
      # SimpleXMLRPCDispatcher. To maintain backwards compatibility,
      # check to see if a subclass implements _dispatch and dispatch
      # using that method if present.
      # pylint: disable-msg=W0212
      if self.path == self.xmlrpc_path:
        if method == 'POST':  # only accept XML-RPC via POST
          response = self.server._marshaled_dispatch(
              data, getattr(self, '_dispatch', None))
          content_type = 'text/xml'
        else:
          raise URLError
      else:
        auth_details = []
        if required_auth:
          if required_auth['user_auth']:
            http_auth = self.headers.get('Authorization', None)
            auth_details = self.GetHttpBasicAuth(http_auth)
          elif required_auth['required_params'] > 0:
            http_auth = self.headers.get(AUTH_HEADER, None)
            auth_details = self.GetHttpServiceAuth(http_auth)
        response = self.RestDispatch(method, auth_details, data)
        content_type = 'text/plain'
    except AuthRequiredError:
      if required_auth['user_auth']:
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="service"')
      else:
        self.send_response(403)
      self.end_headers()
    except URLError:
      self.send_response(404)
      self.end_headers()
    # pylint: disable-msg=W0702
    except Exception:  # This should only happen if the module is buggy
      self.send_response(500)
      self.end_headers()
    else:
      # got a valid XML RPC response
      self.send_response(200)
      self.send_header('Content-type', content_type)
      if deflate:
        self.send_header('Content-Encoding', 'deflate')
        response = zlib.compress(response)

      self.send_header('Content-length', str(len(response)))
      self.end_headers()
      self.wfile.write(response)

      # shut down the connection
      self.wfile.flush()
      if self.server.is_https:
        self.connection.shutdown()
      else:
        self.connection.shutdown(1)

  # pylint: disable-msg=C6409
  def do_POST(self):
    self.DoHttpGeneric('POST')

  # pylint: disable-msg=C6409
  def do_GET(self):
    self.DoHttpGeneric('GET')

  # pylint: disable-msg=C6409
  def do_DELETE(self):
    self.DoHttpGeneric('DELETE')

  # pylint: disable-msg=C6409
  def do_PUT(self):
    self.DoHttpGeneric('PUT')

  # pylint: disable-msg=C6409
  def do_HEAD(self):
    self.DoHttpGeneric('HEAD')


class ServiceMethods(object):
  """This class contains the methods callable over XML-RPC.

  General XML-RPC rules apply: no named parameters, etc.

  Any methods starting with _ are not remotely callable.
  Methods starting without _ ARE remotely callable.
  """

  def __init__(self):
    if common.Network.AUTH_CLASS is not None:
      try:
        auth_class = getattr(auth, common.Network.AUTH_CLASS)
        self.auth_class = auth_class()
      except AttributeError:
        error = ('auth class does not contain AUTH_CLASS defined in common: %s'
                 % common.Network.AUTH_CLASS)
        log.LogError(error)
        raise AuthClassError(error)
    else:
      self.auth_class = None

  def GetRequiredAuth(self):
    """Return authentication info.

    Returns:
      None if no authentication is required,
      or dictionary = {
        'required_params': int, the number of parameters required by
          underlying auth module, e.g. 0,
        'user_auth': bool, whether the parameters are being directly
          authenticated against a user datastore (e.g. ldap, etc)
      }
    """
    if self.auth_class is not None:
      required_params = self.auth_class.REQUIRED_PARAM_COUNT
      user_auth = self.auth_class.USER_AUTH
      if required_params == 0 or not user_auth:
        return
      return {'required_params': required_params, 'user_auth': user_auth}

  def _LogUse(self, method, *params, **kwargs):
    """Log method invocation via standard logger.

    Args:
      method: method name string.
      params: array of parameters to method.
      kwargs: dictionary of parameters to method
    """
    output = ['Remote called:', method]
    if params:
      output.append(str(params))
    if kwargs:
      output.append(str(kwargs))
    log.LogInfo(' '.join(output))

  # pylint: disable-msg=C6409
  def _dispatch(self, method, params, kwargs):
    """Logs method invocation and exceptions to Windows Event Viewer.

    This is the entry point into this class.

    Args:
      method: method name, string.
      params: list of parameters to method.
      kwargs: keyword arguments to method

    Returns:
      return value from method.

    Raises:
      common.InvalidMethod:
        if an unknown or invalid (starts with "_") method is invoked.
      other:
        any other exception that a called method may raise.
    """

    # Prevent private and non-existent methods from being accessed via XML-RPC.
    if method.startswith('_') or not hasattr(self, method):
      raise common.InvalidMethod(method)

    # Authentication
    if self.auth_class is not None:
      self._VerifyAuth(method, params, kwargs)
      params = params[self.auth_class.REQUIRED_PARAM_COUNT:]

    self._LogUse(method, params, kwargs)

    # Since XML-RPC Server returns generic exceptions, here we catch all so
    # that we can nicely log them to the Windows Event Viewer and then
    # reraise.
    # pylint: disable-msg=W0703
    try:
      log.LogDebug('Calling method %s(%s)' % (method, params))
      t1 = time.time()
      ret = getattr(self, method)(*params, **kwargs)
      t2 = time.time()
      log.LogDebug('Execution time for method(%s) is %f' % (method, t2 - t1))
    except common.Error, e:
      log.NormalException(method, e)
      raise
    except Exception, e:
      log.FullException(method, str(e))
      raise

    try:
      wrapped_return = self._WrapOutput(ret)
      return wrapped_return
    except Exception, e:
      log.FullException('WrapOutput', str(e))
      raise

  def _VerifyAuth(self, method, params, unused_kwargs):
    """Verifies authorization of the given method.

    Args:
      method: method name, string.
      params: list of parameters to method.
      unused_kwargs: list of keywords to method.
    Raises:
      common.Error: an authentication error has occurred.
    """
    try:
      auth_params = []
      if params:
        auth_params = params[:self.auth_class.REQUIRED_PARAM_COUNT]
      self.auth_class.Auth(method, auth_params)
    except common.Error, e:
      log.NormalException(method, e, log.LogWarning)
      raise e
    except Exception, e:
      log.FullException(method, str(e))
      raise

  def _WrapOutput(self, x):
    """Wrap output before returning to caller.

    Args:
      x: any variable
    Returns:
      modified value
    """
    return x

  def _RenderOptions(self, options, valid_options=None):
    """Turn options array into keyword parameters.

    Args:
      options: sequence of options [option1, option2]
      valid_options: None (all are valid) or array of valid options
    Returns:
      dictionary of keys {option1: True, option2: True}
    Raises:
      common.InvalidOption: if invalid option (not in valid_options) is supplied
    """
    kargs = {}
    if type(options) is not list and type(options) is not tuple:
      raise common.InvalidOption('Specify an array of options')
    for o in options:
      if valid_options is not None and o not in valid_options:
        raise common.InvalidOption('%s invalid option' % o)
      kargs[o] = True
    return kargs

  def ThreadBegin(self, thread):
    """Handle the beginning of new thread created to handle a request.

    This thread just started and the request hasn't been dispatched yet.

    Args:
      thread: thread that just began (it's also the current thread)
    """

  def ThreadEnd(self, thread):
    """Handle the end of a thread used to handle a request.

    After this method returns, the thread is going to exit.

    Args:
      thread: thread just about to end (it's also the current thread)
    """


class ThreadedServer(
    SocketServer.ThreadingMixIn,  # ThreadingMixIn must be before TCPServer!
    SocketServer.TCPServer,
    ServiceDispatcher):
  """Threaded XML-RPC server with win32 customizations.

  Customization includes fixes for win32 non-blocking I/O weirdness and
  providing better exception logging into Windows Event Viewer.
  """
  daemon_threads = True
  allow_reuse_address = True

  def __init__(
      self, addr,
      requestHandler=SimpleXMLRPCServer.SimpleXMLRPCRequestHandler,
      logRequests=1):
    # pylint: disable-msg=C6409
    self.is_https = common.Network.USE_HTTPS
    self._https_wait = False
    self.logRequests = logRequests
    ServiceDispatcher.__init__(self)

    if self.is_https:
      self._https_wait = True

    SocketServer.TCPServer.__init__(self, addr, requestHandler)

    if self.is_https:
      self._InitHttpsServer()

  def _InitHttpsServer(self):
    """Setup HTTPS server on the socket."""
    if not self._https_wait:
      return
    ssl_context = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
    pem_file = self.GetPemFilename()
    ssl_context.use_privatekey_file(pem_file)
    ssl_context.use_certificate_file(pem_file)
    ssl_socket = OpenSSL.SSL.Connection(ssl_context, self.socket)
    self.socket = ssl_socket
    self._https_wait = False
    self.is_https = True
    self.server_bind()
    self.server_activate()

  def GetPemFilename(self):
    """Return the path of the server PEM file.

    Returns:
      string like '/foo/bar/server.pem'
    Raises:
      Error: if expected file cannot be found
    """
    if common.Network.PEM_FILENAME is None:
      path = os.getcwd()
      pem_file = os.path.join(path, 'server.pem')
    else:
      pem_file = common.Network.PEM_FILENAME
    if not os.path.exists(pem_file):
      raise Error('PEM file is missing: %s' % pem_file)
    return pem_file

  def server_bind(self):
    """Bind to port if https is ready."""
    if not self._https_wait:
      SocketServer.TCPServer.server_bind(self)

  def server_activate(self):
    """Start listening to port if https is ready."""
    if not self._https_wait:
      SocketServer.TCPServer.server_activate(self)

  def process_request_thread(self, request, client_address):
    """Derived from original method.

    Adds Win32 socket fix, hooks for multi-threaded methods, adjusted
    logging.

    Args:
      request: a socket object for the XML-RPC request.
      client_address: a tuple with (string client address, port).
    """
    # on win32, the event select call set this socket to non-blocking
    # mode.  set it back to blocking mode.
    if sys.platform == 'win32':
      request.setblocking(1)

    self.instance.ThreadBegin(threading.currentThread())

    # XML-RPC Server returns generic exception, so we must catch all.
    # pylint: disable-msg=W0703
    try:
      self.finish_request(request, client_address)
      self.close_request(request)
    except Exception, e:
      log.FullException('Request failed in process_request_thread', str(e))
      self.handle_error(request, client_address)
      self.close_request(request)

    self.instance.ThreadEnd(threading.currentThread())


def Server(host, port):
  """Generate a Server bound to host:port.

  Args:
    host: str, hostname
    port: int, port
  Returns:
    initialized ThreadedServer instance
  """
  return ThreadedServer(
      (host, port),
      requestHandler=ServiceRequestHandler)

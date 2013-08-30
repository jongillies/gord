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

"""Provides a generic framework to make fully-fledged Windows services."""

import os
import socket
import sys

# pylint: disable-msg=C6204
try:
  import servicemanager
  import win32serviceutil
  import win32service
  import win32event
  import win32evtlogutil
  import win32file
except ImportError, import_exc:
  raise ImportError(
      import_exc.args[0],
      'required: pywin32 modules or mocked equivalents.')

import common
import log
import service


DEBUG = False
log.DEBUG = DEBUG
INSTALL_PATH = os.getenv('WINSERVICED_INSTALL_PATH') or 'C:\\WINSERVICED\\'
WIN32_SERVICE_NAME = 'WinServiceD'
WIN32_SERVICE_DESC = (
    'A Windows service which offers a XML-RPC interface to '
    'something.')

BIND_HOST = ''    # '' = all interfaces
BIND_PORT = os.getenv('WINSERVICED_PORT') or common.Network.SERVICE_PORT
BIND_PORT = int(BIND_PORT)


class Error(Exception):
  """Domain specific errors."""


class AuthClassError(Error):
  """An error occured while instantiating the auth class."""


class WindowsService(win32serviceutil.ServiceFramework):
  """A class which produces a system service on win32 platform.

  This service handles system calls from Windows' service manager and
  starts/stops a XML-RPC server when startup is requested.  When started, it
  also selects for new connections and informs the XML-RPC server that it
  should handle the connection.
  """

  # the following _svc_ properties are used by the pywin32 modules.
  # these must be defined in any subclass of WindowsService.
  _svc_name_ = WIN32_SERVICE_NAME
  _svc_display_name_ = WIN32_SERVICE_NAME
  _svc_description_ = WIN32_SERVICE_DESC

  def __init__(self, args):
    """Prepares the instance to be startable, but does not start the service."""
    self.rpcserver = None
    self.service_methods = None
    self.service_methods_class = None
    self.LoadSettings()
    win32evtlogutil.AddSourceToRegistry(
        self._svc_display_name_, sys.executable, 'Application')
    win32serviceutil.ServiceFramework.__init__(self, args)
    self.h_wait_stop = win32event.CreateEvent(None, 0, 0, None)
    self.h_sock_event = win32event.CreateEvent(None, 0, 0, None)

  def _GetServiceMethodsClass(self):
    raise Error(
        'Subclass of WindowsService must override _GetServiceMethodsClass')

  def _GetBindAddress(self):
    return (BIND_HOST, BIND_PORT)

  def LoadSettings(self):
    (self.bind_host, self.bind_port) = self._GetBindAddress()
    # end of pywin32-specific properties.
    self.service_methods_class = self._GetServiceMethodsClass()

  def _StartXMLRPCServer(self):
    """Start the XML-RPC server."""
    self.rpcserver = None

    # win32 allows big ints to wrap 64k and produce undesired
    # port bindings.  sanity check.
    if self.bind_port < 1 or self.bind_port > 65535:
      log.LogError('bad port number %d' % self.bind_port)
      return

    try:
      rpcserver = service.Server(self.bind_host, self.bind_port)
    except socket.error, e:
      log.LogError('XML-RPC Server startup socket error: %s' % str(e))
      return

    if self.service_methods is None:
      try:
        self.service_methods = self.service_methods_class()
      except service.AuthClassError:
        return

    rpcserver.register_instance(self.service_methods)
    self.rpcserver = rpcserver

  def SvcStop(self):
    """Sends a stop signal to the main SvcDoRun method in a different thread.

    This method is called when the Windows service manager wants to stop this
    service.
    """
    self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
    win32event.SetEvent(self.h_wait_stop)

  def SvcDoRun(self):
    """Starts the XML-RPC Service.

    This method is invoked when the Windows service manager wants to start this
    service.  This method stays running for the duration of the time the
    service is running.
    """
    servicemanager.LogMsg(
        servicemanager.EVENTLOG_INFORMATION_TYPE,
        servicemanager.PYS_SERVICE_STARTING,
        (self._svc_name_, ''))

    self._StartXMLRPCServer()
    if self.rpcserver is None:
      log.LogError('Could not start XML-RPC server')
      return

    wait_for_objects = (self.h_wait_stop, self.h_sock_event)
    servicemanager.LogMsg(
        servicemanager.EVENTLOG_INFORMATION_TYPE,
        servicemanager.PYS_SERVICE_STARTED,
        (self._svc_name_, ''))

    while True:
      win32file.WSAEventSelect(
          self.rpcserver, self.h_sock_event, win32file.FD_ACCEPT)
      rc = win32event.WaitForMultipleObjects(
          wait_for_objects, 0, win32event.INFINITE)
      # win32 WSAEventSelect set the socket to non-blocking mode and won't
      # allow blocking mode until all NetworkEvent flags are cleared (0).
      win32file.WSAEventSelect(self.rpcserver, self.h_sock_event, 0)
      if rc == win32event.WAIT_OBJECT_0:
        break
      elif rc == win32event.WAIT_OBJECT_0+1:
        self.rpcserver.handle_request()

    win32file.WSAEventSelect(self.rpcserver, self.h_sock_event, 0)
    self.rpcserver.server_close()
    servicemanager.LogMsg(
        servicemanager.EVENTLOG_INFORMATION_TYPE,
        servicemanager.PYS_SERVICE_STOPPED,
        (self._svc_name_, ''))


def main(
    argv,
    install_path=INSTALL_PATH, service_class=WindowsService,
    namespace='winservice.WindowsService'):
  """Method to handle direct server invocation."""
  win32serviceutil.HandleCommandLine(
      service_class,
      '%s%s' % (install_path, namespace),
      argv=argv)


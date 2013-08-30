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

"""Provide mock pywin32 functionality on a non-windows platform, i.e. Linux.

Provide entire modules and methods.

Points event viewer like logs to stderr.
Provides a basic service framework where code can pretend to start, stop,
listen for sock or other events, etc.

Object naming scheme:
MockAllCapsFormModule = equivalent to pywin32 module all_caps_form
MockAllCapsForm = equivalent to pywin32 object AllCapsForm

Method parameters retain their Win32 naming scheme.  This is
intentional and produces gpylint errors.
"""

import re
import select
import sys
import threading
import time


DEBUG = False


class Error(Exception):
  """Base Error."""


class ServiceUnknown(Exception):
  """Service is unknown."""


def SafeLoadMockModules(force=False):
  """Load the Win32 mock modules.

  Note:  This method is careful to only replace
  the module in sys.modules if it doesn't already
  exist.  This avoids a problem where values changed
  in the module may be wiped out as multiple
  modules load and call this method.

  Args:
    force: bool, default False, True to load mocks even if
      we're on Win32
  """
  if sys.platform == 'win32' and not force:
    return

  load_list = [
      ('servicemanager', MockServiceManagerModule),
      ('win32serviceutil', MockWin32ServiceUtilModule),
      ('win32service', MockWin32ServiceModule),
      ('win32event', MockWin32EventModule),
      ('win32evtlogutil', MockWin32EvtLogUtilModule),
      ('win32file', MockWin32FileModule),
      ('pythoncom', MockPythonComModule),
      ('win32security', MockWin32SecurityModule),
  ]

  for (module_name, module_class) in load_list:
    if not module_name in sys.modules:
      sys.modules[module_name] = module_class()


def LogDebugMsg(*args):
  """Log a debug message.

  Args:
    args: any number of args which will be logged with space separation
  """
  if DEBUG:
    servicemanager.LogMsg(' '.join(*args))


class MockServiceManagerModule(object):
  """Mock Win32 ServiceManager module."""

  def __init__(self):
    self.constant_re = re.compile(r'^[A-Z_]+$')

  def Log(self, *x):
    print >>sys.stderr, time.time(), x

  def LogMsg(self, *x):
    self.Log('LogMsg', x)

  def LogErrorMsg(self, *x):
    self.Log('LogErrorMsg', x)

  def LogWarningMsg(self, *x):
    self.Log('LogWarningMsg', x)

  def LogInfoMsg(self, *x):
    self.Log('LogInfoMsg', x)

  def __getattr__(self, x):
    if self.constant_re.search(x):
      return x
    else:
      raise AttributeError(x)


msmm = MockServiceManagerModule()
servicemanager = msmm


class MockPythonComModule(object):
  """Mock Win32 PythonCom module."""
  did_init = {}

  #TODO(user): Expose did_init values in a way that testing would confirm
  #Co{,Un}Initialize is run once per thread instance.
  def CoInitialize(self):
    self.did_init[threading.currentThread().getName()] = 1

  def CoUninitialize(self):
    self.did_init[threading.currentThread().getName()] = 0


class MockWin32EventModule(object):
  """Mock Win32 Win32Event module."""
  # pylint: disable-msg=C6409
  WAIT_OBJECT_0 = 0
  INFINITE = -1

  def SetEvent(self, eventobj):
    eventobj.Set()

  def CreateEvent(self, sa, bManualReset, bInitialState, objectName):
    return MockWin32Event(sa, bManualReset, bInitialState, objectName)

  # pylint: disable-msg=W0613
  def WaitForMultipleObjects(self, handleList, bWaitAll, milliseconds):
    LogDebugMsg(
        'WFMObjects handleList=%s timeout=%s' % (handleList, milliseconds))
    t1 = time.time()
    while 1:
      LogDebugMsg('loop, timeout=')
      n = 0
      for h in handleList:
        LogDebugMsg('looking at %s' % str(h))
        if h.IsSet():
          LogDebugMsg('IsSet %d' % n)
          return self.WAIT_OBJECT_0+n
        LogDebugMsg('not set')
        n += 1

      if milliseconds != self.INFINITE:
        elapsed = (time.time() - t1) * 1000
        if elapsed > milliseconds:
          break

      time.sleep(1.0)


class MockWin32EvtLogUtilModule(object):
  """Mock Win32 Win32EvtLogUtil module."""

  def AddSourceToRegistry(self, *x):
    pass


class MockWin32ServiceUtilModule(object):
  """Mock Win32 Win32ServiceUtil module."""

  class ServiceFramework(object):
    def __init__(self, args):
      self.args = args

    def ReportServiceStatus(self, x):
      servicemanager.Log('ReportServiceStatus', x)

  services = {}
  service_name = None

  def SetServiceName(self, name):
    """Set the service name. Used during unittests, not a Win32 function."""
    self.service_name = name

  def GetService(self, service_name):
    """Get service.  Used during unittests, not a Win32 function."""
    if service_name in self.services:
      return self.services[service_name]
    else:
      raise ServiceUnknown(service_name)

  def ServiceStart(self, service_type, argv):
    if self.service_name is None:
      if 'ServiceNameUndef' in self.services:
        raise Exception('Define a unique service name')
      else:
        self.service_name = 'ServiceNameUndef'
    service = service_type(argv)
    thread = threading.Thread(target=service.SvcDoRun)
    self.services[self.service_name] = {
        'service': service,
        'thread': thread,
    }
    thread.start()
    return service

  # pylint: disable-msg=W0613
  def ServiceStop(self, service_type=None, argv=None, service_name=None):
    if service_name is None:
      service_name = self.service_name
    service = self.GetService(self.service_name)
    service['service'].SvcStop()
    service['thread'].join()
    return service['service']

  def ServiceInstall(self, service_type, argv):
    pass

  def Usage(self):
    print 'MockWin32 Service Framework'
    print
    print '(command) [start|stop|install|debug]'

  # pylint: disable-msg=W0613
  def HandleCommandLine(self, service_type, instance_name=None, argv=()):
    """Parse command line and handle requested actions.

    Args:
      service_type: class to instantiate
      instance_name: string name of instance e.g. "mod.mod.mod.Class"
      argv: list of arguments to supply, e.g. ['start']
    """
    if len(argv) < 2:
      self.Usage()
    elif argv[1] in ['start', 'debug']:
      if argv[1] == 'debug':
        self.SetServiceName('debug')
      self.ServiceStart(service_type, argv)
    elif argv[1] == 'stop':
      self.ServiceStop(service_type, argv)
    elif argv[1] == 'install':
      self.ServiceInstall(service_type, argv)
    else:
      self.Usage()


class MockWin32Event(object):
  """Mock Win32 Win32Event class."""

  def __init__(self, sa, bManualReset, bInitialState, objectName):
    # pylint: disable-msg=C6409
    self.sa = sa
    self.bManualReset = bManualReset
    self.bInitialState = bInitialState
    self.objectName = objectName
    self.event = threading.Event()
    self.socket = None
    self.networkEvents = None

  def Set(self):
    self.event.set()

  def IsSet(self):
    LogDebugMsg('IsSet? event.isSet=%s' % self.event.isSet())
    LogDebugMsg(
        'socket=%s ne=%s' % (str(self.socket), str(self.networkEvents)))
    if self.event.isSet():
      return True
    # NOTE: networkEvents mask is basically ignored, any
    # event taken to be interesting to our select loop.
    if self.socket is not None and self.networkEvents > 0:
      x = select.select((self.socket,), (), (), 0.25)
      LogDebugMsg('select returns %s' % str(x))
      if len(x[0]) > 0 and x[0][0] == self.socket:
        return True
    LogDebugMsg('returning False')
    return False


class MockWin32FileModule(object):
  """Mock Win32 Win32File module."""
  FD_READ = 1
  FD_WRITE = 2
  FD_OOB = 4
  FD_ACCEPT = 8
  FD_CONNECT = 16
  FD_CLOSE = 32
  FD_QOS = 64
  FD_GROUP_QOS = 128
  FD_ROUTING_INTERFACE_CHANGE = 256
  FD_ADDRESS_LIST_CHANGE = 512

  # pylint: disable-msg=C6409
  def WSAEventSelect(self, socket, hEvent, networkEvents):
    LogDebugMsg('WSAEventSelect')
    hEvent.socket = socket
    hEvent.networkEvents = networkEvents


class MockWin32ServiceModule(object):
  SERVICE_STOP_PENDING = 3


class MockWin32SecurityModule(object):
  """Mock Win32security module."""

  LOGON32_LOGON_NETWORK = 3
  LOGON32_PROVIDER_DEFAULT = 0

  # pylint: disable-msg=C6409
  class error(Exception):
    """Error."""

  def LogonUser(self, username, domain, password, logon_type, logon_provider):
    raise NotImplementedError

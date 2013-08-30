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

"""Provides XML-RPC API for the Microsoft SCCM WMI and MsSQL interaction.

Microsoft System Center Configuration Manager (SCCM) is the system that gathers
and stores data about Google's Windows computers.  This service was previously
known as Microsoft System Management Server (SMS).

Due to the nature of SCCM interaction (WMI) and the lack of non-Windows
compatible libraries, this module will only run properly on a Windows computer.
"""

import os
import pydoc
import sys
import types

if sys.platform != 'win32':
  import mockwin32
  mockwin32.SafeLoadMockModules()
  import mockwmi
  mockwmi.SafeLoadMockModules()

# pylint: disable-msg=C6204
try:
  import pythoncom
except ImportError, e:
  raise ImportError(
      e.args[0],
      'required: pywin32 modules or mocked equivalents.')
import common
import log
import service
import winservice
import wmiutil


DEBUG = os.getenv('GORD_DEBUG') or False
wmiutil.DEBUG = DEBUG
log.DEBUG = DEBUG
INSTALL_PATH = os.getenv('GORD_INSTALL_PATH') or 'C:\\GORD\\'
WIN32_SERVICE_NAME = 'GORD'
WIN32_SERVICE_DESC = (
    'A Windows service which offers a XML-RPC interface to '
    'SMS/SCCM.')

BIND_HOST = ''    # '' = all interfaces
BIND_PORT = os.getenv('GORD_SERVICE_PORT') or common.Network.SERVICE_PORT
BIND_PORT = int(BIND_PORT)


class Error(Exception):
  """Domain specific errors."""


class WMIUtilServiceMethods(service.ServiceMethods):
  """This class contains the methods callable over XML-RPC.

  General XML-RPC rules apply: no named parameters, etc.

  Any methods starting with _ are not remotely callable.
  Methods starting without _ ARE remotely callable.
  """

  def __init__(self):
    service.ServiceMethods.__init__(self)
    self.wmiutil = wmiutil.WMIUtil()

  def _WrapOutput(self, x):
    """Given a complex wmi_object type, return a dictionary representation.

    If x is not [wmi_object], returns x without change.

    Args:
      x: any variable, or, value = [ wmiobject ]

    Returns:
      if x is a _wmi_object, returns a dictionary formed from x.properties.
      if x is not a _wmi_object, returns x unchanged.
    """
    if x is None:
      return x

    try:
      if len(x) != 1 or x[0].__class__.__name__ != '_wmi_object':
        return x
    except TypeError:  # it's not a list -- not a wmi object inside
      return x
    except KeyError:   # it's a dictionary -- not a wmi object
      return x

    d = {}
    for k in x[0].properties:
      d[k] = getattr(x[0], k)

    return d

  def ThreadBegin(self, unused_thread):
    """Handle the beginning of new thread created to handle a request.

    This thread just started and the request hasn't been dispatched yet.

    Args:
      unused_thread: thread that just began (it's also the current thread)
    """
    pythoncom.CoInitialize()

  def ThreadEnd(self, thread):
    """Handle the end of a thread used to handle a request.

    After this method returns, the thread is going to exit.

    Args:
      thread: thread just about to end (it's also the current thread)
    """
    pythoncom.CoUninitialize()
    wmiutil.DeleteWmi(thread.getName())

  @service.RestMethod('helloworld/*x', ['GET'])
  def HelloWorld(self, x):
    """HelloWorld. For testing. Accepts one parameter which is returned.

    Args:
      x: any variable.
    Returns:
      x unchanged.
    """
    return x

  def HelloWorldNoAuth(self, x):
    """HelloWorld. For testing. Accepts one parameter which is returned.

    Args:
      x: any variable.
    Returns:
      x unchanged.
    """
    return x

  def RefreshPolicy(self, hostname):
    """Refreshes all policies on a host.

    i.e. Forces them to immediately acknowledge new install/uninstall
    advertisements.

    Args:
      hostname: string like "foohost".

    Returns:
      Boolean. True if the policy was refreshed successfully.

    Raises:
      common.Error on failures.
    """
    return self.wmiutil.RefreshPolicy(hostname)

  def AddHostToCollectionId(self, hostname, collection_id):
    """Add a host to a collection based on id.

    Args:
      hostname: string computer name like 'foohost'.
      collection_id: string collection id like 'MV999999'.

    Returns:
      Boolean. True if the host was successfully added to the collection.

    Raises:
      common.Error on failures.
    """
    return self.wmiutil.AddHostToCollection(
        hostname, collection_id=collection_id)

  def AddHostToCollectionName(self, hostname, name):
    """Add a host to a collection based on name.

    Args:
      hostname: string computer name like 'foohost'.
      name: string collection name like 'Foo Application Collection'.

    Returns:
      Boolean. True if the host was successfully added to the collection.

    Raises:
      common.Error on failures.
    """
    return self.wmiutil.AddHostToCollection(hostname, collection_name=name)

  def GetCollectionIdByName(self, name):
    """Gets a collection ID from a given name.

    Args:
      name: string collection name like 'Foo Application Collection'.

    Returns:
      String collection ID if found (i.e. 'MV99999'), otherwise None.

    Raises:
      common.Error on failures.
    """
    return self.wmiutil.GetCollectionIdByName(name)

  def GetCollectionMembership(self, hostname):
    """Gets a list of collections that a given hostname is a member of.

    Args:
      hostname: str hostname like 'foohost'.

    Returns:
      A list of dictionary collections like {'id': 'MV99999', 'name': 'Name'}.

    Raises:
      wmiutil.Error on failures
    """
    return self.wmiutil.GetCollectionMembership(hostname)

  def GetAdvertisementsByCollection(self, collection_id):
    """Gets a list of advertisements associated with a given collection.

    Args:
      collection_id: string collection ID like 'MV99999'.

    Returns:
      List of dict advertisements [{'id':'MV100000','name':'FooAdvertisement'}].

    Raises:
      common.Error on failures.
    """
    return self.wmiutil.GetAdvertisementsByCollection(collection_id)

  def GetClientAdvertisementStatus(self, advertisement_id, hostname):
    """Gets advertisement status for a given advertisement and host.

    Args:
      advertisement_id: string advertisement ID like 'MV99999'.
      hostname: string hostname like 'foohost'.

    Returns:
      A dictionary with various status information, otherwise None.

    Raises:
      common.Error on failures.
    """
    return self.wmiutil.GetClientAdvertisementStatus(
        advertisement_id, hostname)

  def GetSubCollections(self, collection_id):
    """Gets a list of subcollections of a given collection_id.

    Args:
      collection_id: string collection ID like 'MV99999'.

    Returns:
      List of dict collections [{'id':'MV100000', 'name':'FooCollection'}].

    Raises:
      common.Error on failures.
    """
    return self.wmiutil.GetSubCollections(collection_id)

  def GetHostsByUsername(self, username, options=()):
    """Gets a list of hosts for a given username.

    Args:
      username: string username like 'userx'
      options: array including options: 'with_apps', 'with_usage'

    Returns:
      List of dict hosts or an empty list if no hosts were found.
      If with_apps, each dict will have an additional 'apps' key with the value
      of GetApplicationsOnHost(<hosti>).
      If with_usage, each dict will have an additional 'usage' key with the
      value of GetUsageDataByHost(<host>).

    Raises:
      common.Error on failures.
    """
    kargs = self._RenderOptions(options, ['with_apps', 'with_usage'])
    return self.wmiutil.GetHostsByUsername(username, **kargs)

  def GetHostByHostname(self, hostname, options=()):
    """Gets a list of hosts for a given hostname.

    Args:
      hostname: string host name like 'foohost'.
      options: array including options: 'with_apps', 'with_usage'

    Returns:
      A dict host or None if no active host was found with the given hostname.
      If with_apps, an additional 'apps' key with the value of
      GetApplicationsOnHost(<host>).
      If with_usage, an additional 'usage' key with the value of
      GetUsageDataByHost(<host>).

    Raises:
      common.Error on failures.
    """
    kargs = self._RenderOptions(options, ['with_apps', 'with_usage'])
    return self.wmiutil.GetHostByHostname(hostname, **kargs)

  def GetHostByIPAddress(self, ip_address, options=()):
    """Gets a list of hosts with a given by IP Address.

    Args:
      ip_address: string IP Address like '127.0.0.1'.
      options: array including options: 'with_apps', 'with_usage'

    Returns:
      A dict host or None if no active host was found with the given hostname.
      If with_apps, an additional 'apps' key with the value
      of GetApplicationsOnHost(<host>).
      If with_usage, an additional 'usage' key with the value of
      GetUsageDataByHost(<host>).
    """
    kargs = self._RenderOptions(options, ['with_apps', 'with_usage'])
    return self.wmiutil.GetHostByIPAddress(ip_address, **kargs)

  def GetApplicationsOnHost(self, hostname):
    """Gets a list of applications on a given host.

    Args:
      hostname: str host name like 'foohost'.

    Returns:
      List of dict applications.

    Raises:
      common.Error on failures.
    """
    return self.wmiutil.GetApplicationsOnHost(hostname)

  def GetUsageDataByHost(self, hostname):
    """Gets any available data on software usage for a given host.

    Args:
      hostname: str host name like 'foohost'.

    Returns:
      A list of dicts or None if no data is available.

    Raises:
      wmiutil.Error on failures.
    """
    return self.wmiutil.GetUsageDataByHost(hostname)

  def Help(self, method=None):
    """Return help/usage information on a method.

    Args:
      method: string name like "GetUsageDataByHost"
    Returns:
      HTML documentat
    """
    if method is None:
      obj = self
      title = 'GORD Help'
      text = 'This is the GORD server.'
    else:
      if method.startswith('_') or not hasattr(self, method):
        raise common.InvalidMethod(method)
      title = method
      obj = getattr(self, method)
      text = pydoc.getdoc(obj)

    other = ['Other Help:']
    methods = dir(self)
    methods.sort()
    for d in methods:
      if d.startswith('_') or type(getattr(self, d)) is not types.MethodType:
        continue
      other.append('  %s' % d)
    footer = '\n'.join(other)
    return '%s\n\n%s\n\n%s\n\n' % (title, text, footer)


class GORDService(winservice.WindowsService):
  """A class which produces the system service for GORD."""

  _svc_name_ = WIN32_SERVICE_NAME
  _svc_display_name_ = WIN32_SERVICE_NAME
  _svc_description_ = WIN32_SERVICE_DESC

  def _GetServiceMethodsClass(self):
    return WMIUtilServiceMethods

  def _GetBindAddress(self):
    return (BIND_HOST, BIND_PORT)


def main(argv):
  """Method to handle direct GORD invocation."""
  global INSTALL_PATH

  if not INSTALL_PATH.endswith('\\'):
    INSTALL_PATH = '%s\\' % INSTALL_PATH
  winservice.main(
      argv=argv,
      install_path=INSTALL_PATH,
      service_class=GORDService,
      namespace='gord.gord.GORDService')


if __name__ == '__main__':
  main(sys.argv)  # COV_NF_LINE

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

"""Provides WMI/MsSQL interaction WMI XMLRPC SCCM API.

Microsoft System Center Configuration Manager (SCCM) is the system that
gathers and stores data about Google's Windows computers.  This service was
previously known as Microsoft System Management Server (SMS).

This module uses Windows Management Instrumentation, aka WMI, to interact
with SCCM.  Due to the lack of non-Windows compatible WMI libraries, this
module will only run properly on a Windows computer.
"""

import datetime
import re
import sys
import threading
# import wmi occurs below by calling ImportWmiModule()
import common
import misc

DEBUG = False
DEFAULT_SCCM_WMI_PROVIDER = 'SERVER_NAME_HERE'
IMPORTED_WMI = False
# Careful here, sometimes wmi module adds /root/ to the front of the
# requested namespace, sometimes it does not.  With no computer, user, pass
# arguments it adds /root/ and our namespace starts from there.
SCCM_WMI_NAMESPACE = 'SMS/site_SITE_NAME_HERE'
STATUS_ERROR = 'error'
STATUS_OK = 'ok'
# Keep track of wmi instances per thread, = { threadvar: [ wmi1, wmi2, ...] }
THREAD_WMI_INSTANCES = {}


def ImportWmiModule():
  """Imports wmi module in a hackish manner due to win32 .DLL interference.

  A file named WMI.dll exists which breaks our importing of the wmi python
  module.

  Returns:
    The wmi module.
  """
  # pylint: disable-msg=W0603
  global IMPORTED_WMI
  old_sys_path = sys.path
  tmp_sys_path = sys.path
  # Fix sys.path such, removing the system32 directory to avoid wrongfully
  # importing WML.dll.
  for x in sys.path:
    if x.lower() == r'c:\windows\system32':
      tmp_sys_path.remove(x)
  sys.path = tmp_sys_path
  # Now that the path is fixed, import wmi and reset the path.
  # pylint: disable-msg=C6204
  # pylint: disable-msg=W0404
  # pylint: disable-msg=W0621
  try:
    import wmi
    globals()['wmi'] = wmi
    IMPORTED_WMI = True
  finally:
    sys.path = old_sys_path


# pylint: disable-msg=C6204
try:
  ImportWmiModule()
except ImportError, import_exc:
  raise ImportError(
      import_exc.args[0],
      'required: wmi module or mocked equivalents.')


def DeleteWmi(thread_name):
  """Del() all active wmi handle objects for a given thread.

  Note: This method assumes that the specified thread has
  finished processing and won't be using or requesting new
  wmi handles while this method processes.  No locking
  is performed.

  Args:
    thread_name: string like "Thread-foo-bar"
  Returns:
    integer number of wmi handle objects deleted, >=0
  """
  n = 0
  if thread_name in THREAD_WMI_INSTANCES:
    # pylint: disable-msg=W0612
    for wmih in THREAD_WMI_INSTANCES[thread_name]:
      del(wmih)
      n += 1
    del(THREAD_WMI_INSTANCES[thread_name])  # important step! =)
  return n


class WMIUtil(object):
  """A class which makes high level queries against WMI servers."""

  _WQL_SUB_COLLECTIONS = """
      SELECT c.CollectionID, c.Name
        FROM SMS_CollectToSubCollect AS sc
      INNER JOIN SMS_Collection AS c ON sc.subCollectionID = c.CollectionID
      WHERE sc.parentCollectionID = '%s'
  """
  _WQL_APPLICATIONS_ON_HOST = """
      SELECT DisplayName, Publisher FROM SMS_G_System_ADD_REMOVE_PROGRAMS
      WHERE ResourceID='%s' AND
            DisplayName NOT LIKE "%%Hotfix%%KB%%" AND
            DisplayName NOT LIKE '%%Update%%KB%%'
  """

  # The columns we need to retrieve for all GetHost(windowshostname)
  # type of operation.  Keep this list as short as possible for
  # performance reasons.
  _REQUIRED_HOST_COLUMNS = [
      'ResourceID', 'NetbiosName', 'LastLogonUserName',
      'SMSUniqueIdentifier', 'OperatingSystemNameandVersion']

  # Search parameters required when looking for active, SMS-managed
  # hosts.
  _ACTIVE_HOST_SEARCH = {'Active': 1, 'Client': 1, 'Obsolete': 0}

  def __init__(self, hostname=None, user=None, password=None):
    if hostname is None:
      hostname = self.SaneHostname(DEFAULT_SCCM_WMI_PROVIDER)
    self.__hostname = hostname
    self.__user = user
    self.__password = password
    self.__wmih = {}

  def _MakeNamespaceId(self, hostname, moniker, namespace):
    """Generates a namespace ID based on given host information.

    Args:
      hostname: str hostname like 'foohost'.
      moniker: str WMI construct moniker.
      namespace: str WMI namespace.

    Returns:
      string with namespace hostname, moniker and namespace
      concatenated with dash delimiter.
    """
    hostname = self.SaneHostname(hostname)
    return '%s-%s-%s' % (hostname, moniker, namespace)

  def SaneHostname(self, hostname):
    """Sanitizes the given hostname.

    Args:
      hostname: str hostname like 'foohost'

    Returns:
      str hostname in uppercase.
    """
    return hostname.upper()

  def GetWmi(self, hostname=None, moniker=None, namespace=None, cache=False):
    """Get a WMI handle, given connection information.

    Note: Caching handles across threads is not safe per pythoncom
    module requirements.

    Args:
      hostname: str hostname like 'foohost'.
      moniker: str WMI construct moniker.
      namespace: str WMI namespace.
      cache: boolean, whether to cache the wmi handle for function returns. be
          careful when using in multi-threaded environments.

    Returns:
      A WMI handle object.
    """
    # pylint: disable-msg=W0602
    global THREAD_WMI_INSTANCES

    if not IMPORTED_WMI:
      ImportWmiModule()

    if hostname is None:
      hostname = self.__hostname
    hostname = self.SaneHostname(hostname)
    thread_name = threading.currentThread().getName()

    wmih = None
    if cache:
      i = self._MakeNamespaceId(hostname, moniker, namespace)
      if i in self.__wmih:
        wmih = self.__wmih[i]
    if wmih is None:
      # pylint: disable-msg=E0602
      wmih = wmi.WMI(moniker=moniker, namespace=namespace, computer=hostname,
                     user=self.__user, password=self.__password, debug=DEBUG,
                     find_classes=False)
    if cache:
      self.__wmih[i] = wmih
    if thread_name in THREAD_WMI_INSTANCES:
      THREAD_WMI_INSTANCES[thread_name].append(wmih)
    else:
      THREAD_WMI_INSTANCES[thread_name] = [wmih]
    return wmih

  def _PingStatus(self, hostname):
    """Call Win32_PingStatus.

    Unbelievably this just makes the wmi host perform a normal ICMP ping
    operation and return status.

    Args:
      hostname: string hostname.

    Returns:
      a ping status object, see:
        http://msdn.microsoft.com/en-us/library/aa394350(VS.85).aspx
    """
    wmih = self.GetWmi(self.__hostname, namespace='root/CIMV2')
    i = wmih.Win32_PingStatus(Address=hostname)
    return i[0]

  def Ping(self, hostname):
    """Wrapper around _PingStatus to simplify return status.

    Args:
      hostname: string hostname.

    Returns:
      True or False if hostname is currently pingable / not pingable.
    """
    i = self._PingStatus(hostname)
    return i.StatusCode == 0

  def _GetClass(self, wmih, class_name, *args):
    """Return an object attached to a class of a given name and WMI handle.

    Args:
      wmih: wmi handle from GetWmi().
      class_name: string class name.
      args: optional arguments to pass to the class when invoking.

    Returns:
      a wmi class object.
    """
    try:
      f = getattr(wmih, class_name)
    except AttributeError:
      raise
    return f(*args)

  def _GetHost(self, hostname=None, resource_id=None, host=None, wmih=None):
    """Gets a host for a given hostname if it is an active SMS/SCCM client.

    Args:
      hostname: string hostname like 'foohost'     OR
      resource_id: integer resourceID like 12345   OR
      host: SMS_R_System object (which will simply be returned).
      wmih: SCCM connected wmi.WMI object.

    Raises:
      common.InvalidArgumentsError: If there are invalid arguments.

    Returns:
      a SMS_R_System object if the hostname is active, None otherwise.
    """
    if host is not None:
      if host.__class__.__name__ is '_wmi_object':
        return host
      else:
        raise common.InvalidArgumentsError('Must supply wmi object for host')

    if wmih is None:
      wmih = self.GetWmi(namespace=SCCM_WMI_NAMESPACE)
    if hostname is not None:
      kargs = {'NetbiosName': hostname}
    elif resource_id is not None:
      kargs = {'ResourceID': resource_id}
    else:
      raise common.InvalidArgumentsError('Must specify hostname or resource_id')

    kargs.update(self._ACTIVE_HOST_SEARCH)
    hosts = wmih.SMS_R_System(self._REQUIRED_HOST_COLUMNS, **kargs)

    if hosts:
      return hosts[0]
    raise common.HostNotFound('Hostname not found: %s' % hostname)

  def _GetCollection(
      self, collection_id=None, collection_name=None, columns=(), wmih=None):
    """Get a collection object corresponding to a collection id.

    Args:
      collection_id: string like 'MV10000'             OR
      collection_name: string like 'Foo Application'.
      columns: optional columns to retrieve from the SMS_Collection class.
      wmih: SCCM connected wmi.WMI object.

    Returns:
      a SMS_Collection object if the collection_id is found, None otherwise.

    Raises:
      common.InvalidArgumentsError: required arguments were incorrectly passed.
      common.UnknownCollection: the given collection id or name is unknown.
    """
    if collection_id is not None and collection_name is not None:
      raise common.InvalidArgumentsError(
          'collection_id and collection_name cannot be used simultaneously')
    if collection_id is None and collection_name is None:
      raise common.InvalidArgumentsError(
          'either collection_id or collection_name must be passed.')

    if wmih is None:
      wmih = self.GetWmi(namespace=SCCM_WMI_NAMESPACE)

    if collection_name is not None:
      collection = wmih.SMS_Collection(columns, Name=collection_name)
    else:
      collection = wmih.SMS_Collection(columns, CollectionID=collection_id)

    if not collection:
      raise common.UnknownCollection(
          'Unknown Collection: %s' % collection_id or collection_name)

    return collection[0]

  def GetCollectionIdByName(self, name):
    """Gets a collection ID from a given name.

    Args:
      name: str collection name like 'Foo Application Collection'.

    Returns:
      str collection ID if found, like 'MV999999', otherwise None if not found.
    """
    wmih = self.GetWmi(namespace=SCCM_WMI_NAMESPACE)
    collection = wmih.SMS_Collection(Name=name)
    if collection:
      return collection[0].CollectionID
    return None

  def GetCollectionMembership(self, hostname):
    """Gets a list of collections that a given hostname is a member of.

    Args:
      hostname: str hostname like 'foohost'.

    Returns:
      A list of dictionary collections like {'id': 'MV99999', 'name': 'Name'}.
    """
    wmih = self.GetWmi(namespace=SCCM_WMI_NAMESPACE)
    host = self._GetHost(hostname, wmih=wmih)
    collections = wmih.SMS_CollectionMember_a(
        ['CollectionID'], ResourceID=host.ResourceID)
    collection_results = []
    for collection in collections:
      # WMI py 1.1-1.3.2 module breaks when fetching properties from
      # SMS_CollectionMember_a as it wrongfully believes the return is a WMI
      # path, so it tries to reconnect to the return value, which blows up.
      # Fetching the properties of this class with the incorrect case simply
      # uses basic getattr and works as expected, since Windows WMI isn't case
      # sensitive.
      collection_id = collection.collectionid
      collection_object = self._GetCollection(
          collection_id, columns=['Name'], wmih=wmih)
      collection_name = collection_object.Name
      collection_results.append({'id': collection_id, 'name': collection_name})
    return collection_results

  def GetAdvertisementsByCollection(self, collection_id):
    """Gets a list of advertisements associated with a given collection.

    Args:
      collection_id: string collection ID like 'MV99999'.

    Returns:
      List of dict advertisements [{'id':'MV100000','name':'FooAdvertisement'}].
    """
    wmih = self.GetWmi(namespace=SCCM_WMI_NAMESPACE)
    advertisements = wmih.SMS_Advertisement(CollectionID=collection_id)
    return [{'id': a.AdvertisementID, 'name': a.AdvertisementName}
            for a in advertisements]

  def GetClientAdvertisementStatus(self, advertisement_id, hostname):
    """Gets advertisement status for a given advertisement and host.

    Args:
      advertisement_id: string advertisement ID like 'MV99999'.
      hostname: string hostname like 'foohost'.

    Returns:
      A dictionary with various status information, otherwise None.
    """
    wmih = self.GetWmi(namespace=SCCM_WMI_NAMESPACE)
    host = self._GetHost(hostname, wmih=wmih)
    statuses = wmih.SMS_ClientAdvertisementStatus(
        ResourceID=host.ResourceID, AdvertisementID=advertisement_id)
    if not statuses:
      return None
    status = statuses[0]
    return dict([(misc.CapWordsToLowerWithUnder(attr), getattr(status, attr))
                 for attr in status.properties])

  def GetSubCollections(self, collection_id):
    """Gets a list of subcollections of a given collection_id.

    Args:
      collection_id: string collection ID like 'MV99999'.

    Returns:
      A list of dict collections [{'id': 'MV99999', 'name': 'FooCollection'}].
    """
    wmih = self.GetWmi(namespace=SCCM_WMI_NAMESPACE)
    collections = wmih.query(self._WQL_SUB_COLLECTIONS % collection_id)
    if collections is None:
      return []
    return [{'id': c.CollectionID, 'name': c.Name} for c in collections]

  def TriggerSchedule(self, hostname, schedule_id):
    """Trigger a schedule of a given id on a given hostname.

    Args:
      hostname: string like 'foohost'.
      schedule_id: string like 00000000-0000-0000-0000-000000000021.

    Returns:
      result of triggering schedule.
    """
    wmih = self.GetWmi(hostname, moniker='//%s/root/CCM:SMS_Client' % hostname)
    return wmih.TriggerSchedule(sScheduleID=schedule_id)

  def RefreshPolicy(self, hostname):
    """Refresh all policies on a host.

    i.e. Force them to immediately acknowledge new install/uninstall
    advertisements.

    Args:
      hostname: string like 'foohost'.

    Returns:
      Boolean: True if policy refresh was successful.

    Raises:
      common.HostUnreachable: the host did not resolve or respond to ping.
    """
    if not self.Ping(hostname):
      raise common.HostUnreachable('Host unreachable: %s' % hostname)

    schedid_prefix = '00000000-0000-0000-0000-0000000000'
    for schedid in [21, 22, 40, 42]:
      # pylint: disable-msg=E0602
      try:
        self.TriggerSchedule(hostname, '{%s%d}' % (schedid_prefix, schedid))
      except wmi.x_wmi, e:
        raise common.RPCError(
            'Error refreshing policy: (%d, %s)' % (schedid, str(e)))
    return True

  def AddHostToCollection(
      self, hostname, collection_id=None, collection_name=None):
    """Adds a given hostname to a given collection.

    Args:
      hostname: string like 'foohost'.
      collection_id: string like 'MV100539'.
      collection_name: string like 'Foo Application Collection'.

    Returns:
      Boolean. True if the host was successfully added to the collection.

    Raises:
      common.CollectionMembershipError: adding host to the collection failed.
      common.HostAlreadyCollectionMember: the given hostname is already a member
          of the given collection.
    """
    wmih = self.GetWmi(namespace=SCCM_WMI_NAMESPACE)

    collection = self._GetCollection(
        collection_id=collection_id, collection_name=collection_name, wmih=wmih)

    collection_hosts = self._GetClass(wmih, collection.MemberClassName)

    hostname_sane = self.SaneHostname(hostname)
    for host in collection_hosts:
      if hostname_sane == self.SaneHostname(host.Name):
        raise common.HostAlreadyCollectionMember(
            'Host already member of collection: (%s, %s, %s)' %
            (hostname, collection_id, collection_name))

    host = self._GetHost(hostname, wmih=wmih)

    new_rule = wmih.SMS_CollectionRuleDirect.new()
    new_rule.ResourceID = host.ResourceID
    new_rule.RuleName = '%s (%d)' % (hostname, host.ResourceID)
    new_rule.ResourceClassName = 'SMS_R_System'

    # pylint: disable-msg=E0602
    try:
      query_id, rv = collection.AddMembershipRule(collectionRule=new_rule)
      if (query_id, rv) != (0, 0):
        raise common.CollectionMembershipError(
            'AddMembershipRule returned: (%s, %s)' % (query_id, rv))
      return True
    except wmi.x_wmi, e:
      raise common.CollectionMembershipError(
          'WMI Exception occured: %s' % str(e))

  def AddHostsToCollections(
      self, hostnames, collection_ids=None, collection_names=None):
    """Adds a list of given hosts to a list of given collections.

    Args:
      hostnames: list of strings like 'foohost'.
      collection_ids: list of strings like 'MV100539'.
      collection_names: list of strings like 'Foo Application Collection'.

    Returns:
      Tuple with an overall status string and a dictionary of host/collection
      specific status strings in the following format:
        (<overall_status>, {'<hostname>': {'<collection_id>': <host_status>}}).

      overall_status will be STATUS_OK if all host/collection membership
      requests were successful, and STATUS_ERROR otherwise.
      host_status will be STATUS_OK if operation was successful, or
      contain a string error.

    Raises:
      common.InvalidArgumentsError: required arguments were incorrectly passed.
    """
    if collection_ids is not None and collection_names is not None:
      raise common.InvalidArgumentsError(
          'collection_ids and collection_names cannot be used simultaneously')
    if collection_ids is None and collection_names is None:
      raise common.InvalidArgumentsError(
          'either collection_id or collection_name must be passed.')

    if collection_names is not None:
      collections = collection_names
    else:
      collections = collection_ids

    results = {}
    overall_result = STATUS_OK
    for hostname in hostnames:
      results[hostname] = {}
      for collection in collections:
        try:
          if collection_names is not None:
            self.AddHostToCollection(hostname, collection_name=collection)
          else:
            self.AddHostToCollection(hostname, collection_id=collection)
          results[hostname][collection] = STATUS_OK
        except common.UnknownCollection, e:
          results[hostname][collection] = str(e)
          overall_result = STATUS_ERROR
        except common.HostAlreadyCollectionMember, e:
          results[hostname][collection] = str(e)
          overall_result = STATUS_ERROR
        except common.CollectionMembershipError, e:
          results[hostname][collection] = str(e)
          overall_result = STATUS_ERROR

    return overall_result, results

  def _GetHostsDetails(
      self, hosts, wmih=None, with_apps=False, with_usage=False):
    """Gets host details for a list of hosts.

    The list is returned in the same order that the SMS_R_System
    objects were supplied.

    Args:
      hosts: list of SMS_R_System objects.
      wmih: SCCM connected wmi.WMI object.
      with_apps: boolean, default False, include information about installed
        apps.
      with_usage: boolean, default False, include information about app usage.

    Returns:
      Dict of hosts, by hostname, with host information.  None if no hosts.
    """
    # Unfortunately a WQL Query with joined classes and more than one returned
    # column fails with a generic error (surprise!), so this performs subsequent
    # WMI calls for each class we need information from on each host. This is
    # obviously slower than a single query using joins, but it's currently the
    # only working solution.
    if not hosts:
      return None
    user_hosts = {}
    if wmih is None:
      wmih = self.GetWmi(namespace=SCCM_WMI_NAMESPACE)
    for host in hosts:
      # A class query filtering by any given ResourceID should always return
      # either an empty list, or a list with a single object; never more.
      bios = wmih.SMS_G_System_PC_BIOS(
          ['Manufacturer', 'SerialNumber'],
          ResourceID=host.ResourceID)
      manufacturer = ''
      serial = ''
      if bios:
        manufacturer = bios[0].Manufacturer
        serial = bios[0].SerialNumber
      model = wmih.SMS_G_System_COMPUTER_SYSTEM(
          ['model'], ResourceID=host.ResourceID)
      if model:
        model = model[0].model
      host_dict = {
          'name': host.NetbiosName,
          'manufacturer': manufacturer,
          'model': model,
          'username': host.LastLogonUserName,
          'uuid': host.SMSUniqueIdentifier,
          'osname': host.OperatingSystemNameandVersion,
          'serial': serial,
      }
      if with_apps:
        host_dict['apps'] = self.GetApplicationsOnHost(host=host, wmih=wmih)
      if with_usage:
        host_dict['usage'] = self.GetUsageDataByHost(host=host, wmih=wmih)
      user_hosts[host.NetbiosName] = host_dict
    return user_hosts

  def GetHostsByUsername(self, username, with_apps=False, with_usage=False):
    """Gets a list of hosts with a given username.

    Args:
      username: string username like 'userx'.
      with_apps: boolean, default False, include information about installed
        apps.
      with_usage: boolean, default False, include information about app usage.

    Returns:
      List of dict hosts, or an empty list if no hosts are found.
      If with_apps, each dict will have an additional 'apps' key with the value
      of GetApplicationsOnHost(<host>)
      If with_usage, each dict will have an additional 'usage' key with the
      value of GetUsageDataByHost(<host>).
    """
    wmih = self.GetWmi(namespace=SCCM_WMI_NAMESPACE)
    hosts = wmih.SMS_R_System(
        self._REQUIRED_HOST_COLUMNS,
        LastLogonUserName=username,
        **self._ACTIVE_HOST_SEARCH)
    hosts_details = self._GetHostsDetails(
        hosts=hosts, wmih=wmih, with_apps=with_apps, with_usage=with_usage)
    if hosts_details is None:
      return []
    return [details for unused_hostname, details in hosts_details.iteritems()]

  def GetHostByHostname(self, hostname, with_apps=False, with_usage=False):
    """Gets a list of hosts with a given hostname.

    Args:
      hostname: string host name like 'foohost'.
      with_apps: boolean, default False, include information about installed
        apps.
      with_usage: boolean, default False, include information about app usage.

    Returns:
      A dict host or None if no active host was found with the given hostname.
      If with_apps, an additional 'apps' key with the value
      of GetApplicationsOnHost(<host>).
      If with_usage, an additional 'usage' key with the value of
      GetUsageDataByHost(<host>).
    """
    wmih = self.GetWmi(namespace=SCCM_WMI_NAMESPACE)
    hosts = wmih.SMS_R_System(
        self._REQUIRED_HOST_COLUMNS, NetbiosName=hostname,
        **self._ACTIVE_HOST_SEARCH)
    host_details = self._GetHostsDetails(
        hosts, wmih=wmih, with_apps=with_apps, with_usage=with_usage)
    return host_details

  def GetHostByIPAddress(self, ip_address, with_apps=False, with_usage=False):
    """Gets a list of hosts with a given by IP Address.

    Args:
      ip_address: string IP Address like '127.0.0.1'.
      with_apps: boolean, default False, include information about installed
        apps.
      with_usage: boolean, default False, include information about app usage.

    Returns:
      A dict host or None if no active host was found with the given hostname.
      If with_apps, an additional 'apps' key with the value
      of GetApplicationsOnHost(<host>).
      If with_usage, an additional 'usage' key with the value of
      GetUsageDataByHost(<host>).
    """
    wmih = self.GetWmi(namespace=SCCM_WMI_NAMESPACE)
    hosts = wmih.SMS_R_System(
        self._REQUIRED_HOST_COLUMNS, IPAddresses=ip_address,
        **self._ACTIVE_HOST_SEARCH)
    host_details = self._GetHostsDetails(
        hosts, wmih=wmih, with_apps=with_apps, with_usage=with_usage)
    return host_details

  def GetApplicationsOnHost(self, hostname=None, host=None, wmih=None):
    """Gets a list of applications on a given host.

    Args:
      hostname: str host name like 'foohost'      OR
      host: host, wmi object from SMS_R_System()
      wmih: optional, supply a SCCM connected wmi.WMI object.

    Returns:
      List of dict applications.

    Raises:
      common.InvalidArgumentsError: if the arguments were invalid.
    """
    if wmih is None:
      wmih = self.GetWmi(namespace=SCCM_WMI_NAMESPACE)
    host = self._GetHost(hostname=hostname, host=host, wmih=wmih)

    host_apps = []
    junkapps = re.compile(r'(Hotfix|Update).*KB')
    applications = wmih.SMS_G_System_ADD_REMOVE_PROGRAMS(
        ['Publisher', 'DisplayName'], ResourceID=host.ResourceID)

    for a in applications:
      if a.Publisher is None or a.DisplayName is None:
        continue
      publisher = a.Publisher.encode('utf-8', 'ignore')
      display_name = a.DisplayName.encode('utf-8', 'ignore')
      if junkapps.search(display_name):
        continue
      host_apps.append({'publisher': publisher, 'name': display_name})

    return host_apps

  def GetUsageDataByHost(self, hostname=None, host=None, wmih=None):
    """Gets any available data on software usage for a given host.

    Args:
      hostname: str host name like 'foohost'.
      host: host, wmi object from SMS_R_System()
      wmih: optional, supply a SCCM connected wmi.WMI object.

    Returns:
      A list of dicts or None if no data is available.

    Raises:
      common.InvalidArgumentsError: if there are invalid arguments.
    """
    if wmih is None:
      wmih = self.GetWmi(namespace=SCCM_WMI_NAMESPACE)
    host = self._GetHost(hostname=hostname, host=host, wmih=wmih)

    usage_data = wmih.SMS_G_System_SoftwareUsageData(
        ['ProductName', 'FileName', 'StartTimeGMT', 'EndTimeGMT'],
        ResourceID=host.ResourceID, StillRunning=False)

    if not usage_data:
      return None

    final_data = {}
    for datum in usage_data:
      key = '%s:%s:%d' % (
          datum.ProductName, datum.FileName.lower(), host.ResourceID)
      final_data.setdefault(key, {
          'computer_name': host.Name,
          'product_name': datum.ProductName,
          'file_name': datum.FileName.lower(),
          'usage_ratio': 0,
          'avg_runtime_secs': [],
          'start_date_time': datetime.datetime.now()})
      start_time = misc.WMIDateToPythonDateTime(datum.StartTimeGMT)
      end_time = misc.WMIDateToPythonDateTime(datum.EndTimeGMT)
      final_data[key]['usage_ratio'] += 1
      final_data[key]['start_date_time'] = min(
          final_data[key]['start_date_time'], start_time)
      final_data[key]['avg_runtime_secs'].append(
          misc.TimeDeltaToSeconds(end_time - start_time))
    for key in final_data:
      denominator = (
          datetime.datetime.now() - final_data[key]['start_date_time']).days
      if denominator < 1:
        final_data[key]['usage_ratio'] = 0
      else:
        final_data[key]['usage_ratio'] = (
            float(final_data[key]['usage_ratio']) / float(denominator))
      final_data[key]['avg_runtime_secs'] = (
          float(sum(final_data[key]['avg_runtime_secs']))
          / float(len(final_data[key]['avg_runtime_secs'])))
      # XML-RPC can't serialize datetime.datetimes and start_date_time
      # is not useful anyway
      del final_data[key]['start_date_time']

    return final_data.values()

# Module Docstring

Provides WMI/MsSQL interaction WMI XMLRPC SCCM API.

Microsoft System Center Configuration Manager (SCCM) is the system that gathers and stores data about Google's Windows computers. This service was previously known as Microsoft System Management Server (SMS).

This module uses Windows Management Instrumentation, aka WMI, to interact with SCCM. Due to the lack of non-Windows compatible WMI libraries, this module will only run properly on a Windows computer.

# WMIUtil Class Methods

## AddHostToCollection(self, hostname, collection_id=None, collection_name=None)

Adds a given hostname to a given collection.

    Args:
      hostname: string like 'foohost'.
      collection_id: string like 'MV100539'.
      collection_name: string like 'Foo Application Version X'.

    Returns:
      Boolean. True if the host was successfully added to the collection.

    Raises:
      common.CollectionMembershipError: adding host to the collection failed.
      common.HostAlreadyCollectionMember: the given hostname is already a member of the given collection.

## AddHostsToCollections(self, hostnames, collection_ids=None, collection_names=None)

Adds a list of given hosts to a list of given collections.

    Args:
      hostnames: list of strings like 'foohost'.
      collection_ids: list of strings like 'MV100539'.
      collection_names: list of strings like 'Foo Application Version X'.

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

## GetAdvertisementsByCollection(self, collection_id)

Gets a list of advertisements associated with a given collection.

    Args:
      collection_id: string collection ID like 'MV99999'.

    Returns:
      List of dict advertisements [{'id':'MV100000','name':'FooAdvertisement'}].
    GetApplicationsOnHost(self, hostname=None, host=None, wmih=None)
    Gets a list of applications on a given host.

    Args:
      hostname: str host name like 'foohost'      OR
      host: host, wmi object from SMS_R_System()
      wmih: optional, supply a SCCM connected wmi.WMI object.

    Returns:
      List of dict applications.

    Raises:
      common.InvalidArgumentsError: if the arguments were invalid.

## GetClientAdvertisementStatus(self, advertisement_id, hostname)

Gets advertisement status for a given advertisement and host.

    Args:
      advertisement_id: string advertisement ID like 'MV99999'.
      hostname: string hostname like 'foohost'.

    Returns:
      A dictionary with various status information, otherwise None.

## GetCollectionIdByName(self, name)

Gets a collection ID from a given name.

    Args:
      name: str collection name like 'Foo Application Version X'.

    Returns:
      str collection ID if found, like 'MV999999', otherwise None if not found.

## GetCollectionMembership(self, hostname)

Gets a list of collections that a given hostname is a member of.

  Args:
    hostname: str hostname like 'foohost'.

  Returns:
    A list of dictionary collections like {'id': 'MV99999', 'name': 'Name'}.

## GetHostByHostname(self, hostname, with_apps=False, with_usage=False)

Gets a list of hosts with a given hostname.

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

## GetHostByIPAddress(self, ip_address, with_apps=False, with_usage=False)

Gets a list of hosts with a given by IP Address.

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

## GetHostsByUsername(self, username, with_apps=False, with_usage=False)

Gets a list of hosts with a given username.

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

## GetSubCollections(self, collection_id)

Gets a list of subcollections of a given collection_id.

    Args:
      collection_id: string collection ID like 'MV99999'.

    Returns:
      A list of dict collections [{'id': 'MV99999', 'name': 'FooCollection'}].

## GetUsageDataByHost(self, hostname=None, host=None, wmih=None)

Gets any available data on software usage for a given host.

    Args:
      hostname: str host name like 'foohost'.
      host: host, wmi object from SMS_R_System()
      wmih: optional, supply a SCCM connected wmi.WMI object.

    Returns:
      A list of dicts or None if no data is available.

    Raises:
      common.InvalidArgumentsError: if there are invalid arguments.

## GetWmi(self, hostname=None, moniker=None, namespace=None, cache=False)

Get a WMI handle, given connection information.

    Note: Caching handles across threads is not safe per pythoncom module requirements.

    Args:
      hostname: str hostname like 'foohost'.
      moniker: str WMI construct moniker.
      namespace: str WMI namespace.
      cache: boolean, whether to cache the wmi handle for function returns. be
          careful when using in multi-threaded environments.

    Returns:
      A WMI handle object.

## Ping(self, hostname)

Wrapper around PingStatus to simplify return status.

    Args:
      hostname: string hostname.

    Returns:
      True or False if hostname is currently pingable / not pingable.

## RefreshPolicy(self, hostname)

Refresh all policies on a host.

    i.e. Force them to immediately acknowledge new install/uninstall advertisements.

    Args:
      hostname: string like 'foohost'.

    Returns:
      Boolean: True if policy refresh was successful.

    Raises:
      common.HostUnreachable: the host did not resolve or respond to ping.

## SaneHostname(self, hostname)

Sanitizes the given hostname.

    Args:
      hostname: str hostname like 'foohost'

    Returns:
      str hostname in uppercase.

## TriggerSchedule(self, hostname, schedule_id)

Trigger a schedule of a given id on a given hostname.

    Args:
      hostname: string like 'foohost'.
      schedule_id: string like 00000000-0000-0000-0000-000000000021.

    Returns:
      result of triggering schedule.

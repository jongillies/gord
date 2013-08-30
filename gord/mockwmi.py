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

"""Provide mock wmi module.

As new classes are touched in real WMI usage, add empty methods here for
testing, then override with mocks in unittest.
"""

import sys

# pylint: disable-msg=C6409
__VERSION__ = 'MockVersion'  # provide like real wmi module


SCCM_WMI_NAMESPACE = 'SMS/site_MV1'


class Error(Exception):
  pass


class x_wmi(Error):
  pass


def SafeLoadMockModules():
  if sys.platform == 'win32':
    return

  if 'wmi' not in sys.modules:
    sys.modules['wmi'] = sys.modules[__name__]


class GenericContainer(object):
  """Class that assigns named init parameters as properties.

  Useful shortcut for simulating wmi return objects from class operations.
  """

  def __init__(self, **kargs):
    for k in kargs:
      setattr(self, k, kargs[k])


class SMSCollectionContainer(GenericContainer):
  """Class to store a mock SMS Collection."""

  def __init__(self, **kargs):
    self.amr_success = True
    self.amr_exception = False
    super(SMSCollectionContainer, self).__init__(**kargs)

  def AddMembershipRule(self, collectionRule):
    # pylint: disable-msg=W0613
    if self.amr_exception:
      raise x_wmi('Exception occurred')

    if self.amr_success:
      return (0, 0)
    else:
      return (1, 2)


class WMI(object):
  """Mock WMI object."""

  # Ignore invalid names, as they are due to compliance with Windows WMI.
  # pylint: disable-msg=C6409
  # Ignore unused arguments, as this file acts as more of an interface.
  # pylint: disable-msg=W0613

  def __init__(self, moniker=None, namespace=None, computer=None,
               user=None, password=None, debug=True, find_classes=True):
    self.moniker = moniker
    self.namespace = namespace
    self.computer = computer
    self.user = computer
    self.password = password
    self.debug = debug
    self.find_classes = find_classes
    self.ns_cimv2 = 'root/CIMV2'
    self.ns_sms = SCCM_WMI_NAMESPACE

  def Win32_PingStatus(self, Address):
    if self.namespace == self.ns_cimv2:
      return
    else:
      raise AttributeError

  def SMS_Advertisement(
      self, CollectionID=None, AdvertisementID=None, AdvertisementName=None):
    if self.namespace == self.ns_sms:
      return AdvertisementID, AdvertisementName
    else:
      raise AttributeError

  def SMS_ClientAdvertisementStatus(
      self, ResourceID=None, AdvertisementID=None):
    if self.namespace == self.ns_sms:
      return ResourceID, AdvertisementID
    else:
      raise AttributeError

  def SMS_Collection(self, Columns=(), CollectionID=None, Name=None):
    if self.namespace == self.ns_sms:
      return CollectionID, Name
    else:
      raise AttributeError

  def SMS_CollectionMember_a(self, Columns=None, ResourceID=None):
    if self.namespace == self.ns_sms:
      return ResourceID
    else:
      raise AttributeError

  def query(self, query=None):
    if self.namespace == self.ns_sms:
      return []
    else:
      raise AttributeError

  def TriggerSchedule(self, sScheduleID=None):
    if self.moniker.endswith('/CCM:SMS_Client'):
      return sScheduleID
    else:
      raise AttributeError

  def TestMemberClassName(self):
    pass

  def SMS_R_System(self, Columns=(), NetbiosName=None, LastLogonUserName=None,
                   IPAddresses=None, ResourceID=None, Active=None, Client=None,
                   Obsolete=None):
    if self.namespace == self.ns_sms:
      return (NetbiosName, LastLogonUserName)
    else:
      raise AttributeError

  def SMS_G_System_PC_BIOS(self, Columns=(), ResourceID=None):
    if self.namespace == self.ns_sms:
      return ResourceID
    else:
      raise AttributeError

  def SMS_G_System_COMPUTER_SYSTEM(self, Columns=(), ResourceID=None):
    if self.namespace == self.ns_sms:
      return ResourceID
    else:
      raise AttributeError

  def SMS_G_System_ADD_REMOVE_PROGRAMS(self, Columns=(), ResourceID=None):
    if self.namespace == self.ns_sms:
      return ResourceID
    else:
      raise AttributeError

  def SMS_G_System_SoftwareUsageData(self, Columns=(), ResourceID=None,
                                     StillRunning=None):
    if self.namespace == self.ns_sms:
      return (ResourceID, StillRunning)
    else:
      raise AttributeError

  x = lambda: GenericContainer(ResourceID=0, RuleName='', ResourceClassName='')
  SMS_CollectionRuleDirect = GenericContainer(new=x)

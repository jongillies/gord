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

"""Provides miscellaneous utility functions.

These functions are independent of other modules in this codebase.
"""


import datetime
import re

CAPWORDS_REGEX = None


def WMIDateToPythonDateTime(wmistr):
  """Converts WMI dates to Python datetime.datetime objects.

  See http://www.microsoft.com/technet/scriptcenter/guide/sas_wmi_yakv.mspx.

  Args:
    wmistr: MS WMI date to convert
  Returns:
    datetime.datetime object (UTC)
  """
  year = int(wmistr[0:4])
  month = int(wmistr[4:6])
  day = int(wmistr[6:8])
  hours = int(wmistr[8:10])
  minutes = int(wmistr[10:12])
  seconds = int(wmistr[12:14])
  microseconds = int(wmistr[15:21])
  return datetime.datetime(
      year, month, day, hours, minutes, seconds, microseconds)


def TimeDeltaToSeconds(delta):
  """Converts a datetime.timedelta to integer seconds.

  Args:
    delta: a datetime.timedelta object.

  Returns:
    the integer seconds for the timedelta.
  """
  return delta.seconds + (delta.days * 3600 * 24)


def CapWordsToLowerWithUnder(capwords_string):
  """Given a CapWords string, return it in lower_with_under style.

  Args:
    capwords_string: a string like CapWords (UpperCamelCasing).

  Returns:
    A string in lower_with_under style. i.e. FunAuthTest returns fun_auth_test.
  """
  # pylint: disable-msg=W0603
  global CAPWORDS_REGEX
  if CAPWORDS_REGEX is None:
    CAPWORDS_REGEX = re.compile(r'(?<!\A)([A-Z](?=[a-z])|(?<![A-Z])[A-Z])')
  lower_with_under = CAPWORDS_REGEX.sub(r'_\1', capwords_string)
  return lower_with_under.lower()

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

"""Provide utility functions to work with httplib over SDC on AppEngine.

FixSDCHTTPS():  Method to replace httplib.HTTPS with a new version
  which enables appropriate http headers to turn on SDC usage.

"""

import httplib


ORIG_HTTP = '_gae_sdc_orig_HTTP'
ORIG_HTTPS = '_gae_sdc_orig_HTTPS'
# Add hosts to use SDC with to this list.
SDC_INTRANET_HOSTS = [
    ''
]


# Find the original HTTPS class.  We might have already overriden it in
# prior FixSDCHTTPS() calls, so be careful.
if not hasattr(httplib, ORIG_HTTPS):
  parent_HTTPS = httplib.HTTPS
else:
  parent_HTTPS = getattr(httplib, ORIG_HTTPS)

if not hasattr(httplib, ORIG_HTTP):
  parent_HTTP = httplib.HTTP
else:
  parent_HTTP = getattr(httplib, ORIG_HTTP)


class SDCHTTP(parent_HTTP):
  """HTTP class which sets SDC header for any hosts in SDC_INTRANET_HOSTS."""

  def __init__(self, host='', port=None, strict=None):
    parent_HTTP.__init__(self, host=host, port=port, strict=strict)
    if host in SDC_INTRANET_HOSTS:
      self.putheader('use_intranet', 'yes')


def FixSDCHTTP():
  """Replace httplib.HTTP with SDCHTTP."""
  if not hasattr(httplib, ORIG_HTTP):
    setattr(httplib, ORIG_HTTP, httplib.HTTP)
  httplib.HTTP = SDCHTTP


class SDCHTTPS(parent_HTTPS):
  """HTTPS class which sets SDC header for any hosts in SDC_INTRANET_HOSTS."""

  def __init__(self, host='', port=None, strict=None):
    parent_HTTPS.__init__(self, host=host, port=port, strict=strict)
    if host in SDC_INTRANET_HOSTS:
      self.putheader('use_intranet', 'yes')


def FixSDCHTTPS():
  """Replace httplib.HTTPS with SDCHTTPS."""
  if not hasattr(httplib, ORIG_HTTPS):
    setattr(httplib, ORIG_HTTPS, httplib.HTTPS)
  httplib.HTTPS = SDCHTTPS

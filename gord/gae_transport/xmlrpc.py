#!/usr/bin/python2.4
#
# Copyright © 2008 Brian M. Clapper
#
# This is free software, released under the following BSD-like license:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. The end-user documentation included with the redistribution, if any,
#    must include the following acknowledgement:
#
#       This product includes software developed by Brian M. Clapper
#      (bmc@clapper.org, http://www.clapper.org/bmc/). That software is
#       copyright © 2008 Brian M. Clapper.
#
#     Alternately, this acknowlegement may appear in the software itself, if
#     and wherever such third-party acknowlegements normally appear.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
# EVENT SHALL BRIAN M. CLAPPER BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""Provides an XMLRPC transport factory for use with App Engine.

Provides transport classes for XML-RPC that substitute urlfetch calls
in place of socket connections, which are disallowed in App Engine.
"""

import logging
import xmlrpclib
# pylint: disable-msg=C6204
# Disable warning for import not at top of file.
try:
  from google.appengine.api import urlfetch
  IS_APPENGINE = True
except ImportError:
  IS_APPENGINE = False
  pass
# pylint: enable-msg=C6204


class UrlfetchTransport(xmlrpclib.Transport):
  """Handles an HTTP request to an XML-RPC server using urlfetch."""

  PROTOCOL = 'http'
  DEBUG_RESPONSE = False
  DEBUG_HEADERS = False

  # pylint: disable-msg=W0613
  # Disable warning for unused argument.
  def request(self, host, handler, request_body, verbose=0):
    """Request via urlfetch instead of socket connection.

    Args:
      host: string hostname.
      handler: string '/RPC2', defined in xmlrpclib.
      request_body: string XML-RPC request body.
      verbose: integer, defined in xmlrpclib, unused here.

    Returns:
      ServerProxy instance.

    Raises:
      ProtocolError: if urlfetch.fetch fails or returns an HTTP status
        code other than 200.
    """
    result = None
    url = '%s://%s%s' % (self.PROTOCOL, host, handler)
    headers = {'Content-Type': 'text/xml',
               'use_intranet': 'yes',
               'X-secureDataConnector-RouteDomain': 'google.com'}
    if self.DEBUG_HEADERS:
      headers['X-secureDataConnectorDebug'] = 'text'
    try:
      response = urlfetch.fetch(url,
                                payload=request_body,
                                method=urlfetch.POST,
                                headers=headers,
                                deadline=10)
    except urlfetch.Error, error:
      raise xmlrpclib.ProtocolError(host + handler,
                                    500,
                                    error,
                                    {})
    if response.status_code != 200:
      raise xmlrpclib.ProtocolError(host + handler,
                                    response.status_code,
                                    '',
                                    response.headers)
    else:
      if response:
        if self.DEBUG_RESPONSE:
          logging.debug('Response from xmlrpc call: %s', response.content)
        result = self._parse_response(response.content)
      else:
        logging.warning('urlfetch.fetch of %s returned nothing.'
                        ' This may be due to access restrictions'
                        ' in sdc.', url)
    return result

  # pylint: enable-msg=W0613

  def _parse_response(self, response_body):
    """Parse XML-RPC response without socket connection.

    Args:
      response_body: string, XML-RPC response body.

    Returns:
      A tuple containing the unmarshalled XML-RPC response.
    """

    # pylint: disable-msg=E6412
    # Disable error for unexpected keyword argument.
    parser, unmarshaller = xmlrpclib.getparser(use_datetime=0)
    # pylint: enable-msg=E6412
    parser.feed(response_body)
    return unmarshaller.close()


class UrlfetchSafeTransport(UrlfetchTransport):
  """Handles an HTTPS request to an XML-RPC server using urlfetch."""

  PROTOCOL = 'https'
  make_connection = xmlrpclib.SafeTransport.make_connection

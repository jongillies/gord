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

"""Command Line Interface for GORD Client."""




import getpass
import optparse
import sys
import client
import common


class OptionProcessError(Exception):
  """If there is a problem processing command line options."""


class CliClient(object):
  """Command line interface client for GORD Client.

  Attributes:
    USAGE: String basic command line syntax and usage.
    console: Boolean, True if output should be printed to console.  False to
      supress output (critical errors will not be supressed).
    parser: OptionParser object to parse command line options.
    sms_client: client.GORDClient object to execute remote commands.
  """
  USAGE = '%s [options] MethodName Parameter1 Parameter2 ...' % sys.argv[0]

  def __init__(self, console=True):
    """Initializes the cli_client.

    Args:
      console: Boolean, True if output should be printed to console.  False to
        supress output (critical errors will not be supressed).
    """
    self.console = console
    self.parser = self._CreateParser()
    self.sms_client = None

  def _CreateParser(self):
    """Create a OptionParser object for handing cli_client arguments.

    Returns:
      An OptionParser object.
    """
    parser = optparse.OptionParser(usage=self.USAGE)
    parser.add_option('-i', '--uri', action='store', type='string', dest='uri',
                      default=None, help=
                      'Proxy URI to connect to.  Default is current server.')
    parser.add_option('-u', '--username', action='store', type='string',
                      dest='username', default=None, help=
                      'Username to use for obtaining a ticket.')
    parser.add_option('-p', '--password', action='store', type='string',
                      dest='password', default=None, help=
                      'Password to use for obtaining a ticket.  Ignoring '
                      'this option will prompt for an interactive password, and'
                      ' is more secure than typing the password in plain text '
                      'on the command line.')
    parser.add_option('-f', '--fake-login', action='store_true',
                      dest='fake_login', default=False, help=
                      'Enable to use fake-login service.')
    parser.add_option('-n', '--no-auth', action='store_true', dest='no_auth',
                      default=False, help='Use no authentication.  --username '
                      'and --password options are ignored.')
    return parser

  def ProcessArguments(self):
    """Processes command line arguments and runs corresponding GORD client.

    Raises:
      OptionProcessError: If invalid or conflicting options were given.

    Returns:
      A Tuple containing (<str method>, <list method args>) of the remote
      command to execute.
    """
    options, extra_args = self.parser.parse_args()

    # Verify there is actually a remote method to run
    if len(extra_args) < 1:
      raise OptionProcessError('Must specify a method to run on GORD!')
    else:
      method = extra_args.pop(0)
      if len(extra_args) >= 1:
        method_args = extra_args
      else:
        method_args = None

    # Make sure the user/pass is set if needed
    if options.no_auth:
      options.username = None
      options.password = None
    else:
      if options.fake_login:
        options.password = 'junk'
      elif not options.password:
        options.password = getpass.getpass()

    self.sms_client = client.GORDClient(
        options.username, options.password, options.fake_login, options.no_auth)

    if options.uri:
      self.sms_client.proxy_uri = options.uri
      self.sms_client.GetProxy()

    return (method, method_args)

  def ExecuteCommand(self, method, method_args):
    """Executes the requested command against the GORD client.

    Args:
      method: String remote method name to call.
      method_args: List containing method arguments to use, or None.

    Raises:
      common.Error: If there was a problem executing the remote call.

    Returns:
      If running a non-interactive shell (self.console=False), then the results
      of the command are returned from this method.
    """
    method_to_execute = getattr(self.sms_client, method)
    results = method_to_execute(*method_args)
    if self.console:
      print 'return value: %s' % str(results)  # COV_NF_LINE
    else:
      return results


def main():
  """run the CLI interface for the GORD client."""
  cli_client = CliClient()
  try:
    cli_client.ExecuteCommand(*cli_client.ProcessArguments())
  except OptionProcessError, error:
    print '%s\n\n%s' % (cli_client.USAGE, error)
    sys.exit(1)
  except common.Error, error:
    print ('Fatal Error while executing remote command: %s raised: %s' %
           (error.__class__.__name__, str(error)))
    sys.exit(2)

if __name__ == '__main__':
  main()  # COV_NF_LINE

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

"""Logging methods which are Win32-aware."""


import sys
import traceback

DEBUG = False


def LogDebug(*args):
  """If DEBUG, log."""
  if DEBUG:
    LogInfo(*args)


def GenArgsWrapper(handler):
  """Generate a wrapper around a log handler method.

  Args:
    handler: method
  Returns:
    function callable with string formatting
  """
  return lambda msg, *args: ArgsWrapper(handler, msg, args)


def ArgsWrapper(handler, msg, *args):
  """Wrap method calls to carefully perform string formatting on their args.

  The logging.* methods allow you to supply your C-string format args as
  separate arguments.  Therefore one bug in your log output doesn't cause
  the code to crash or not log.

  consider:
    anyfunction('x %d')            # bug, forgot the argument
    anyfunction('x %d' % string)   # bug, can't coerce a string like that
  better:
    log('x %d')          # outputs "x %d"
    log('x %d', 10)      # outputs "x 10"

  The Win32 logging methods do not accept lists of arguments so
  we wrap them to be consistent with logging.*

  Args:
    handler: method to call with only one argument, msg
    msg: str, string to send to handler() with string formatting done
    args: optional, arguments to supply to string formatting

  Returns:
    return value from handler(msg)
  """
  try:
    msg %= args
  except TypeError:
    pass
  return handler(msg)


def FullException(*args):
  """Log an exception to LogError, including backtrace.

  Args:
    args: any number of arguments to print as a header.
  """
  info = sys.exc_info()
  LogError('%s\n\n%s' % (
      str(' '.join(args)), '\n'.join(traceback.format_tb(info[2]))))


def NormalException(method, exc, level=None):
  """Log an exception to LogError, not including backtrace.

  Used for logging exceptions that occur in normal operation as
  return values from methods, not unexpected errors.

  Args:
    method: string method name like HelloWorld
    exc: exception that was raised
    level: log method to use, a method.  one of:
      LogInfo, LogWarning, LogError, default LogInfo.
  """
  if level not in [LogInfo, LogWarning, LogError]:
    level = LogInfo
  level('%s() raised exception %s%s' % (
      method, exc.__class__.__name__, exc.args))


# Create logging wrappers for both win32 and other platforms.
# pylint: disable-msg=C6409
if sys.platform == 'win32':
  import servicemanager  # pylint: disable-msg=C6204
  LogError = GenArgsWrapper(servicemanager.LogErrorMsg)
  LogWarning = GenArgsWrapper(servicemanager.LogWarningMsg)
  LogInfo = GenArgsWrapper(servicemanager.LogInfoMsg)
else:
  import logging  # pylint: disable-msg=C6204
  LogError = logging.error
  LogWarning = logging.warn
  LogInfo = logging.info


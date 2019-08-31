#!/usr/bin/env python

# Copyright 2016 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""The script is used to check cloud activities log for
specified user.
"""

import argparse
import errno
import importlib
import random
import os
import pty
import re
import select
import signal
import six
import subprocess
import sys
import threading
import time
import tty

from datetime import datetime, timedelta, date
from google.cloud import logging

VERSION = "1.0.1"

RED   = "\033[1;31m"
BLUE  = "\033[1;34m"
CYAN  = "\033[1;36m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD    = "\033[;1m"
REVERSE = "\033[;7m"


# define convenient aliases for subprocess constants
# Note subprocess.PIPE == -1, subprocess.STDOUT = -2
PIPE = subprocess.PIPE
STDOUT = subprocess.STDOUT
PTY = -3


class Error(Exception):
  """Exception when Popen suprocesses fail."""


class TimeoutError(Error):
  """Exception when Popen suprocesses time out."""


PopenTimeoutError = TimeoutError


class PollError(Error):
  """Exception when Popen suprocesses have poll errors."""


class ReturncodeError(Error):
  """Exception raised for non-zero returncodes.

  Attributes:
    returncode: the returncode of the failed process.
    cmd: the Popen args argument of the command executed.
  """

  def __init__(self, returncode, cmd):
    Error.__init__(self, returncode, cmd)
    self.returncode = returncode
    self.cmd = cmd

  def __str__(self):
    return "Command '%s' returned non-zero returncode %d" % (
        self.cmd, self.returncode)


def setraw(*args, **kwargs):
  """Wrapper for tty.setraw that retries on EINTR."""
  while True:
    try:
      return tty.setraw(*args, **kwargs)
    except OSError as e:
      if e.errno == errno.EINTR:
        continue
      else:
        raise


def call(*args, **kwargs):
  """Run a command, wait for it to complete, and return the returncode.

  Example:
    retcode = call(["ls", "-l"])

  Args:
    See the Popen constructor.

  Returns:
    The int returncode.
  """
  # Make the default stdout None.
  kwargs.setdefault('stdout', None)
  return Popen(*args, **kwargs).wait()


class Popen(subprocess.Popen):
  """An extended Popen class that is iterable.

  Args:
    args: str or argv arguments of the command
      (sets shell default to True if it is a str)
    bufsize: buffer size to use for IO and iterating
      (default: 1 means linebuffered, 0 means unbuffered)
    input: stdin input data for the command
      (default: None, sets stdin default to PIPE if it is a str)
    timeout: timeout in seconds for command IO processing
      (default:None means no no timeout)
    **kwargs: other subprocess.Popen arguments
  """

  def __init__(self, args, bufsize=1, input=None, timeout=None, **kwargs):
    # make arguments consistent and set defaults
    if isinstance(args, (six.text_type, six.binary_type)):
      kwargs.setdefault('shell', True)
    if isinstance(input, six.text_type):
      input = input.encode('utf-8')
    if isinstance(input, six.binary_type):
      kwargs.setdefault('stdin', PIPE)
    kwargs.setdefault('stdout', PIPE)
    self.__race_lock = threading.RLock()
    super(Popen, self).__init__(args, bufsize=bufsize, **kwargs)
    self.bufsize = bufsize
    self.input = input
    self.timeout = timeout
    # Initialise stdout and stderr buffers as attributes such that their content
    # does not get lost if an iterator is abandoned.
    self.outbuff, self.errbuff = b'', b''

  def _get_handles(self, stdin, stdout, stderr):
    """Construct and return tuple with IO objects.

    This overrides and extends the inherited method to also support PTY as a
    special argument to use pty's for stdin/stdout/stderr.

    Args:
      stdin: the stdin initialisation argument
      stdout: the stdout initialisation argument
      stderr: the stderr initialisation argument

    Returns:
      For recent upstream python2.7+ versions;
      (p2cread, p2cwrite, c2pread, c2pwrite, errread, errwrite), to_close
      For older python versions it returns;
      (p2cread, p2cwrite, c2pread, c2pwrite, errread, errwrite)
    """
    # For upstream recent python2.7+ this returns a tuple (handles, to_close)
    # where handles is a tuple of file handles to use, and to_close is the set
    # of file handles to close after the command completes. For older versions
    # it just returns the file handles.
    orig = super(Popen, self)._get_handles(stdin, stdout, stderr)  # type: ignore
    if len(orig) == 2:
      handles, to_close = orig
    else:
      handles, to_close = orig, set()
    p2cread, p2cwrite, c2pread, c2pwrite, errread, errwrite = handles
    if stdin == PTY:
      p2cread, p2cwrite = pty.openpty()
      setraw(p2cwrite)
      to_close.update((p2cread, p2cwrite))
    if stdout == PTY:
      c2pread, c2pwrite = pty.openpty()
      setraw(c2pwrite)
      to_close.update((c2pread, c2pwrite))
      # if stderr==STDOUT, we need to set errwrite to the new stdout
      if stderr == STDOUT:
        errwrite = c2pwrite
    if stderr == PTY:
      errread, errwrite = pty.openpty()
      setraw(errwrite)
      to_close.update((errread, errwrite))
    handles = p2cread, p2cwrite, c2pread, c2pwrite, errread, errwrite
    if len(orig) == 2:
      return handles, to_close
    else:
      return handles

  def __iter__(self):
    """Iterate through the output of the process.

    Multiple iterators can be instatiated for a Popen instance, e.g. to continue
    reading after a TimeoutError. Creating a new iterator invalidates all
    existing ones. The behavior when reading from old iterators is undefined.

    Raises:
      TimeoutError: if iteration times out
      PollError: if there is an unexpected poll event

    Yields:
      'outdata': if only stdout was PIPE or PTY
      'errdata': if only stderr was PIPE or PTY
      ('outdata', 'errdata') - if both stdout and stderr were PIPE or PTY
      an empty string indicates no output for that iteration.
    """
    # set the per iteration size based on bufsize
    print "Command issued is still running, please wait......"

    if self.bufsize < 1:
      itersize = 2**20  # Use 1M itersize for "as much as possible".
    else:
      itersize = self.bufsize
    # intialize files map and poller
    poller, files = select.poll(), {}
    # register stdin if we have it and it wasn't closed by a previous iterator.
    if self.stdin and not self.stdin.closed:
      # only register stdin if we have input, otherwise just close it
      if self.input:
        poller.register(self.stdin, select.POLLOUT)
        files[self.stdin.fileno()] = self.stdin
      else:
        self.stdin.close()
    # register stdout and sterr if we have them and they weren't closed by a
    # previous iterator.
    for handle in (f for f in (self.stdout, self.stderr) if f and not f.closed):
      poller.register(handle, select.POLLIN)
      files[handle.fileno()] = handle
    # iterate until input and output is finished
    while files:
      # make sure poll/read actions are atomic by aquiring lock
      with self.__race_lock:
        try:
          ready = poller.poll(self.timeout and self.timeout*1000.0)
        except select.error as e:
          # According to chapter 17, section 1 of Python standard library,
          # the exception value is a pair containing the numeric error code
          # from errno and the corresponding string as printed by C function
          # perror().
          if e.args[0] == errno.EINTR:
            # An interrupted system call. try the call again.
            continue
          else:
            # raise everything else that could happen.
            raise
        if not ready:
          raise TimeoutError(
              'command timed out in %s seconds' % self.timeout)
        for fd, event in ready:
          if event & (select.POLLERR | select.POLLNVAL):
            raise PollError(
                'command failed with invalid poll event %s' % event)
          elif event & select.POLLOUT:
            # write input and set data to remaining input
            if self.bufsize == 1:
              itersize = (self.input.find(b'\n') + 1) or None
            self.input = self.input[os.write(fd, self.input[:itersize]):]
            data = self.input
          else:
            # read output into data and set it to outdata or errdata
            try:
              if self.bufsize == 1:
                itersize = 2**10  # Use 1K itersize for line-buffering.
              data = os.read(fd, itersize)
            except (OSError, IOError) as e:
              # reading closed pty's raises IOError or OSError
              if not os.isatty(fd) or e.errno != 5:
                raise
              data = b''
            # Append the read data to the stdout or stderr buffers.
            if files[fd] is self.stdout:
              self.outbuff += data
            else:
              self.errbuff += data
          if not data:
            # no input remaining or output read, close and unregister file
            files[fd].close()
            poller.unregister(fd)
            del files[fd]
      # Break up the output buffers into blocks based on bufsize.
      outdata, errdata = self.outbuff, self.errbuff
      while outdata or errdata:
        if self.bufsize < 1:
          # For unbuffered modes, yield all the buffered data at once.
          outdata, self.outbuff = self.outbuff, b''
          errdata, self.errbuff = self.errbuff, b''
        else:
          # For buffered modes, yield the buffered data as itersize blocks.
          outdata, errdata = b'', b''
          if self.bufsize == 1:
            itersize = (self.outbuff.find(b'\n') + 1) or (len(self.outbuff) + 1)
          if self.outbuff and (len(self.outbuff) >= itersize or
                               self.stdout.closed):
            outdata, self.outbuff = (self.outbuff[:itersize],
                                     self.outbuff[itersize:])
          if self.bufsize == 1:
            itersize = (self.errbuff.find(b'\n') + 1) or (len(self.errbuff) + 1)
          if self.errbuff and (len(self.errbuff) >= itersize or
                               self.stderr.closed):
            errdata, self.errbuff = (self.errbuff[:itersize],
                                     self.errbuff[itersize:])
        # Yield appropriate output depending on what was requested.
        if outdata or errdata:
          if self.stdout and self.stderr:
            yield outdata, errdata
          elif self.stdout:
            yield outdata
          elif self.stderr:
            yield errdata
    # make sure the process is finished
    self.wait()

  def communicate(self, input=None):
    """Interact with a process, feeding it input and returning output.

    This is the same as subprocess.Popen.communicate() except it adds support
    for timeouts and sends any input provided at initialiasation before
    sending additional input provided to this method.

    Args:
      input: extra input to send to stdin after any initialisation input
        (default: None)

    Raises:
      TimeoutError: if IO times out
      PollError: if there is an unexpected poll event

    Returns:
      (stdout, sterr) tuple of ouput data
    """
    # extend self.input with additional input
    if isinstance(input, six.text_type):
      input = input.encode('utf-8')
    self.input = (self.input or b'') + (input or b'')
    # As an optimization (and to avoid potential b/3469176 style deadlock), set
    # aggressive buffering for communicate, regardless of bufsize.
    self.bufsize = -1
    try:
      # Create a list out of the iterated output.
      output = list(self)
    except TimeoutError:
      # On timeout, kill and reap the process and re-raise.
      self.kill()
      self.wait()
      raise
    # construct and return the (stdout, stderr) tuple
    if self.stdout and self.stderr:
      return b''.join(o[0] for o in output), b''.join(o[1] for o in output)
    elif self.stdout:
      return b''.join(output), None
    elif self.stderr:
      return None, b''.join(output)
    else:
      return None, None

  def poll(self, *args, **kwargs):
    """Work around a known race condition in subprocess fixed in Python 2.5."""
    # Another thread is operating on (likely waiting on) this process. Claim
    # that the process has not finished yet, unless the returncode attribute
    # has already bet set. Even if this is a lie, it's a harmless one --
    # generally anyone calling poll() will check back later. Much more often,
    # it means that another thread is blocking on wait().
    print "Command is finished."
    if not self.__race_lock.acquire(blocking=False):
      return self.returncode
    try:
      return super(Popen, self).poll(*args, **kwargs)
    finally:
      self.__race_lock.release()

  def wait(self, *args, **kwargs):
    """Work around a known race condition in subprocess fixed in Python 2.5."""
    print "Command is finished."

    with self.__race_lock:
      return super(Popen, self).wait(*args, **kwargs)

  # Python v2.6 introduced the kill() method.
  if not hasattr(subprocess.Popen, 'kill'):

    def kill(self):
      """Kill the subprocess."""
      os.kill(self.pid, signal.SIGKILL)

  # Python v2.6 introduced the terminate() method.
  if not hasattr(subprocess.Popen, 'terminate'):

    def terminate(self):
      """Terminate the subprocess."""
      os.kill(self.pid, signal.SIGTERM)


def countdown(t, step=1, msg='sleeping'):
    for i in range(t, 0, -step):
        pad_str = '.' * len('%d' % i)
        print '%s for the next %d seconds %s.\r' % (msg, i, pad_str),
        sys.stdout.flush()
        time.sleep(step)
    print 'Done %s for %d seconds!  %s' % (msg, t, pad_str)


def send_log_to_stdout():
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    root.addHandler(handler)


class CommandFailError(Exception):
     pass


def RunCmd(cmd, timeout, output_file=None, wait=2, counter=0, **kwargs):
  """Run a command from console and wait/return command reply.

  Args:
    cmd: the command to execute
    timeout: command timeout value
    output_file: the abusolute path to the output file for command reply
    wait: time interval between command retries
    counter: number of retry times if command failed, by default, no retry
             needed
    **kwargs: other args to control command execution,
      "no_raise": if True, do not raise exception if command failed.

  Returns:
    tuple: return code and reply message
  """

  def RetryCmd(cmd, timeout, output_file=None):
    """Execute a command with timeout restriction."""
    outfile = output_file and open(output_file, 'a') or PIPE
    bash = Popen(cmd, stdout=outfile, stderr=outfile, timeout=timeout,
                           shell=True)
    output, err = bash.communicate()
    if bash.returncode != 0 and not kwargs.get('no_raise'):
        print "Fail to run cmd {}".format(cmd)
    return bash.returncode, output, err

  timeout = max(timeout, 20)
  rc, out, err = RetryCmd(cmd, timeout, output_file)
  if rc == 0:
    return (0, err and out + '\n' + err or out)
  return (rc, err)


def gcp_auth(serviceacct):
    # gcloud auth activate-service-account --key-file=release-reader-key.json
    cmdline = 'gcloud auth activate-service-account --key-file={}'.format(serviceacct)
    print cmdline
    (retcode, retOuput) = RunCmd(cmdline, 15, None, wait=2, counter=3)
    print retOuput
    if retcode == 1:
        print "Failure to run cmd {}".format(cmdline)
    return retcode


def write_entry(logger_name, project, number, user, window):
    """Writes log entries to the given logger."""
    logging_client = logging.Client()

    # This log can be found in the Cloud Logging console under 'Custom Logs'.
    logger = logging_client.logger(logger_name)

    # Simple text log with severity.
    if number == 0:
         severity_status = "WARNING"
         logger_text = 'WARNING: For the last {} days no log found for {} in the project {} for log {} ( additional filter = {} ).'.format(window, user, project[0], logger_name, logging_filter)
         
    else:
         severity_status = "INFO"
         logger_text = 'For the last {} days found {} of log for {} in the project {} for log {} (aditional filter = {} ) .'.format(window, number), user, project[0], logger_name, logging_filter)
         
    logger.log_text(logger_text, severity=severity_status)


    print('Wrote logs to {}.'.format(logger.name))
    print("logging: {}".format(logger_text))

def compose_log_filter(logger_name, user, window, addfilter=None):
    mydate = datetime.now()
    mydate = mydate - timedelta(days = window)
    start_date = str(mydate).split(' ')[0]

    if not logger_name == None:
        logging_filter =  'timestamp>="{}T00:00:00Z" AND logName:{}'.format(start_date, logger_name)
    else:
        logging_filter =  'timestamp>="{}T00:00:00Z"'.format(start_date)

    if not user == None:
        logging_filter =  '{} AND protoPayload.authenticationInfo.principalEmail:{} ' .format(logging_filter, user)

    if not addfilter == None:
        logging_filter  = '{} AND {}'.format(logging_filter, addfilter)
    return  logging_filter 

def list_entries(logger_name, project, user, window, addfilter=None):
    """Lists the most recent entries for a given logger."""
    logging_client = logging.Client()
    logger = logging_client.logger(logger_name)
    logging_filter = compose_log_filter(logger_name, user, window, addfilter)
    print "Filter used to retrieve log: {}".format(logging_filter)

    projectlist = []
    projectlist.append(project)
    loglist = None
    loglist = logger.list_entries(projects=projectlist, filter_=logging_filter)

    if not loglist:
        print "No log found."
        return
    count = 0
    for entry in loglist:
        timestamp = entry.timestamp.isoformat()
        print('* {}: {}'.format
              (timestamp, entry.payload))
        count += 1
    write_logger_name = "partner_activities_check"
    if not logger_name == write_logger_name:
        write_entry(write_logger_name, projectlist, count, user, window)


def gcp_write_log(logger_name, project, logtext, logseverity):
    # gcloud logging write partner_activities_check  "A simple entry"  --severity=WARNING --project=gkeoplabs-hammerspace-1
    cmdline = "gcloud logging write {}  \"{}\"  --severity={} --project={}".format(logger_name, logtext, logseverity, project)
    print cmdline
    (retcode, retOutput) = RunCmd(cmdline, 15, None, wait=2, counter=3)
    print  "result: {}".format(retOutput)
    return


def gcp_get_log_count(logger_name, project, user, window, addfilter=None):
    # gcloud logging read 'timestamp>="2019-08-30T00:00:00Z" AND protoPayload.authenticationInfo.principalEmail:mzhuo@google.com AND logName:projects/gkeoplabs-hammerspace-1/logs/cloudaudit.googleapis.com%2Factivity' --project=gkeoplabs-hammerspace-1  | grep insertId | wc -l
    logging_filter = compose_log_filter(logger_name, user, window, addfilter)
    print "Filter used to retrieve log: {}".format(logging_filter)

    cmdline = 'gcloud logging read \'{}\' --project={} | grep insertId | wc -l'.format(logging_filter, project)
    print cmdline
    (retcode, retOutput) = RunCmd(cmdline, 15, None, wait=2, counter=3)
    print  "result: {}".format(retOutput)

    write_logger_name = "partner_activities_check"

    if int(retOutput) == 0:
        severity_status = "WARNING"
        logger_text = 'WARNING: For the last {} days no log found for {} in the project {} for log {} ( additional filter = {} ).'.format(window, user, project, logger_name, logging_filter)
    else:
        severity_status = "INFO"
        logger_text = 'For the last {} days found {} of log for {} in the project {} for log {} (aditional filter = {} ) .'.format(window, int(retOutput), user, project, logger_name, logging_filter)

    gcp_write_log(write_logger_name, project, logger_text, severity_status)

    return int(retOutput)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-logger_name', '--logger_name', dest='logger_name', help='Log Name', type=str, default=None)
    parser.add_argument('-project', '--project', dest='project', type=str, help='Project ID', required=True, default=None)
    parser.add_argument('-user', '--user', dest='user', type=str, help='User Name', default=None)
    parser.add_argument('-logfilter', '--logfiler', dest='logfilter', help='log filter', type=str, default=None)
    parser.add_argument('-window', '--window', dest='window', help='number of days to inspect logs', type=int, default=0)
    parser.add_argument('-serviceacct', '--serviceacct', dest='serviceacct', help='Google Cloud service account', type=str, default=None)
    parser.add_argument('-gclient', '--gclient', dest='gclient', help='flag to use gclient to retrieve log or not', action='store_true', default=False)

    args = parser.parse_args()

    if not args.serviceacct == None:
        if gcp_auth(args.serviceacct) == 1:
            print "Fail to activate GCP service acct {}.".format(serviceacct)
    if args.gclient:
        list_entries(args.logger_name, args.project, args.user, int(args.window), args.logfilter)
    else:
        gcp_get_log_count(args.logger_name, args.project, args.user, int(args.window), args.logfilter)

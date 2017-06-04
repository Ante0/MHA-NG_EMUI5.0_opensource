#
# Copyright 2008 Google Inc. Released under the GPL v2

# pylint: disable-msg=C0111

import StringIO
import errno
import itertools
import logging
import os
import pickle
import random
import re
import resource
import select
import shutil
import signal
import smtplib
import socket
import string
import struct
import subprocess
import textwrap
import time
import urllib2
import urlparse
import warnings

from threading import Thread, Event

try:
    import hashlib
except ImportError:
    import md5
    import sha

from autotest_lib.client.common_lib import error, logging_manager


def deprecated(func):
    """This is a decorator which can be used to mark functions as deprecated.
    It will result in a warning being emmitted when the function is used."""
    def new_func(*args, **dargs):
        warnings.warn("Call to deprecated function %s." % func.__name__,
                      category=DeprecationWarning)
        return func(*args, **dargs)
    new_func.__name__ = func.__name__
    new_func.__doc__ = func.__doc__
    new_func.__dict__.update(func.__dict__)
    return new_func


class _NullStream(object):
    def write(self, data):
        pass


    def flush(self):
        pass


TEE_TO_LOGS = object()
_the_null_stream = _NullStream()

DEFAULT_STDOUT_LEVEL = logging.DEBUG
DEFAULT_STDERR_LEVEL = logging.ERROR

# prefixes for logging stdout/stderr of commands
STDOUT_PREFIX = '[stdout] '
STDERR_PREFIX = '[stderr] '

# safe characters for the shell (do not need quoting)
SHELL_QUOTING_WHITELIST = frozenset(string.ascii_letters +
                                    string.digits +
                                    '_-+=')


def custom_warning_handler(message, category, filename, lineno, file=None,
                           line=None):
    """Custom handler to log at the WARNING error level. Ignores |file|."""
    logging.warning(warnings.formatwarning(message, category, filename, lineno,
                                           line))

warnings.showwarning = custom_warning_handler

def get_stream_tee_file(stream, level, prefix=''):
    if stream is None:
        return _the_null_stream
    if stream is TEE_TO_LOGS:
        return logging_manager.LoggingFile(level=level, prefix=prefix)
    return stream


def _join_with_nickname(base_string, nickname):
    if nickname:
        return '%s BgJob "%s" ' % (base_string, nickname)
    return base_string


# TODO: Cleanup and possibly eliminate no_pipes, which is only used
# in our master-ssh connection process, while fixing underlying
# semantics problem in BgJob. See crbug.com/279312
class BgJob(object):
    def __init__(self, command, stdout_tee=None, stderr_tee=None, verbose=True,
                 stdin=None, stderr_level=DEFAULT_STDERR_LEVEL, nickname=None,
                 no_pipes=False):
        """Create and start a new BgJob.

        This constructor creates a new BgJob, and uses Popen to start a new
        subprocess with given command. It returns without blocking on execution
        of the subprocess.

        After starting a new BgJob, use output_prepare to connect the process's
        stdout and stderr pipes to the stream of your choice.

        When the job is running, the jobs's output streams are only read from
        when process_output is called.

        @param command: command to be executed in new subprocess. May be either
                        a list, or a string (in which case Popen will be called
                        with shell=True)
        @param stdout_tee: Optional additional stream that the process's stdout
                           stream output will be written to. Or, specify
                           base_utils.TEE_TO_LOGS and the output will handled by
                           the standard logging_manager.
        @param stderr_tee: Same as stdout_tee, but for stderr.
        @param verbose: Boolean, make BgJob logging more verbose.
        @param stdin: Stream object, will be passed to Popen as the new
                      process's stdin.
        @param stderr_level: A logging level value. If stderr_tee was set to
                             base_utils.TEE_TO_LOGS, sets the level that tee'd
                             stderr output will be logged at. Ignored
                             otherwise.
        @param nickname: Optional string, to be included in logging messages
        @param no_pipes: Boolean, default False. If True, this subprocess
                         created by this BgJob does NOT use subprocess.PIPE
                         for its stdin or stderr streams. Instead, these
                         streams are connected to the logging manager
                         (regardless of the values of stdout_tee and
                         stderr_tee).
                         If no_pipes is True, then calls to output_prepare,
                         process_output, and cleanup will result in an
                         InvalidBgJobCall exception. no_pipes should be
                         True for BgJobs that do not interact via stdout/stderr
                         with other BgJobs, or long runing background jobs that
                         will never be joined with join_bg_jobs, such as the
                         master-ssh connection BgJob.
        """
        self.command = command
        self._no_pipes = no_pipes
        if no_pipes:
            stdout_tee = TEE_TO_LOGS
            stderr_tee = TEE_TO_LOGS
        self.stdout_tee = get_stream_tee_file(stdout_tee, DEFAULT_STDOUT_LEVEL,
                prefix=_join_with_nickname(STDOUT_PREFIX, nickname))
        self.stderr_tee = get_stream_tee_file(stderr_tee, stderr_level,
                prefix=_join_with_nickname(STDERR_PREFIX, nickname))
        self.result = CmdResult(command)

        # allow for easy stdin input by string, we'll let subprocess create
        # a pipe for stdin input and we'll write to it in the wait loop
        if isinstance(stdin, basestring):
            self.string_stdin = stdin
            stdin = subprocess.PIPE
        else:
            self.string_stdin = None


        if no_pipes:
            stdout_param = self.stdout_tee
            stderr_param = self.stderr_tee
        else:
            stdout_param = subprocess.PIPE
            stderr_param = subprocess.PIPE

        if verbose:
            logging.debug("Running '%s'", command)
        if type(command) == list:
            self.sp = subprocess.Popen(command,
                                       stdout=stdout_param,
                                       stderr=stderr_param,
                                       preexec_fn=self._reset_sigpipe,
                                       stdin=stdin)
        else:
            self.sp = subprocess.Popen(command, stdout=stdout_param,
                                       stderr=stderr_param,
                                       preexec_fn=self._reset_sigpipe, shell=True,
                                       executable="/bin/bash",
                                       stdin=stdin)

        self._output_prepare_called = False
        self._process_output_warned = False
        self._cleanup_called = False
        self.stdout_file = _the_null_stream
        self.stderr_file = _the_null_stream

    def output_prepare(self, stdout_file=_the_null_stream,
                       stderr_file=_the_null_stream):
        """Connect the subprocess's stdout and stderr to streams.

        Subsequent calls to output_prepare are permitted, and will reassign
        the streams. However, this will have the side effect that the ultimate
        call to cleanup() will only remember the stdout and stderr data up to
        the last output_prepare call when saving this data to BgJob.result.

        @param stdout_file: Stream that output from the process's stdout pipe
                            will be written to. Default: a null stream.
        @param stderr_file: Stream that output from the process's stdout pipe
                            will be written to. Default: a null stream.
        """
        if self._no_pipes:
            raise error.InvalidBgJobCall('Cannot call output_prepare on a '
                                         'job with no_pipes=True.')
        if self._output_prepare_called:
            logging.warning('BgJob [%s] received a duplicate call to '
                            'output prepare. Allowing, but this may result '
                            'in data missing from BgJob.result.')
        self.stdout_file = stdout_file
        self.stderr_file = stderr_file
        self._output_prepare_called = True


    def process_output(self, stdout=True, final_read=False):
        """Read from process's output stream, and write data to destinations.

        This function reads up to 1024 bytes from the background job's
        stdout or stderr stream, and writes the resulting data to the BgJob's
        output tee and to the stream set up in output_prepare.

        Warning: Calls to process_output will block on reads from the
        subprocess stream, and will block on writes to the configured
        destination stream.

        @param stdout: True = read and process data from job's stdout.
                       False = from stderr.
                       Default: True
        @param final_read: Do not read only 1024 bytes from stream. Instead,
                           read and process all data until end of the stream.

        """
        if self._no_pipes:
            raise error.InvalidBgJobCall('Cannot call process_output on '
                                         'a job with no_pipes=True')
        if not self._output_prepare_called and not self._process_output_warned:
            logging.warning('BgJob with command [%s] handled a process_output '
                            'call before output_prepare was called. '
                            'Some output data discarded. '
                            'Future warnings suppressed.',
                            self.command)
            self._process_output_warned = True
        if stdout:
            pipe, buf, tee = self.sp.stdout, self.stdout_file, self.stdout_tee
        else:
            pipe, buf, tee = self.sp.stderr, self.stderr_file, self.stderr_tee

        if final_read:
            # read in all the data we can from pipe and then stop
            data = []
            while select.select([pipe], [], [], 0)[0]:
                data.append(os.read(pipe.fileno(), 1024))
                if len(data[-1]) == 0:
                    break
            data = "".join(data)
        else:
            # perform a single read
            data = os.read(pipe.fileno(), 1024)
        buf.write(data)
        tee.write(data)


    def cleanup(self):
        """Clean up after BgJob.

        Flush the stdout_tee and stderr_tee buffers, close the
        subprocess stdout and stderr buffers, and saves data from
        the configured stdout and stderr destination streams to
        self.result. Duplicate calls ignored with a warning.
        """
        if self._no_pipes:
            raise error.InvalidBgJobCall('Cannot call cleanup on '
                                         'a job with no_pipes=True')
        if self._cleanup_called:
            logging.warning('BgJob [%s] received a duplicate call to '
                            'cleanup. Ignoring.', self.command)
            return
        try:
            self.stdout_tee.flush()
            self.stderr_tee.flush()
            self.sp.stdout.close()
            self.sp.stderr.close()
            self.result.stdout = self.stdout_file.getvalue()
            self.result.stderr = self.stderr_file.getvalue()
        finally:
            self._cleanup_called = True


    def _reset_sigpipe(self):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)


def ip_to_long(ip):
    # !L is a long in network byte order
    return struct.unpack('!L', socket.inet_aton(ip))[0]


def long_to_ip(number):
    # See above comment.
    return socket.inet_ntoa(struct.pack('!L', number))


def create_subnet_mask(bits):
    return (1 << 32) - (1 << 32-bits)


def format_ip_with_mask(ip, mask_bits):
    masked_ip = ip_to_long(ip) & create_subnet_mask(mask_bits)
    return "%s/%s" % (long_to_ip(masked_ip), mask_bits)


def normalize_hostname(alias):
    ip = socket.gethostbyname(alias)
    return socket.gethostbyaddr(ip)[0]


def get_ip_local_port_range():
    match = re.match(r'\s*(\d+)\s*(\d+)\s*$',
                     read_one_line('/proc/sys/net/ipv4/ip_local_port_range'))
    return (int(match.group(1)), int(match.group(2)))


def set_ip_local_port_range(lower, upper):
    write_one_line('/proc/sys/net/ipv4/ip_local_port_range',
                   '%d %d\n' % (lower, upper))


def send_email(mail_from, mail_to, subject, body):
    """
    Sends an email via smtp

    mail_from: string with email address of sender
    mail_to: string or list with email address(es) of recipients
    subject: string with subject of email
    body: (multi-line) string with body of email
    """
    if isinstance(mail_to, str):
        mail_to = [mail_to]
    msg = "From: %s\nTo: %s\nSubject: %s\n\n%s" % (mail_from, ','.join(mail_to),
                                                   subject, body)
    try:
        mailer = smtplib.SMTP('localhost')
        try:
            mailer.sendmail(mail_from, mail_to, msg)
        finally:
            mailer.quit()
    except Exception, e:
        # Emails are non-critical, not errors, but don't raise them
        print "Sending email failed. Reason: %s" % repr(e)


def read_one_line(filename):
    return open(filename, 'r').readline().rstrip('\n')


def read_file(filename):
    f = open(filename)
    try:
        return f.read()
    finally:
        f.close()


def get_field(data, param, linestart="", sep=" "):
    """
    Parse data from string.
    @param data: Data to parse.
        example:
          data:
             cpu   324 345 34  5 345
             cpu0  34  11  34 34  33
             ^^^^
             start of line
             params 0   1   2  3   4
    @param param: Position of parameter after linestart marker.
    @param linestart: String to which start line with parameters.
    @param sep: Separator between parameters regular expression.
    """
    search = re.compile(r"(?<=^%s)\s*(.*)" % linestart, re.MULTILINE)
    find = search.search(data)
    if find != None:
        return re.split("%s" % sep, find.group(1))[param]
    else:
        print "There is no line which starts with %s in data." % linestart
        return None


def write_one_line(filename, line):
    open_write_close(filename, str(line).rstrip('\n') + '\n')


def open_write_close(filename, data):
    f = open(filename, 'w')
    try:
        f.write(data)
    finally:
        f.close()


def locate_file(path, base_dir=None):
    """Locates a file.

    @param path: The path of the file being located. Could be absolute or relative
        path. For relative path, it tries to locate the file from base_dir.
    @param base_dir (optional): Base directory of the relative path.

    @returns Absolute path of the file if found. None if path is None.
    @raises error.TestFail if the file is not found.
    """
    if path is None:
        return None

    if not os.path.isabs(path) and base_dir is not None:
        # Assume the relative path is based in autotest directory.
        path = os.path.join(base_dir, path)
    if not os.path.isfile(path):
        raise error.TestFail('ERROR: Unable to find %s' % path)
    return path


def matrix_to_string(matrix, header=None):
    """
    Return a pretty, aligned string representation of a nxm matrix.

    This representation can be used to print any tabular data, such as
    database results. It works by scanning the lengths of each element
    in each column, and determining the format string dynamically.

    @param matrix: Matrix representation (list with n rows of m elements).
    @param header: Optional tuple or list with header elements to be displayed.
    """
    if type(header) is list:
        header = tuple(header)
    lengths = []
    if header:
        for column in header:
            lengths.append(len(column))
    for row in matrix:
        for i, column in enumerate(row):
            column = unicode(column).encode("utf-8")
            cl = len(column)
            try:
                ml = lengths[i]
                if cl > ml:
                    lengths[i] = cl
            except IndexError:
                lengths.append(cl)

    lengths = tuple(lengths)
    format_string = ""
    for length in lengths:
        format_string += "%-" + str(length) + "s "
    format_string += "\n"

    matrix_str = ""
    if header:
        matrix_str += format_string % header
    for row in matrix:
        matrix_str += format_string % tuple(row)

    return matrix_str


def read_keyval(path, type_tag=None):
    """
    Read a key-value pair format file into a dictionary, and return it.
    Takes either a filename or directory name as input. If it's a
    directory name, we assume you want the file to be called keyval.

    @param path: Full path of the file to read from.
    @param type_tag: If not None, only keyvals with key ending
                     in a suffix {type_tag} will be collected.
    """
    if os.path.isdir(path):
        path = os.path.join(path, 'keyval')
    if not os.path.exists(path):
        return {}

    if type_tag:
        pattern = r'^([-\.\w]+)\{%s\}=(.*)$' % type_tag
    else:
        pattern = r'^([-\.\w]+)=(.*)$'

    keyval = {}
    f = open(path)
    for line in f:
        line = re.sub('#.*', '', line).rstrip()
        if not line:
            continue
        match = re.match(pattern, line)
        if match:
            key = match.group(1)
            value = match.group(2)
            if re.search('^\d+$', value):
                value = int(value)
            elif re.search('^(\d+\.)?\d+$', value):
                value = float(value)
            keyval[key] = value
        else:
            raise ValueError('Invalid format line: %s' % line)
    f.close()
    return keyval


def write_keyval(path, dictionary, type_tag=None, tap_report=None):
    """
    Write a key-value pair format file out to a file. This uses append
    mode to open the file, so existing text will not be overwritten or
    reparsed.

    If type_tag is None, then the key must be composed of alphanumeric
    characters (or dashes+underscores). However, if type-tag is not
    null then the keys must also have "{type_tag}" as a suffix. At
    the moment the only valid values of type_tag are "attr" and "perf".

    @param path: full path of the file to be written
    @param dictionary: the items to write
    @param type_tag: see text above
    """
    if os.path.isdir(path):
        path = os.path.join(path, 'keyval')
    keyval = open(path, 'a')

    if type_tag is None:
        key_regex = re.compile(r'^[-\.\w]+$')
    else:
        if type_tag not in ('attr', 'perf'):
            raise ValueError('Invalid type tag: %s' % type_tag)
        escaped_tag = re.escape(type_tag)
        key_regex = re.compile(r'^[-\.\w]+\{%s\}$' % escaped_tag)
    try:
        for key in sorted(dictionary.keys()):
            if not key_regex.search(key):
                raise ValueError('Invalid key: %s' % key)
            keyval.write('%s=%s\n' % (key, dictionary[key]))
    finally:
        keyval.close()

    # same for tap
    if tap_report is not None and tap_report.do_tap_report:
        tap_report.record_keyval(path, dictionary, type_tag=type_tag)

class FileFieldMonitor(object):
    """
    Monitors the information from the file and reports it's values.

    It gather the information at start and stop of the measurement or
    continuously during the measurement.
    """
    class Monitor(Thread):
        """
        Internal monitor class to ensure continuous monitor of monitored file.
        """
        def __init__(self, master):
            """
            @param master: Master class which control Monitor
            """
            Thread.__init__(self)
            self.master = master

        def run(self):
            """
            Start monitor in thread mode
            """
            while not self.master.end_event.isSet():
                self.master._get_value(self.master.logging)
                time.sleep(self.master.time_step)


    def __init__(self, status_file, data_to_read, mode_diff, continuously=False,
                 contlogging=False, separator=" +", time_step=0.1):
        """
        Initialize variables.
        @param status_file: File contain status.
        @param mode_diff: If True make a difference of value, else average.
        @param data_to_read: List of tuples with data position.
            format: [(start_of_line,position in params)]
            example:
              data:
                 cpu   324 345 34  5 345
                 cpu0  34  11  34 34  33
                 ^^^^
                 start of line
                 params 0   1   2  3   4
        @param mode_diff: True to subtract old value from new value,
            False make average of the values.
        @parma continuously: Start the monitoring thread using the time_step
            as the measurement period.
        @param contlogging: Log data in continuous run.
        @param separator: Regular expression of separator.
        @param time_step: Time period of the monitoring value.
        """
        self.end_event = Event()
        self.start_time = 0
        self.end_time = 0
        self.test_time = 0

        self.status_file = status_file
        self.separator = separator
        self.data_to_read = data_to_read
        self.num_of_params = len(self.data_to_read)
        self.mode_diff = mode_diff
        self.continuously = continuously
        self.time_step = time_step

        self.value = [0 for i in range(self.num_of_params)]
        self.old_value = [0 for i in range(self.num_of_params)]
        self.log = []
        self.logging = contlogging

        self.started = False
        self.num_of_get_value = 0
        self.monitor = None


    def _get_value(self, logging=True):
        """
        Return current values.
        @param logging: If true log value in memory. There can be problem
          with long run.
        """
        data = read_file(self.status_file)
        value = []
        for i in range(self.num_of_params):
            value.append(int(get_field(data,
                             self.data_to_read[i][1],
                             self.data_to_read[i][0],
                             self.separator)))

        if logging:
            self.log.append(value)
        if not self.mode_diff:
            value = map(lambda x, y: x + y, value, self.old_value)

        self.old_value = value
        self.num_of_get_value += 1
        return value


    def start(self):
        """
        Start value monitor.
        """
        if self.started:
            self.stop()
        self.old_value = [0 for i in range(self.num_of_params)]
        self.num_of_get_value = 0
        self.log = []
        self.end_event.clear()
        self.start_time = time.time()
        self._get_value()
        self.started = True
        if (self.continuously):
            self.monitor = FileFieldMonitor.Monitor(self)
            self.monitor.start()


    def stop(self):
        """
        Stop value monitor.
        """
        if self.started:
            self.started = False
            self.end_time = time.time()
            self.test_time = self.end_time - self.start_time
            self.value = self._get_value()
            if (self.continuously):
                self.end_event.set()
                self.monitor.join()
            if (self.mode_diff):
                self.value = map(lambda x, y: x - y, self.log[-1], self.log[0])
            else:
                self.value = map(lambda x: x / self.num_of_get_value,
                                 self.value)


    def get_status(self):
        """
        @return: Status of monitored process average value,
            time of test and array of monitored values and time step of
            continuous run.
        """
        if self.started:
            self.stop()
        if self.mode_diff:
            for i in range(len(self.log) - 1):
                self.log[i] = (map(lambda x, y: x - y,
                                   self.log[i + 1], self.log[i]))
            self.log.pop()
        return (self.value, self.test_time, self.log, self.time_step)


def is_url(path):
    """Return true if path looks like a URL"""
    # for now, just handle http and ftp
    url_parts = urlparse.urlparse(path)
    return (url_parts[0] in ('http', 'ftp'))


def urlopen(url, data=None, timeout=5):
    """Wrapper to urllib2.urlopen with timeout addition."""

    # Save old timeout
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        return urllib2.urlopen(url, data=data)
    finally:
        socket.setdefaulttimeout(old_timeout)


def urlretrieve(url, filename, data=None, timeout=300):
    """Retrieve a file from given url."""
    logging.debug('Fetching %s -> %s', url, filename)

    src_file = urlopen(url, data=data, timeout=timeout)
    try:
        dest_file = open(filename, 'wb')
        try:
            shutil.copyfileobj(src_file, dest_file)
        finally:
            dest_file.close()
    finally:
        src_file.close()


def hash(type, input=None):
    """
    Returns an hash object of type md5 or sha1. This function is implemented in
    order to encapsulate hash objects in a way that is compatible with python
    2.4 and python 2.6 without warnings.

    Note that even though python 2.6 hashlib supports hash types other than
    md5 and sha1, we are artificially limiting the input values in order to
    make the function to behave exactly the same among both python
    implementations.

    @param input: Optional input string that will be used to update the hash.
    """
    if type not in ['md5', 'sha1']:
        raise ValueError("Unsupported hash type: %s" % type)

    try:
        hash = hashlib.new(type)
    except NameError:
        if type == 'md5':
            hash = md5.new()
        elif type == 'sha1':
            hash = sha.new()

    if input:
        hash.update(input)

    return hash


def get_file(src, dest, permissions=None):
    """Get a file from src, which can be local or a remote URL"""
    if src == dest:
        return

    if is_url(src):
        urlretrieve(src, dest)
    else:
        shutil.copyfile(src, dest)

    if permissions:
        os.chmod(dest, permissions)
    return dest


def unmap_url(srcdir, src, destdir='.'):
    """
    Receives either a path to a local file or a URL.
    returns either the path to the local file, or the fetched URL

    unmap_url('/usr/src', 'foo.tar', '/tmp')
                            = '/usr/src/foo.tar'
    unmap_url('/usr/src', 'http://site/file', '/tmp')
                            = '/tmp/file'
                            (after retrieving it)
    """
    if is_url(src):
        url_parts = urlparse.urlparse(src)
        filename = os.path.basename(url_parts[2])
        dest = os.path.join(destdir, filename)
        return get_file(src, dest)
    else:
        return os.path.join(srcdir, src)


def update_version(srcdir, preserve_srcdir, new_version, install,
                   *args, **dargs):
    """
    Make sure srcdir is version new_version

    If not, delete it and install() the new version.

    In the preserve_srcdir case, we just check it's up to date,
    and if not, we rerun install, without removing srcdir
    """
    versionfile = os.path.join(srcdir, '.version')
    install_needed = True

    if os.path.exists(versionfile):
        old_version = pickle.load(open(versionfile))
        if old_version == new_version:
            install_needed = False

    if install_needed:
        if not preserve_srcdir and os.path.exists(srcdir):
            shutil.rmtree(srcdir)
        install(*args, **dargs)
        if os.path.exists(srcdir):
            pickle.dump(new_version, open(versionfile, 'w'))


def get_stderr_level(stderr_is_expected):
    if stderr_is_expected:
        return DEFAULT_STDOUT_LEVEL
    return DEFAULT_STDERR_LEVEL


def run(command, timeout=None, ignore_status=False,
        stdout_tee=None, stderr_tee=None, verbose=True, stdin=None,
        stderr_is_expected=None, args=(), nickname=None, ignore_timeout=False):
    """
    Run a command on the host.

    @param command: the command line string.
    @param timeout: time limit in seconds before attempting to kill the
            running process. The run() function will take a few seconds
            longer than 'timeout' to complete if it has to kill the process.
    @param ignore_status: do not raise an exception, no matter what the exit
            code of the command is.
    @param ignore_timeout: If True, timeouts are ignored otherwise if a
            timeout occurs it will raise CmdTimeoutError.
    @param stdout_tee: optional file-like object to which stdout data
            will be written as it is generated (data will still be stored
            in result.stdout).
    @param stderr_tee: likewise for stderr.
    @param verbose: if True, log the command being run.
    @param stdin: stdin to pass to the executed process (can be a file
            descriptor, a file object of a real file or a string).
    @param args: sequence of strings of arguments to be given to the command
            inside " quotes after they have been escaped for that; each
            element in the sequence will be given as a separate command
            argument
    @param nickname: Short string that will appear in logging messages
                     associated with this command.

    @return a CmdResult object or None if the command timed out and
            ignore_timeout is True

    @raise CmdError: the exit code of the command execution was not 0
    @raise CmdTimeoutError: the command timed out and ignore_timeout is False.
    """
    if isinstance(args, basestring):
        raise TypeError('Got a string for the "args" keyword argument, '
                        'need a sequence.')

    # In some cases, command will actually be a list
    # (For example, see get_user_hash in client/cros/cryptohome.py.)
    # So, to cover that case, detect if it's a string or not and convert it
    # into one if necessary.
    if not isinstance(command, basestring):
        command = ' '.join([sh_quote_word(arg) for arg in command])

    command = ' '.join([command] + [sh_quote_word(arg) for arg in args])
    if stderr_is_expected is None:
        stderr_is_expected = ignore_status

    try:
        bg_job = join_bg_jobs(
            (BgJob(command, stdout_tee, stderr_tee, verbose, stdin=stdin,
                   stderr_level=get_stderr_level(stderr_is_expected),
                   nickname=nickname),), timeout)[0]
    except error.CmdTimeoutError:
        if not ignore_timeout:
            raise
        return None

    if not ignore_status and bg_job.result.exit_status:
        raise error.CmdError(command, bg_job.result,
                             "Command returned non-zero exit status")

    return bg_job.result


def run_parallel(commands, timeout=None, ignore_status=False,
                 stdout_tee=None, stderr_tee=None,
                 nicknames=[]):
    """
    Behaves the same as run() with the following exceptions:

    - commands is a list of commands to run in parallel.
    - ignore_status toggles whether or not an exception should be raised
      on any error.

    @return: a list of CmdResult objects
    """
    bg_jobs = []
    for (command, nickname) in itertools.izip_longest(commands, nicknames):
        bg_jobs.append(BgJob(command, stdout_tee, stderr_tee,
                             stderr_level=get_stderr_level(ignore_status),
                             nickname=nickname))

    # Updates objects in bg_jobs list with their process information
    join_bg_jobs(bg_jobs, timeout)

    for bg_job in bg_jobs:
        if not ignore_status and bg_job.result.exit_status:
            raise error.CmdError(command, bg_job.result,
                                 "Command returned non-zero exit status")

    return [bg_job.result for bg_job in bg_jobs]


@deprecated
def run_bg(command):
    """Function deprecated. Please use BgJob class instead."""
    bg_job = BgJob(command)
    return bg_job.sp, bg_job.result


def join_bg_jobs(bg_jobs, timeout=None):
    """Joins the bg_jobs with the current thread.

    Returns the same list of bg_jobs objects that was passed in.
    """
    ret, timeout_error = 0, False
    for bg_job in bg_jobs:
        bg_job.output_prepare(StringIO.StringIO(), StringIO.StringIO())

    try:
        # We are holding ends to stdin, stdout pipes
        # hence we need to be sure to close those fds no mater what
        start_time = time.time()
        timeout_error = _wait_for_commands(bg_jobs, start_time, timeout)

        for bg_job in bg_jobs:
            # Process stdout and stderr
            bg_job.process_output(stdout=True,final_read=True)
            bg_job.process_output(stdout=False,final_read=True)
    finally:
        # close our ends of the pipes to the sp no matter what
        for bg_job in bg_jobs:
            bg_job.cleanup()

    if timeout_error:
        # TODO: This needs to be fixed to better represent what happens when
        # running in parallel. However this is backwards compatable, so it will
        # do for the time being.
        raise error.CmdTimeoutError(
                bg_jobs[0].command, bg_jobs[0].result,
                "Command(s) did not complete within %d seconds" % timeout)


    return bg_jobs


def _wait_for_commands(bg_jobs, start_time, timeout):
    """Waits for background jobs by select polling their stdout/stderr.

    @param bg_jobs: A list of background jobs to wait on.
    @param start_time: Time used to calculate the timeout lifetime of a job.
    @param timeout: The timeout of the list of bg_jobs.

    @return: True if the return was due to a timeout, False otherwise.
    """

    # To check for processes which terminate without producing any output
    # a 1 second timeout is used in select.
    SELECT_TIMEOUT = 1

    read_list = []
    write_list = []
    reverse_dict = {}

    for bg_job in bg_jobs:
        read_list.append(bg_job.sp.stdout)
        read_list.append(bg_job.sp.stderr)
        reverse_dict[bg_job.sp.stdout] = (bg_job, True)
        reverse_dict[bg_job.sp.stderr] = (bg_job, False)
        if bg_job.string_stdin is not None:
            write_list.append(bg_job.sp.stdin)
            reverse_dict[bg_job.sp.stdin] = bg_job

    if timeout:
        stop_time = start_time + timeout
        time_left = stop_time - time.time()
    else:
        time_left = None # so that select never times out

    while not timeout or time_left > 0:
        # select will return when we may write to stdin, when there is
        # stdout/stderr output we can read (including when it is
        # EOF, that is the process has terminated) or when a non-fatal
        # signal was sent to the process. In the last case the select returns
        # EINTR, and we continue waiting for the job if the signal handler for
        # the signal that interrupted the call allows us to.
        try:
            read_ready, write_ready, _ = select.select(read_list, write_list,
                                                       [], SELECT_TIMEOUT)
        except select.error as v:
            if v[0] == errno.EINTR:
                logging.warning(v)
                continue
            else:
                raise
        # os.read() has to be used instead of
        # subproc.stdout.read() which will otherwise block
        for file_obj in read_ready:
            bg_job, is_stdout = reverse_dict[file_obj]
            bg_job.process_output(is_stdout)

        for file_obj in write_ready:
            # we can write PIPE_BUF bytes without blocking
            # POSIX requires PIPE_BUF is >= 512
            bg_job = reverse_dict[file_obj]
            file_obj.write(bg_job.string_stdin[:512])
            bg_job.string_stdin = bg_job.string_stdin[512:]
            # no more input data, close stdin, remove it from the select set
            if not bg_job.string_stdin:
                file_obj.close()
                write_list.remove(file_obj)
                del reverse_dict[file_obj]

        all_jobs_finished = True
        for bg_job in bg_jobs:
            if bg_job.result.exit_status is not None:
                continue

            bg_job.result.exit_status = bg_job.sp.poll()
            if bg_job.result.exit_status is not None:
                # process exited, remove its stdout/stdin from the select set
                bg_job.result.duration = time.time() - start_time
                read_list.remove(bg_job.sp.stdout)
                read_list.remove(bg_job.sp.stderr)
                del reverse_dict[bg_job.sp.stdout]
                del reverse_dict[bg_job.sp.stderr]
            else:
                all_jobs_finished = False

        if all_jobs_finished:
            return False

        if timeout:
            time_left = stop_time - time.time()

    # Kill all processes which did not complete prior to timeout
    for bg_job in bg_jobs:
        if bg_job.result.exit_status is not None:
            continue

        logging.warning('run process timeout (%s) fired on: %s', timeout,
                        bg_job.command)
        if nuke_subprocess(bg_job.sp) is None:
            # If process could not be SIGKILL'd, log kernel stack.
            logging.warning(read_file('/proc/%d/stack' % bg_job.sp.pid))
        bg_job.result.exit_status = bg_job.sp.poll()
        bg_job.result.duration = time.time() - start_time

    return True


def pid_is_alive(pid):
    """
    True if process pid exists and is not yet stuck in Zombie state.
    Zombies are impossible to move between cgroups, etc.
    pid can be integer, or text of integer.
    """
    path = '/proc/%s/stat' % pid

    try:
        stat = read_one_line(path)
    except IOError:
        if not os.path.exists(path):
            # file went away
            return False
        raise

    return stat.split()[2] != 'Z'


def signal_pid(pid, sig):
    """
    Sends a signal to a process id. Returns True if the process terminated
    successfully, False otherwise.
    """
    try:
        os.kill(pid, sig)
    except OSError:
        # The process may have died before we could kill it.
        pass

    for i in range(5):
        if not pid_is_alive(pid):
            return True
        time.sleep(1)

    # The process is still alive
    return False


def nuke_subprocess(subproc):
    # check if the subprocess is still alive, first
    if subproc.poll() is not None:
        return subproc.poll()

    # the process has not terminated within timeout,
    # kill it via an escalating series of signals.
    signal_queue = [signal.SIGTERM, signal.SIGKILL]
    for sig in signal_queue:
        signal_pid(subproc.pid, sig)
        if subproc.poll() is not None:
            return subproc.poll()


def nuke_pid(pid, signal_queue=(signal.SIGTERM, signal.SIGKILL)):
    # the process has not terminated within timeout,
    # kill it via an escalating series of signals.
    pid_path = '/proc/%d/'
    if not os.path.exists(pid_path % pid):
        # Assume that if the pid does not exist in proc it is already dead.
        logging.error('No listing in /proc for pid:%d.', pid)
        raise error.AutoservPidAlreadyDeadError('Could not kill nonexistant '
                                                'pid: %s.', pid)
    for sig in signal_queue:
        if signal_pid(pid, sig):
            return

    # no signal successfully terminated the process
    raise error.AutoservRunError('Could not kill %d for process name: %s' % (
            pid, get_process_name(pid)), None)


def system(command, timeout=None, ignore_status=False):
    """
    Run a command

    @param timeout: timeout in seconds
    @param ignore_status: if ignore_status=False, throw an exception if the
            command's exit code is non-zero
            if ignore_stauts=True, return the exit code.

    @return exit status of command
            (note, this will always be zero unless ignore_status=True)
    """
    return run(command, timeout=timeout, ignore_status=ignore_status,
               stdout_tee=TEE_TO_LOGS, stderr_tee=TEE_TO_LOGS).exit_status


def system_parallel(commands, timeout=None, ignore_status=False):
    """This function returns a list of exit statuses for the respective
    list of commands."""
    return [bg_jobs.exit_status for bg_jobs in
            run_parallel(commands, timeout=timeout, ignore_status=ignore_status,
                         stdout_tee=TEE_TO_LOGS, stderr_tee=TEE_TO_LOGS)]


def system_output(command, timeout=None, ignore_status=False,
                  retain_output=False, args=()):
    """
    Run a command and return the stdout output.

    @param command: command string to execute.
    @param timeout: time limit in seconds before attempting to kill the
            running process. The function will take a few seconds longer
            than 'timeout' to complete if it has to kill the process.
    @param ignore_status: do not raise an exception, no matter what the exit
            code of the command is.
    @param retain_output: set to True to make stdout/stderr of the command
            output to be also sent to the logging system
    @param args: sequence of strings of arguments to be given to the command
            inside " quotes after they have been escaped for that; each
            element in the sequence will be given as a separate command
            argument

    @return a string with the stdout output of the command.
    """
    if retain_output:
        out = run(command, timeout=timeout, ignore_status=ignore_status,
                  stdout_tee=TEE_TO_LOGS, stderr_tee=TEE_TO_LOGS,
                  args=args).stdout
    else:
        out = run(command, timeout=timeout, ignore_status=ignore_status,
                  args=args).stdout
    if out[-1:] == '\n':
        out = out[:-1]
    return out


def system_output_parallel(commands, timeout=None, ignore_status=False,
                           retain_output=False):
    if retain_output:
        out = [bg_job.stdout for bg_job
               in run_parallel(commands, timeout=timeout,
                               ignore_status=ignore_status,
                               stdout_tee=TEE_TO_LOGS, stderr_tee=TEE_TO_LOGS)]
    else:
        out = [bg_job.stdout for bg_job in run_parallel(commands,
                                  timeout=timeout, ignore_status=ignore_status)]
    for x in out:
        if out[-1:] == '\n': out = out[:-1]
    return out


def strip_unicode(input):
    if type(input) == list:
        return [strip_unicode(i) for i in input]
    elif type(input) == dict:
        output = {}
        for key in input.keys():
            output[str(key)] = strip_unicode(input[key])
        return output
    elif type(input) == unicode:
        return str(input)
    else:
        return input


def get_cpu_percentage(function, *args, **dargs):
    """Returns a tuple containing the CPU% and return value from function call.

    This function calculates the usage time by taking the difference of
    the user and system times both before and after the function call.
    """
    child_pre = resource.getrusage(resource.RUSAGE_CHILDREN)
    self_pre = resource.getrusage(resource.RUSAGE_SELF)
    start = time.time()
    to_return = function(*args, **dargs)
    elapsed = time.time() - start
    self_post = resource.getrusage(resource.RUSAGE_SELF)
    child_post = resource.getrusage(resource.RUSAGE_CHILDREN)

    # Calculate CPU Percentage
    s_user, s_system = [a - b for a, b in zip(self_post, self_pre)[:2]]
    c_user, c_system = [a - b for a, b in zip(child_post, child_pre)[:2]]
    cpu_percent = (s_user + c_user + s_system + c_system) / elapsed

    return cpu_percent, to_return


class SystemLoad(object):
    """
    Get system and/or process values and return average value of load.
    """
    def __init__(self, pids, advanced=False, time_step=0.1, cpu_cont=False,
                 use_log=False):
        """
        @param pids: List of pids to be monitored. If pid = 0 whole system will
          be monitored. pid == 0 means whole system.
        @param advanced: monitor add value for system irq count and softirq
          for process minor and maior page fault
        @param time_step: Time step for continuous monitoring.
        @param cpu_cont: If True monitor CPU load continuously.
        @param use_log: If true every monitoring is logged for dump.
        """
        self.pids = []
        self.stats = {}
        for pid in pids:
            if pid == 0:
                cpu = FileFieldMonitor("/proc/stat",
                                       [("cpu", 0), # User Time
                                        ("cpu", 2), # System Time
                                        ("intr", 0), # IRQ Count
                                        ("softirq", 0)], # Soft IRQ Count
                                       True,
                                       cpu_cont,
                                       use_log,
                                       " +",
                                       time_step)
                mem = FileFieldMonitor("/proc/meminfo",
                                       [("MemTotal:", 0), # Mem Total
                                        ("MemFree:", 0), # Mem Free
                                        ("Buffers:", 0), # Buffers
                                        ("Cached:", 0)], # Cached
                                       False,
                                       True,
                                       use_log,
                                       " +",
                                       time_step)
                self.stats[pid] = ["TOTAL", cpu, mem]
                self.pids.append(pid)
            else:
                name = ""
                if (type(pid) is int):
                    self.pids.append(pid)
                    name = get_process_name(pid)
                else:
                    self.pids.append(pid[0])
                    name = pid[1]

                cpu = FileFieldMonitor("/proc/%d/stat" %
                                       self.pids[-1],
                                       [("", 13), # User Time
                                        ("", 14), # System Time
                                        ("", 9), # Minority Page Fault
                                        ("", 11)], # Majority Page Fault
                                       True,
                                       cpu_cont,
                                       use_log,
                                       " +",
                                       time_step)
                mem = FileFieldMonitor("/proc/%d/status" %
                                       self.pids[-1],
                                       [("VmSize:", 0), # Virtual Memory Size
                                        ("VmRSS:", 0), # Resident Set Size
                                        ("VmPeak:", 0), # Peak VM Size
                                        ("VmSwap:", 0)], # VM in Swap
                                       False,
                                       True,
                                       use_log,
                                       " +",
                                       time_step)
                self.stats[self.pids[-1]] = [name, cpu, mem]

        self.advanced = advanced


    def __str__(self):
        """
        Define format how to print
        """
        out = ""
        for pid in self.pids:
            for stat in self.stats[pid][1:]:
                out += str(stat.get_status()) + "\n"
        return out


    def start(self, pids=[]):
        """
        Start monitoring of the process system usage.
        @param pids: List of PIDs you intend to control. Use pids=[] to control
            all defined PIDs.
        """
        if pids == []:
            pids = self.pids

        for pid in pids:
            for stat in self.stats[pid][1:]:
                stat.start()


    def stop(self, pids=[]):
        """
        Stop monitoring of the process system usage.
        @param pids: List of PIDs you intend to control. Use pids=[] to control
            all defined PIDs.
        """
        if pids == []:
            pids = self.pids

        for pid in pids:
            for stat in self.stats[pid][1:]:
                stat.stop()


    def dump(self, pids=[]):
        """
        Get the status of monitoring.
        @param pids: List of PIDs you intend to control. Use pids=[] to control
            all defined PIDs.
         @return:
            tuple([cpu load], [memory load]):
                ([(PID1, (PID1_cpu_meas)), (PID2, (PID2_cpu_meas)), ...],
                 [(PID1, (PID1_mem_meas)), (PID2, (PID2_mem_meas)), ...])

            PID1_cpu_meas:
                average_values[], test_time, cont_meas_values[[]], time_step
            PID1_mem_meas:
                average_values[], test_time, cont_meas_values[[]], time_step
            where average_values[] are the measured values (mem_free,swap,...)
            which are described in SystemLoad.__init__()-FileFieldMonitor.
            cont_meas_values[[]] is a list of average_values in the sampling
            times.
        """
        if pids == []:
            pids = self.pids

        cpus = []
        memory = []
        for pid in pids:
            stat = (pid, self.stats[pid][1].get_status())
            cpus.append(stat)
        for pid in pids:
            stat = (pid, self.stats[pid][2].get_status())
            memory.append(stat)

        return (cpus, memory)


    def get_cpu_status_string(self, pids=[]):
        """
        Convert status to string array.
        @param pids: List of PIDs you intend to control. Use pids=[] to control
            all defined PIDs.
        @return: String format to table.
        """
        if pids == []:
            pids = self.pids

        headers = ["NAME",
                   ("%7s") % "PID",
                   ("%5s") % "USER",
                   ("%5s") % "SYS",
                   ("%5s") % "SUM"]
        if self.advanced:
            headers.extend(["MINFLT/IRQC",
                            "MAJFLT/SOFTIRQ"])
        headers.append(("%11s") % "TIME")
        textstatus = []
        for pid in pids:
            stat = self.stats[pid][1].get_status()
            time = stat[1]
            stat = stat[0]
            textstatus.append(["%s" % self.stats[pid][0],
                               "%7s" % pid,
                               "%4.0f%%" % (stat[0] / time),
                               "%4.0f%%" % (stat[1] / time),
                               "%4.0f%%" % ((stat[0] + stat[1]) / time),
                               "%10.3fs" % time])
            if self.advanced:
                textstatus[-1].insert(-1, "%11d" % stat[2])
                textstatus[-1].insert(-1, "%14d" % stat[3])

        return matrix_to_string(textstatus, tuple(headers))


    def get_mem_status_string(self, pids=[]):
        """
        Convert status to string array.
        @param pids: List of PIDs you intend to control. Use pids=[] to control
            all defined PIDs.
        @return: String format to table.
        """
        if pids == []:
            pids = self.pids

        headers = ["NAME",
                   ("%7s") % "PID",
                   ("%8s") % "TOTAL/VMSIZE",
                   ("%8s") % "FREE/VMRSS",
                   ("%8s") % "BUFFERS/VMPEAK",
                   ("%8s") % "CACHED/VMSWAP",
                   ("%11s") % "TIME"]
        textstatus = []
        for pid in pids:
            stat = self.stats[pid][2].get_status()
            time = stat[1]
            stat = stat[0]
            textstatus.append(["%s" % self.stats[pid][0],
                               "%7s" % pid,
                               "%10dMB" % (stat[0] / 1024),
                               "%8dMB" % (stat[1] / 1024),
                               "%12dMB" % (stat[2] / 1024),
                               "%11dMB" % (stat[3] / 1024),
                               "%10.3fs" % time])

        return matrix_to_string(textstatus, tuple(headers))


def get_arch(run_function=run):
    """
    Get the hardware architecture of the machine.
    If specified, run_function should return a CmdResult object and throw a
    CmdError exception.
    If run_function is anything other than utils.run(), it is used to
    execute the commands. By default (when set to utils.run()) this will
    just examine os.uname()[4].
    """

    # Short circuit from the common case.
    if run_function == run:
        return re.sub(r'i\d86$', 'i386', os.uname()[4])

    # Otherwise, use the run_function in case it hits a remote machine.
    arch = run_function('/bin/uname -m').stdout.rstrip()
    if re.match(r'i\d86$', arch):
        arch = 'i386'
    return arch

def get_arch_userspace(run_function=run):
    """
    Get the architecture by userspace (possibly different from kernel).
    """
    archs = {
        'arm': 'ELF 32-bit.*, ARM,',
        'i386': 'ELF 32-bit.*, Intel 80386,',
        'x86_64': 'ELF 64-bit.*, x86-64,',
    }

    cmd = 'file --brief --dereference /bin/sh'
    filestr = run_function(cmd).stdout.rstrip()
    for a, regex in archs.iteritems():
        if re.match(regex, filestr):
            return a

    return get_arch()


def get_num_logical_cpus_per_socket(run_function=run):
    """
    Get the number of cores (including hyperthreading) per cpu.
    run_function is used to execute the commands. It defaults to
    utils.run() but a custom method (if provided) should be of the
    same schema as utils.run. It should return a CmdResult object and
    throw a CmdError exception.
    """
    siblings = run_function('grep "^siblings" /proc/cpuinfo').stdout.rstrip()
    num_siblings = map(int,
                       re.findall(r'^siblings\s*:\s*(\d+)\s*$',
                                  siblings, re.M))
    if len(num_siblings) == 0:
        raise error.TestError('Unable to find siblings info in /proc/cpuinfo')
    if min(num_siblings) != max(num_siblings):
        raise error.TestError('Number of siblings differ %r' %
                              num_siblings)
    return num_siblings[0]


def merge_trees(src, dest):
    """
    Merges a source directory tree at 'src' into a destination tree at
    'dest'. If a path is a file in both trees than the file in the source
    tree is APPENDED to the one in the destination tree. If a path is
    a directory in both trees then the directories are recursively merged
    with this function. In any other case, the function will skip the
    paths that cannot be merged (instead of failing).
    """
    if not os.path.exists(src):
        return # exists only in dest
    elif not os.path.exists(dest):
        if os.path.isfile(src):
            shutil.copy2(src, dest) # file only in src
        else:
            shutil.copytree(src, dest, symlinks=True) # dir only in src
        return
    elif os.path.isfile(src) and os.path.isfile(dest):
        # src & dest are files in both trees, append src to dest
        destfile = open(dest, "a")
        try:
            srcfile = open(src)
            try:
                destfile.write(srcfile.read())
            finally:
                srcfile.close()
        finally:
            destfile.close()
    elif os.path.isdir(src) and os.path.isdir(dest):
        # src & dest are directories in both trees, so recursively merge
        for name in os.listdir(src):
            merge_trees(os.path.join(src, name), os.path.join(dest, name))
    else:
        # src & dest both exist, but are incompatible
        return


class CmdResult(object):
    """
    Command execution result.

    command:     String containing the command line itself
    exit_status: Integer exit code of the process
    stdout:      String containing stdout of the process
    stderr:      String containing stderr of the process
    duration:    Elapsed wall clock time running the process
    """


    def __init__(self, command="", stdout="", stderr="",
                 exit_status=None, duration=0):
        self.command = command
        self.exit_status = exit_status
        self.stdout = stdout
        self.stderr = stderr
        self.duration = duration


    def __repr__(self):
        wrapper = textwrap.TextWrapper(width = 78,
                                       initial_indent="\n    ",
                                       subsequent_indent="    ")

        stdout = self.stdout.rstrip()
        if stdout:
            stdout = "\nstdout:\n%s" % stdout

        stderr = self.stderr.rstrip()
        if stderr:
            stderr = "\nstderr:\n%s" % stderr

        return ("* Command: %s\n"
                "Exit status: %s\n"
                "Duration: %s\n"
                "%s"
                "%s"
                % (wrapper.fill(str(self.command)), self.exit_status,
                self.duration, stdout, stderr))


class run_randomly:
    def __init__(self, run_sequentially=False):
        # Run sequentially is for debugging control files
        self.test_list = []
        self.run_sequentially = run_sequentially


    def add(self, *args, **dargs):
        test = (args, dargs)
        self.test_list.append(test)


    def run(self, fn):
        while self.test_list:
            test_index = random.randint(0, len(self.test_list)-1)
            if self.run_sequentially:
                test_index = 0
            (args, dargs) = self.test_list.pop(test_index)
            fn(*args, **dargs)


def import_site_module(path, module, dummy=None, modulefile=None):
    """
    Try to import the site specific module if it exists.

    @param path full filename of the source file calling this (ie __file__)
    @param module full module name
    @param dummy dummy value to return in case there is no symbol to import
    @param modulefile module filename

    @return site specific module or dummy

    @raises ImportError if the site file exists but imports fails
    """
    short_module = module[module.rfind(".") + 1:]

    if not modulefile:
        modulefile = short_module + ".py"

    if os.path.exists(os.path.join(os.path.dirname(path), modulefile)):
        return __import__(module, {}, {}, [short_module])
    return dummy


def import_site_symbol(path, module, name, dummy=None, modulefile=None):
    """
    Try to import site specific symbol from site specific file if it exists

    @param path full filename of the source file calling this (ie __file__)
    @param module full module name
    @param name symbol name to be imported from the site file
    @param dummy dummy value to return in case there is no symbol to import
    @param modulefile module filename

    @return site specific symbol or dummy

    @raises ImportError if the site file exists but imports fails
    """
    module = import_site_module(path, module, modulefile=modulefile)
    if not module:
        return dummy

    # special unique value to tell us if the symbol can't be imported
    cant_import = object()

    obj = getattr(module, name, cant_import)
    if obj is cant_import:
        return dummy

    return obj


def import_site_class(path, module, classname, baseclass, modulefile=None):
    """
    Try to import site specific class from site specific file if it exists

    Args:
        path: full filename of the source file calling this (ie __file__)
        module: full module name
        classname: class name to be loaded from site file
        baseclass: base class object to return when no site file present or
            to mixin when site class exists but is not inherited from baseclass
        modulefile: module filename

    Returns: baseclass if site specific class does not exist, the site specific
        class if it exists and is inherited from baseclass or a mixin of the
        site specific class and baseclass when the site specific class exists
        and is not inherited from baseclass

    Raises: ImportError if the site file exists but imports fails
    """

    res = import_site_symbol(path, module, classname, None, modulefile)
    if res:
        if not issubclass(res, baseclass):
            # if not a subclass of baseclass then mix in baseclass with the
            # site specific class object and return the result
            res = type(classname, (res, baseclass), {})
    else:
        res = baseclass

    return res


def import_site_function(path, module, funcname, dummy, modulefile=None):
    """
    Try to import site specific function from site specific file if it exists

    Args:
        path: full filename of the source file calling this (ie __file__)
        module: full module name
        funcname: function name to be imported from site file
        dummy: dummy function to return in case there is no function to import
        modulefile: module filename

    Returns: site specific function object or dummy

    Raises: ImportError if the site file exists but imports fails
    """

    return import_site_symbol(path, module, funcname, dummy, modulefile)


def _get_pid_path(program_name):
    my_path = os.path.dirname(__file__)
    return os.path.abspath(os.path.join(my_path, "..", "..",
                                        "%s.pid" % program_name))


def write_pid(program_name):
    """
    Try to drop <program_name>.pid in the main autotest directory.

    Args:
      program_name: prefix for file name
    """
    pidfile = open(_get_pid_path(program_name), "w")
    try:
        pidfile.write("%s\n" % os.getpid())
    finally:
        pidfile.close()


def delete_pid_file_if_exists(program_name):
    """
    Tries to remove <program_name>.pid from the main autotest directory.
    """
    pidfile_path = _get_pid_path(program_name)

    try:
        os.remove(pidfile_path)
    except OSError:
        if not os.path.exists(pidfile_path):
            return
        raise


def get_pid_from_file(program_name):
    """
    Reads the pid from <program_name>.pid in the autotest directory.

    @param program_name the name of the program
    @return the pid if the file exists, None otherwise.
    """
    pidfile_path = _get_pid_path(program_name)
    if not os.path.exists(pidfile_path):
        return None

    pidfile = open(_get_pid_path(program_name), 'r')

    try:
        try:
            pid = int(pidfile.readline())
        except IOError:
            if not os.path.exists(pidfile_path):
                return None
            raise
    finally:
        pidfile.close()

    return pid


def get_process_name(pid):
    """
    Get process name from PID.
    @param pid: PID of process.
    @return: Process name if PID stat file exists or 'Dead PID' if it does not.
    """
    pid_stat_path = "/proc/%d/stat"
    if not os.path.exists(pid_stat_path % pid):
        return "Dead Pid"
    return get_field(read_file(pid_stat_path % pid), 1)[1:-1]


def program_is_alive(program_name):
    """
    Checks if the process is alive and not in Zombie state.

    @param program_name the name of the program
    @return True if still alive, False otherwise
    """
    pid = get_pid_from_file(program_name)
    if pid is None:
        return False
    return pid_is_alive(pid)


def signal_program(program_name, sig=signal.SIGTERM):
    """
    Sends a signal to the process listed in <program_name>.pid

    @param program_name the name of the program
    @param sig signal to send
    """
    pid = get_pid_from_file(program_name)
    if pid:
        signal_pid(pid, sig)


def get_relative_path(path, reference):
    """Given 2 absolute paths "path" and "reference", compute the path of
    "path" as relative to the directory "reference".

    @param path the absolute path to convert to a relative path
    @param reference an absolute directory path to which the relative
        path will be computed
    """
    # normalize the paths (remove double slashes, etc)
    assert(os.path.isabs(path))
    assert(os.path.isabs(reference))

    path = os.path.normpath(path)
    reference = os.path.normpath(reference)

    # we could use os.path.split() but it splits from the end
    path_list = path.split(os.path.sep)[1:]
    ref_list = reference.split(os.path.sep)[1:]

    # find the longest leading common path
    for i in xrange(min(len(path_list), len(ref_list))):
        if path_list[i] != ref_list[i]:
            # decrement i so when exiting this loop either by no match or by
            # end of range we are one step behind
            i -= 1
            break
    i += 1
    # drop the common part of the paths, not interested in that anymore
    del path_list[:i]

    # for each uncommon component in the reference prepend a ".."
    path_list[:0] = ['..'] * (len(ref_list) - i)

    return os.path.join(*path_list)


def sh_escape(command):
    """
    Escape special characters from a command so that it can be passed
    as a double quoted (" ") string in a (ba)sh command.

    Args:
            command: the command string to escape.

    Returns:
            The escaped command string. The required englobing double
            quotes are NOT added and so should be added at some point by
            the caller.

    See also: http://www.tldp.org/LDP/abs/html/escapingsection.html
    """
    command = command.replace("\\", "\\\\")
    command = command.replace("$", r'\$')
    command = command.replace('"', r'\"')
    command = command.replace('`', r'\`')
    return command


def sh_quote_word(text, whitelist=SHELL_QUOTING_WHITELIST):
    r"""Quote a string to make it safe as a single word in a shell command.

    POSIX shell syntax recognizes no escape characters inside a single-quoted
    string.  So, single quotes can safely quote any string of characters except
    a string with a single quote character.  A single quote character must be
    quoted with the sequence '\'' which translates to:
        '  -> close current quote
        \' -> insert a literal single quote
        '  -> reopen quoting again.

    This is safe for all combinations of characters, including embedded and
    trailing backslashes in odd or even numbers.

    This is also safe for nesting, e.g. the following is a valid use:

        adb_command = 'adb shell %s' % (
                sh_quote_word('echo %s' % sh_quote_word('hello world')))

    @param text: The string to be quoted into a single word for the shell.
    @param whitelist: Optional list of characters that do not need quoting.
                      Defaults to a known good list of characters.

    @return A string, possibly quoted, safe as a single word for a shell.
    """
    if all(c in whitelist for c in text):
        return text
    return "'" + text.replace("'", r"'\''") + "'"


def configure(extra=None, configure='./configure'):
    """
    Run configure passing in the correct host, build, and target options.

    @param extra: extra command line arguments to pass to configure
    @param configure: which configure script to use
    """
    args = []
    if 'CHOST' in os.environ:
        args.append('--host=' + os.environ['CHOST'])
    if 'CBUILD' in os.environ:
        args.append('--build=' + os.environ['CBUILD'])
    if 'CTARGET' in os.environ:
        args.append('--target=' + os.environ['CTARGET'])
    if extra:
        args.append(extra)

    system('%s %s' % (configure, ' '.join(args)))


def make(extra='', make='make', timeout=None, ignore_status=False):
    """
    Run make, adding MAKEOPTS to the list of options.

    @param extra: extra command line arguments to pass to make.
    """
    cmd = '%s %s %s' % (make, os.environ.get('MAKEOPTS', ''), extra)
    return system(cmd, timeout=timeout, ignore_status=ignore_status)


def compare_versions(ver1, ver2):
    """Version number comparison between ver1 and ver2 strings.

    >>> compare_tuple("1", "2")
    -1
    >>> compare_tuple("foo-1.1", "foo-1.2")
    -1
    >>> compare_tuple("1.2", "1.2a")
    -1
    >>> compare_tuple("1.2b", "1.2a")
    1
    >>> compare_tuple("1.3.5.3a", "1.3.5.3b")
    -1

    Args:
        ver1: version string
        ver2: version string

    Returns:
        int:  1 if ver1 >  ver2
              0 if ver1 == ver2
             -1 if ver1 <  ver2
    """
    ax = re.split('[.-]', ver1)
    ay = re.split('[.-]', ver2)
    while len(ax) > 0 and len(ay) > 0:
        cx = ax.pop(0)
        cy = ay.pop(0)
        maxlen = max(len(cx), len(cy))
        c = cmp(cx.zfill(maxlen), cy.zfill(maxlen))
        if c != 0:
            return c
    return cmp(len(ax), len(ay))


def args_to_dict(args):
    """Convert autoserv extra arguments in the form of key=val or key:val to a
    dictionary.  Each argument key is converted to lowercase dictionary key.

    Args:
        args - list of autoserv extra arguments.

    Returns:
        dictionary
    """
    arg_re = re.compile(r'(\w+)[:=](.*)$')
    dict = {}
    for arg in args:
        match = arg_re.match(arg)
        if match:
            dict[match.group(1).lower()] = match.group(2)
        else:
            logging.warning("args_to_dict: argument '%s' doesn't match "
                            "'%s' pattern. Ignored.", arg, arg_re.pattern)
    return dict


def get_unused_port():
    """
    Finds a semi-random available port. A race condition is still
    possible after the port number is returned, if another process
    happens to bind it.

    Returns:
        A port number that is unused on both TCP and UDP.
    """

    def try_bind(port, socket_type, socket_proto):
        s = socket.socket(socket.AF_INET, socket_type, socket_proto)
        try:
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('', port))
                return s.getsockname()[1]
            except socket.error:
                return None
        finally:
            s.close()

    # On the 2.6 kernel, calling try_bind() on UDP socket returns the
    # same port over and over. So always try TCP first.
    while True:
        # Ask the OS for an unused port.
        port = try_bind(0, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        # Check if this port is unused on the other protocol.
        if port and try_bind(port, socket.SOCK_DGRAM, socket.IPPROTO_UDP):
            return port


def ask(question, auto=False):
    """
    Raw input with a prompt that emulates logging.

    @param question: Question to be asked
    @param auto: Whether to return "y" instead of asking the question
    """
    if auto:
        logging.info("%s (y/n) y", question)
        return "y"
    return raw_input("%s INFO | %s (y/n) " %
                     (time.strftime("%H:%M:%S", time.localtime()), question))


def rdmsr(address, cpu=0):
    """
    Reads an x86 MSR from the specified CPU, returns as long integer.
    """
    with open('/dev/cpu/%s/msr' % cpu, 'r', 0) as fd:
        fd.seek(address)
        return struct.unpack('=Q', fd.read(8))[0]


def wait_for_value(func,
                   expected_value=None,
                   min_threshold=None,
                   max_threshold=None,
                   timeout_sec=10):
    """
    Returns the value of func().  If |expected_value|, |min_threshold|, and
    |max_threshold| are not set, returns immediately.

    If |expected_value| is set, polls the return value until |expected_value| is
    reached, and returns that value.

    If either |max_threshold| or |min_threshold| is set, this function will
    will repeatedly call func() until the return value reaches or exceeds one of
    these thresholds.

    Polling will stop after |timeout_sec| regardless of these thresholds.

    @param func: function whose return value is to be waited on.
    @param expected_value: wait for func to return this value.
    @param min_threshold: wait for func value to reach or fall below this value.
    @param max_threshold: wait for func value to reach or rise above this value.
    @param timeout_sec: Number of seconds to wait before giving up and
                        returning whatever value func() last returned.

    Return value:
        The most recent return value of func().
    """
    value = None
    start_time_sec = time.time()
    while True:
        value = func()
        if (expected_value is None and \
            min_threshold is None and \
            max_threshold is None) or \
           (expected_value is not None and value == expected_value) or \
           (min_threshold is not None and value <= min_threshold) or \
           (max_threshold is not None and value >= max_threshold):
            break

        if time.time() - start_time_sec >= timeout_sec:
            break
        time.sleep(0.1)

    return value


def wait_for_value_changed(func,
                           old_value=None,
                           timeout_sec=10):
    """
    Returns the value of func().

    The function polls the return value until it is different from |old_value|,
    and returns that value.

    Polling will stop after |timeout_sec|.

    @param func: function whose return value is to be waited on.
    @param old_value: wait for func to return a value different from this.
    @param timeout_sec: Number of seconds to wait before giving up and
                        returning whatever value func() last returned.

    @returns The most recent return value of func().
    """
    value = None
    start_time_sec = time.time()
    while True:
        value = func()
        if value != old_value:
            break

        if time.time() - start_time_sec >= timeout_sec:
            break
        time.sleep(0.1)

    return value


def restart_job(name):
    """
    Restarts an upstart job if it's running.
    If it's not running, start it.
    """

    if system_output('status %s' % name).find('start/running') != -1:
        system_output('restart %s' % name)
    else:
        system_output('start %s' % name)


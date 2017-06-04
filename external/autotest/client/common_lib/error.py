#pylint: disable-msg=C0111

"""
Internal global error types
"""

import sys, traceback, threading
from traceback import format_exception

# Add names you want to be imported by 'from errors import *' to this list.
# This must be list not a tuple as we modify it to include all of our
# the Exception classes we define below at the end of this file.
__all__ = ['format_error', 'context_aware', 'context', 'get_context',
           'exception_context']


def format_error():
    t, o, tb = sys.exc_info()
    trace = format_exception(t, o, tb)
    # Clear the backtrace to prevent a circular reference
    # in the heap -- as per tutorial
    tb = ''

    return ''.join(trace)


# Exception context information:
# ------------------------------
# Every function can have some context string associated with it.
# The context string can be changed by calling context(str) and cleared by
# calling context() with no parameters.
# get_context() joins the current context strings of all functions in the
# provided traceback.  The result is a brief description of what the test was
# doing in the provided traceback (which should be the traceback of a caught
# exception).
#
# For example: assume a() calls b() and b() calls c().
#
# @error.context_aware
# def a():
#     error.context("hello")
#     b()
#     error.context("world")
#     error.get_context() ----> 'world'
#
# @error.context_aware
# def b():
#     error.context("foo")
#     c()
#
# @error.context_aware
# def c():
#     error.context("bar")
#     error.get_context() ----> 'hello --> foo --> bar'
#
# The current context is automatically inserted into exceptions raised in
# context_aware functions, so usually test code doesn't need to call
# error.get_context().

ctx = threading.local()


def _new_context(s=""):
    if not hasattr(ctx, "contexts"):
        ctx.contexts = []
    ctx.contexts.append(s)


def _pop_context():
    ctx.contexts.pop()


def context(s="", log=None):
    """
    Set the context for the currently executing function and optionally log it.

    @param s: A string.  If not provided, the context for the current function
            will be cleared.
    @param log: A logging function to pass the context message to.  If None, no
            function will be called.
    """
    ctx.contexts[-1] = s
    if s and log:
        log("Context: %s" % get_context())


def base_context(s="", log=None):
    """
    Set the base context for the currently executing function and optionally
    log it.  The base context is just another context level that is hidden by
    default.  Functions that require a single context level should not use
    base_context().

    @param s: A string.  If not provided, the base context for the current
            function will be cleared.
    @param log: A logging function to pass the context message to.  If None, no
            function will be called.
    """
    ctx.contexts[-1] = ""
    ctx.contexts[-2] = s
    if s and log:
        log("Context: %s" % get_context())


def get_context():
    """Return the current context (or None if none is defined)."""
    if hasattr(ctx, "contexts"):
        return " --> ".join([s for s in ctx.contexts if s])


def exception_context(e):
    """Return the context of a given exception (or None if none is defined)."""
    if hasattr(e, "_context"):
        return e._context  # pylint: disable=W0212


def set_exception_context(e, s):
    """Set the context of a given exception."""
    e._context = s


def join_contexts(s1, s2):
    """Join two context strings."""
    if s1:
        if s2:
            return "%s --> %s" % (s1, s2)
        else:
            return s1
    else:
        return s2


def context_aware(fn):
    """A decorator that must be applied to functions that call context()."""
    def new_fn(*args, **kwargs):
        _new_context()
        _new_context("(%s)" % fn.__name__)
        try:
            try:
                return fn(*args, **kwargs)
            except Exception, e:
                if not exception_context(e):
                    set_exception_context(e, get_context())
                raise
        finally:
            _pop_context()
            _pop_context()
    new_fn.__name__ = fn.__name__
    new_fn.__doc__ = fn.__doc__
    new_fn.__dict__.update(fn.__dict__)
    return new_fn


def _context_message(e):
    s = exception_context(e)
    if s:
        return "    [context: %s]" % s
    else:
        return ""



class TimeoutException(Exception):
    """
    Generic exception raised on retry timeouts.
    """
    pass


class JobContinue(SystemExit):
    """Allow us to bail out requesting continuance."""
    pass


class JobComplete(SystemExit):
    """Allow us to bail out indicating continuation not required."""
    pass


class AutotestError(Exception):
    """The parent of all errors deliberatly thrown within the client code."""
    def __str__(self):
        return Exception.__str__(self) + _context_message(self)


class JobError(AutotestError):
    """Indicates an error which terminates and fails the whole job (ABORT)."""
    pass


class UnhandledJobError(JobError):
    """Indicates an unhandled error in a job."""
    def __init__(self, unhandled_exception):
        if isinstance(unhandled_exception, JobError):
            JobError.__init__(self, *unhandled_exception.args)
        elif isinstance(unhandled_exception, str):
            JobError.__init__(self, unhandled_exception)
        else:
            msg = "Unhandled %s: %s"
            msg %= (unhandled_exception.__class__.__name__,
                    unhandled_exception)
            if not isinstance(unhandled_exception, AutotestError):
                msg += _context_message(unhandled_exception)
            msg += "\n" + traceback.format_exc()
            JobError.__init__(self, msg)


class TestBaseException(AutotestError):
    """The parent of all test exceptions."""
    # Children are required to override this.  Never instantiate directly.
    exit_status = "NEVER_RAISE_THIS"


class TestError(TestBaseException):
    """Indicates that something went wrong with the test harness itself."""
    exit_status = "ERROR"


class TestNAError(TestBaseException):
    """Indictates that the test is Not Applicable.  Should be thrown
    when various conditions are such that the test is inappropriate."""
    exit_status = "TEST_NA"


class TestFail(TestBaseException):
    """Indicates that the test failed, but the job will not continue."""
    exit_status = "FAIL"


class TestWarn(TestBaseException):
    """Indicates that bad things (may) have happened, but not an explicit
    failure."""
    exit_status = "WARN"


class TestFailRetry(TestFail):
    """Indicates that the test failed, but in a manner that may be retried
    if test retries are enabled for this test."""
    exit_status = "FAIL"


class UnhandledTestError(TestError):
    """Indicates an unhandled error in a test."""
    def __init__(self, unhandled_exception):
        if isinstance(unhandled_exception, TestError):
            TestError.__init__(self, *unhandled_exception.args)
        elif isinstance(unhandled_exception, str):
            TestError.__init__(self, unhandled_exception)
        else:
            msg = "Unhandled %s: %s"
            msg %= (unhandled_exception.__class__.__name__,
                    unhandled_exception)
            if not isinstance(unhandled_exception, AutotestError):
                msg += _context_message(unhandled_exception)
            msg += "\n" + traceback.format_exc()
            TestError.__init__(self, msg)


class UnhandledTestFail(TestFail):
    """Indicates an unhandled fail in a test."""
    def __init__(self, unhandled_exception):
        if isinstance(unhandled_exception, TestFail):
            TestFail.__init__(self, *unhandled_exception.args)
        elif isinstance(unhandled_exception, str):
            TestFail.__init__(self, unhandled_exception)
        else:
            msg = "Unhandled %s: %s"
            msg %= (unhandled_exception.__class__.__name__,
                    unhandled_exception)
            if not isinstance(unhandled_exception, AutotestError):
                msg += _context_message(unhandled_exception)
            msg += "\n" + traceback.format_exc()
            TestFail.__init__(self, msg)


class CmdError(TestError):
    """Indicates that a command failed, is fatal to the test unless caught."""
    def __init__(self, command, result_obj, additional_text=None):
        TestError.__init__(self, command, result_obj, additional_text)
        self.command = command
        self.result_obj = result_obj
        self.additional_text = additional_text

    def __str__(self):
        if self.result_obj.exit_status is None:
            msg = "Command <%s> failed and is not responding to signals"
            msg %= self.command
        else:
            msg = "Command <%s> failed, rc=%d"
            msg %= (self.command, self.result_obj.exit_status)

        if self.additional_text:
            msg += ", " + self.additional_text
        msg += _context_message(self)
        msg += '\n' + repr(self.result_obj)
        return msg


class CmdTimeoutError(CmdError):
    """Indicates that a command timed out."""
    pass


class PackageError(TestError):
    """Indicates an error trying to perform a package operation."""
    pass


class BarrierError(JobError):
    """Indicates an error happened during a barrier operation."""
    pass


class BarrierAbortError(BarrierError):
    """Indicate that the barrier was explicitly aborted by a member."""
    pass


class InstallError(JobError):
    """Indicates an installation error which Terminates and fails the job."""
    pass


class AutotestRunError(AutotestError):
    """Indicates a problem running server side control files."""
    pass


class AutotestTimeoutError(AutotestError):
    """This exception is raised when an autotest test exceeds the timeout
    parameter passed to run_timed_test and is killed.
    """
    pass


class HostRunErrorMixIn(Exception):
    """
    Indicates a problem in the host run() function raised from client code.
    Should always be constructed with a tuple of two args (error description
    (str), run result object). This is a common class mixed in to create the
    client and server side versions of it.
    """
    def __init__(self, description, result_obj):
        self.description = description
        self.result_obj = result_obj
        Exception.__init__(self, description, result_obj)

    def __str__(self):
        return self.description + '\n' + repr(self.result_obj)


class HostInstallTimeoutError(JobError):
    """
    Indicates the machine failed to be installed after the predetermined
    timeout.
    """
    pass


class AutotestHostRunError(HostRunErrorMixIn, AutotestError):
    pass


# server-specific errors

class AutoservError(Exception):
    pass


class AutoservSSHTimeout(AutoservError):
    """SSH experienced a connection timeout"""
    pass


class AutoservRunError(HostRunErrorMixIn, AutoservError):
    pass


class AutoservSshPermissionDeniedError(AutoservRunError):
    """Indicates that a SSH permission denied error was encountered."""
    pass


class AutoservVirtError(AutoservError):
    """Vitualization related error"""
    pass


class AutoservUnsupportedError(AutoservError):
    """Error raised when you try to use an unsupported optional feature"""
    pass


class AutoservHostError(AutoservError):
    """Error reaching a host"""
    pass


class AutoservHostIsShuttingDownError(AutoservHostError):
    """Host is shutting down"""
    pass


class AutoservNotMountedHostError(AutoservHostError):
    """Found unmounted partitions that should be mounted"""
    pass


class AutoservSshPingHostError(AutoservHostError):
    """SSH ping failed"""
    pass


class AutoservDiskFullHostError(AutoservHostError):
    """Not enough free disk space on host"""

    def __init__(self, path, want_gb, free_space_gb):
        super(AutoservDiskFullHostError, self).__init__(
            'Not enough free space on %s - %.3fGB free, want %.3fGB' %
                    (path, free_space_gb, want_gb))
        self.path = path
        self.want_gb = want_gb
        self.free_space_gb = free_space_gb


class AutoservNoFreeInodesError(AutoservHostError):
    """Not enough free i-nodes on host"""

    def __init__(self, path, want_inodes, free_inodes):
        super(AutoservNoFreeInodesError, self).__init__(
            'Not enough free inodes on %s - %d free, want %d' %
                    (path, free_inodes, want_inodes))
        self.path = path
        self.want_inodes = want_inodes
        self.free_inodes = free_inodes


class AutoservHardwareHostError(AutoservHostError):
    """Found hardware problems with the host"""
    pass


class AutoservRebootError(AutoservError):
    """Error occured while rebooting a machine"""
    pass


class AutoservShutdownError(AutoservRebootError):
    """Error occured during shutdown of machine"""
    pass


class AutoservSuspendError(AutoservRebootError):
    """Error occured while suspending a machine"""
    pass


class AutoservSubcommandError(AutoservError):
    """Indicates an error while executing a (forked) subcommand"""
    def __init__(self, func, exit_code):
        AutoservError.__init__(self, func, exit_code)
        self.func = func
        self.exit_code = exit_code

    def __str__(self):
        return ("Subcommand %s failed with exit code %d" %
                (self.func, self.exit_code))


class AutoservRepairTotalFailure(AutoservError):
    """Raised if all attempts to repair the DUT failed."""
    pass


class AutoservRepairFailure(AutoservError):
    """Raised by a repair method if it is unable to repair a DUT."""
    pass


class AutoservRepairMethodNA(AutoservError):
    """Raised when for any reason a praticular repair method is NA."""
    pass


class AutoservInstallError(AutoservError):
    """Error occured while installing autotest on a host"""
    pass


class AutoservPidAlreadyDeadError(AutoservError):
    """Error occured by trying to kill a nonexistant PID"""
    pass


class AutoservCrashLogCollectRequired(AutoservError):
    """Need to collect crash-logs first"""
    pass


# packaging system errors

class PackagingError(AutotestError):
    'Abstract error class for all packaging related errors.'


class PackageUploadError(PackagingError):
    'Raised when there is an error uploading the package'


class PackageFetchError(PackagingError):
    'Raised when there is an error fetching the package'


class PackageRemoveError(PackagingError):
    'Raised when there is an error removing the package'


class PackageInstallError(PackagingError):
    'Raised when there is an error installing the package'


class RepoDiskFullError(PackagingError):
    'Raised when the destination for packages is full'


class RepoWriteError(PackagingError):
    "Raised when packager cannot write to a repo's desitnation"


class RepoUnknownError(PackagingError):
    "Raised when packager cannot write to a repo's desitnation"


class RepoError(PackagingError):
    "Raised when a repo isn't working in some way"


class StageControlFileFailure(Exception):
    """Exceptions encountered staging control files."""
    pass


class CrosDynamicSuiteException(Exception):
    """
    Base class for exceptions coming from dynamic suite code in
    server/cros/dynamic_suite/*.
    """
    pass


class StageBuildFailure(CrosDynamicSuiteException):
    """Raised when the dev server throws 500 while staging a build."""
    pass


class ControlFileEmpty(CrosDynamicSuiteException):
    """Raised when the control file exists on the server, but can't be read."""
    pass


class ControlFileMalformed(CrosDynamicSuiteException):
    """Raised when an invalid control file is read."""
    pass


class AsynchronousBuildFailure(CrosDynamicSuiteException):
    """Raised when the dev server throws 500 while finishing staging of a build.
    """
    pass


class SuiteArgumentException(CrosDynamicSuiteException):
    """Raised when improper arguments are used to run a suite."""
    pass


class MalformedDependenciesException(CrosDynamicSuiteException):
    """Raised when a build has a malformed dependency_info file."""
    pass


class InadequateHostsException(CrosDynamicSuiteException):
    """Raised when there are too few hosts to run a suite."""
    pass


class NoHostsException(CrosDynamicSuiteException):
    """Raised when there are no healthy hosts to run a suite."""
    pass


class ControlFileNotFound(CrosDynamicSuiteException):
    """Raised when a control file cannot be found and/or read."""
    pass


class NoControlFileList(CrosDynamicSuiteException):
    """Raised to indicate that a listing can't be done."""
    pass


class HostLockManagerReuse(CrosDynamicSuiteException):
    """Raised when a caller tries to re-use a HostLockManager instance."""
    pass


class ReimageAbortedException(CrosDynamicSuiteException):
    """Raised when a Reimage job is aborted"""
    pass


class UnknownReimageType(CrosDynamicSuiteException):
    """Raised when a suite passes in an invalid reimage type"""
    pass


class NoUniquePackageFound(Exception):
    """Raised when an executable cannot be mapped back to a single package."""
    pass


class RPCException(Exception):
    """Raised when an RPC encounters an error that a client might wish to
    handle specially."""
    pass


class NoEligibleHostException(RPCException):
    """Raised when no host could satisfy the requirements of a job."""
    pass


class InvalidBgJobCall(Exception):
    """Raised when an invalid call is made to a BgJob object."""
    pass


class HeartbeatOnlyAllowedInShardModeException(Exception):
    """Raised when a heartbeat is attempted but not allowed."""
    pass


class UnallowedRecordsSentToMaster(Exception):
    pass


class InvalidDataError(Exception):
    """Exception raised when invalid data provided for database operation.
    """
    pass


class ContainerError(Exception):
    """Exception raised when program runs into error using container.
    """


class IllegalUser(Exception):
    """Exception raise when a program runs as an illegal user."""


# This MUST remain at the end of the file.
# Limit 'from error import *' to only import the exception instances.
for _name, _thing in locals().items():
    try:
        if issubclass(_thing, Exception):
            __all__.append(_name)
    except TypeError:
        pass  # _thing not a class
__all__ = tuple(__all__)

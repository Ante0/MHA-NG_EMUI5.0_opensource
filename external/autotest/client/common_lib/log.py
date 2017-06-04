import sys, re, traceback

# these statuses are ordered such that a status earlier in the list will
# override a status later in a list (e.g. ERROR during a test will override
# prior GOOD results, but WARN will not override a FAIL)
job_statuses = ["TEST_NA", "ABORT", "ERROR", "FAIL", "WARN", "GOOD", "ALERT",
                "RUNNING", "NOSTATUS"]

def is_valid_status(status):
    if not re.match(r'(START|INFO|(END )?(' + '|'.join(job_statuses) + '))$',
                    status):
        return False
    else:
        return True


def is_failure(status):
    if not is_valid_status(status):
        return False
    if status in ('START', 'INFO'):
        return False
    if status.startswith('END '):
        status = status[len('END '):]
    return job_statuses.index(status) <= job_statuses.index("FAIL")


def record(fn):
    """
    Generic method decorator for logging calls under the
    assumption that return=GOOD, exception=FAIL. The method
    determines parameters as:
            subdir = self.subdir if it exists, or None
            operation = "class name"."method name"
            status = None on GOOD, str(exception) on FAIL
    The object using this method must have a job attribute
    for the logging to actually occur, otherwise the logging
    will silently fail.

    Logging can explicitly be disabled for a call by passing
    a logged=False parameter
    """
    def recorded_func(self, *args, **dargs):
        logged = dargs.pop('logged', True)
        job = getattr(self, 'job', None)
        # if logging is disabled/unavailable, just
        # call the method
        if not logged or job is None:
            return fn(self, *args, **dargs)
        # logging is available, so wrap the method call
        # in success/failure logging
        subdir = getattr(self, 'subdir', None)
        operation = '%s.%s' % (self.__class__.__name__,
                               fn.__name__)
        try:
            result = fn(self, *args, **dargs)
            job.record('GOOD', subdir, operation)
        except Exception, detail:
            job.record('FAIL', subdir, operation, str(detail))
            raise
        return result
    return recorded_func


def log_and_ignore_errors(msg):
    """ A decorator for wrapping functions in a 'log exception and ignore'
    try-except block. """
    def decorator(fn):
        def decorated_func(*args, **dargs):
            try:
                fn(*args, **dargs)
            except Exception:
                print >> sys.stderr, msg
                traceback.print_exc(file=sys.stderr)
        return decorated_func
    return decorator

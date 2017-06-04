import os, time, logging, shutil

from autotest_lib.client.common_lib import global_config
from autotest_lib.client.common_lib.cros.graphite import autotest_stats
from autotest_lib.client.cros import constants
from autotest_lib.server import utils


# import any site hooks for the crashdump and crashinfo collection
get_site_crashdumps = utils.import_site_function(
    __file__, "autotest_lib.server.site_crashcollect", "get_site_crashdumps",
    lambda host, test_start_time: None)
get_site_crashinfo = utils.import_site_function(
    __file__, "autotest_lib.server.site_crashcollect", "get_site_crashinfo",
    lambda host, test_start_time: None)


_timer = autotest_stats.Timer('crash_collection')

@_timer.decorate
def get_crashdumps(host, test_start_time):
    get_site_crashdumps(host, test_start_time)


@_timer.decorate
def get_crashinfo(host, test_start_time):
    logging.info("Collecting crash information...")

    # get_crashdumps collects orphaned crashdumps and symbolicates all
    # collected crashdumps. Symbolicating could happen
    # during a postjob task as well, at which time some crashdumps could have
    # already been pulled back from machine. So it doesn't necessarily need
    # to wait for the machine to come up.
    get_crashdumps(host, test_start_time)

    if wait_for_machine_to_recover(host):
        # run any site-specific collection
        get_site_crashinfo(host, test_start_time)

        crashinfo_dir = get_crashinfo_dir(host, 'crashinfo')
        collect_messages(host)
        collect_command(host, "dmesg", os.path.join(crashinfo_dir, "dmesg"))
        collect_uncollected_logs(host)

        # Collect everything in /var/log.
        log_path = os.path.join(crashinfo_dir, 'var')
        os.makedirs(log_path)
        collect_log_file(host, constants.LOG_DIR, log_path)

        # Collect console-ramoops
        log_path = os.path.join(
                crashinfo_dir, os.path.basename(constants.LOG_CONSOLE_RAMOOPS))
        collect_log_file(host, constants.LOG_CONSOLE_RAMOOPS, log_path)
        # Collect i915_error_state, only available on intel systems.
        # i915 contains the Intel graphics state. It might contain useful data
        # when a DUT hangs, times out or crashes.
        log_path = os.path.join(
                crashinfo_dir, os.path.basename(constants.LOG_I915_ERROR_STATE))
        collect_log_file(host, constants.LOG_I915_ERROR_STATE,
                         log_path, use_tmp=True)


# Load default for number of hours to wait before giving up on crash collection.
HOURS_TO_WAIT = global_config.global_config.get_config_value(
    'SERVER', 'crash_collection_hours_to_wait', type=float, default=4.0)


def wait_for_machine_to_recover(host, hours_to_wait=HOURS_TO_WAIT):
    """Wait for a machine (possibly down) to become accessible again.

    @param host: A RemoteHost instance to wait on
    @param hours_to_wait: Number of hours to wait before giving up

    @returns: True if the machine comes back up, False otherwise
    """
    current_time = time.strftime("%b %d %H:%M:%S", time.localtime())
    if host.is_up():
        logging.info("%s already up, collecting crash info", host.hostname)
        return True

    logging.info("Waiting %s hours for %s to come up (%s)",
                 hours_to_wait, host.hostname, current_time)
    if not host.wait_up(timeout=hours_to_wait * 3600):
        autotest_stats.Counter('collect_crashinfo_timeout').increment()
        logging.warning("%s down, unable to collect crash info",
                        host.hostname)
        return False
    else:
        logging.info("%s is back up, collecting crash info", host.hostname)
        return True


def get_crashinfo_dir(host, dir_prefix):
    """Find and if necessary create a directory to store crashinfo in.

    @param host: The RemoteHost object that crashinfo will be collected from
    @param dir_prefix: Prefix of directory name.

    @returns: The path to an existing directory for writing crashinfo into
    """
    host_resultdir = getattr(getattr(host, "job", None), "resultdir", None)
    if host_resultdir:
        infodir = host_resultdir
    else:
        infodir = os.path.abspath(os.getcwd())
    infodir = os.path.join(infodir, "%s.%s" % (dir_prefix, host.hostname))
    if not os.path.exists(infodir):
        os.mkdir(infodir)
    return infodir


def collect_log_file(host, log_path, dest_path, use_tmp=False):
    """Collects a log file from the remote machine.

    Log files are collected from the remote machine and written into the
    destination path. If dest_path is a directory, the log file will be named
    using the basename of the remote log path.

    @param host: The RemoteHost to collect logs from
    @param log_path: The remote path to collect the log file from
    @param dest_path: A path (file or directory) to write the copies logs into
    @param use_tmp: If True, will first copy the logs to a temporary directory
                    on the host and download logs from there.

    """
    logging.info('Collecting %s...', log_path)
    try:
        source_path = log_path
        if use_tmp:
            devnull = open('/dev/null', 'w')
            tmpdir = host.run('mktemp -d', stdout_tee=devnull).stdout.strip()
            host.run('cp -rp %s %s' % (log_path, tmpdir))
            source_path = os.path.join(tmpdir, os.path.basename(log_path))
        host.get_file(source_path, dest_path, preserve_perm=False)
        if use_tmp:
            host.run('rm -rf %s' % tmpdir)
    except Exception, e:
        logging.warning('Collection of %s failed: %s', log_path, e)


def collect_command(host, command, dest_path):
    """Collects the result of a command on the remote machine.

    The standard output of the command will be collected and written into the
    desitionation path. The destination path is assumed to be filename and
    not a directory.

    @param host: The RemoteHost to collect from
    @param command: A shell command to run on the remote machine and capture
        the output from.
    @param dest_path: A file path to write the results of the log into
    """
    logging.info("Collecting '%s' ...", command)
    devnull = open("/dev/null", "w")
    try:
        try:
            result = host.run(command, stdout_tee=devnull).stdout
            utils.open_write_close(dest_path, result)
        except Exception, e:
            logging.warning("Collection of '%s' failed:\n%s", command, e)
    finally:
        devnull.close()


def collect_uncollected_logs(host):
    """Collects any leftover uncollected logs from the client.

    @param host: The RemoteHost to collect from
    """
    if host.job:
        try:
            logs = host.job.get_client_logs()
            for hostname, remote_path, local_path in logs:
                if hostname == host.hostname:
                    logging.info("Retrieving logs from %s:%s into %s",
                                 hostname, remote_path, local_path)
                    host.get_file(remote_path + "/", local_path + "/")
        except Exception, e:
            logging.warning("Error while trying to collect stranded "
                            "Autotest client logs: %s", e)


def collect_messages(host):
    """Collects the 'new' contents of /var/log/messages.

    If host.VAR_LOG_MESSAGE_COPY_PATH is on the remote machine, collects
    the contents of /var/log/messages excluding whatever initial contents
    are already present in host.VAR_LOG_MESSAGE_COPY_PATH. If it is not
    present, simply collects the entire contents of /var/log/messages.

    @param host: The RemoteHost to collect from
    """
    crashinfo_dir = get_crashinfo_dir(host, 'crashinfo')

    try:
        # paths to the messages files
        messages = os.path.join(crashinfo_dir, "messages")
        messages_raw = os.path.join(crashinfo_dir, "messages.raw")
        messages_at_start = os.path.join(crashinfo_dir, "messages.at_start")

        # grab the files from the remote host
        collect_log_file(host, host.VAR_LOG_MESSAGES_COPY_PATH,
                         messages_at_start)
        collect_log_file(host, "/var/log/messages", messages_raw)

        # figure out how much of messages.raw to skip
        if os.path.exists(messages_at_start):
            # if the first lines of the messages at start should match the
            # first lines of the current messages; if they don't then messages
            # has been erase or rotated and we just grab all of it
            first_line_at_start = utils.read_one_line(messages_at_start)
            first_line_now = utils.read_one_line(messages_raw)
            if first_line_at_start != first_line_now:
                size_at_start = 0
            else:
                size_at_start = os.path.getsize(messages_at_start)
        else:
            size_at_start = 0
        raw_messages_file = open(messages_raw)
        messages_file = open(messages, "w")
        raw_messages_file.seek(size_at_start)
        shutil.copyfileobj(raw_messages_file, messages_file)
        raw_messages_file.close()
        messages_file.close()

        # get rid of the "raw" versions of messages
        os.remove(messages_raw)
        if os.path.exists(messages_at_start):
            os.remove(messages_at_start)
    except Exception, e:
        logging.warning("Error while collecting /var/log/messages: %s", e)

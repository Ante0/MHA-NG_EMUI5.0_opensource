# Copyright Martin J. Bligh, Google Inc 2008
# Released under the GPL v2

"""
This class allows you to communicate with the frontend to submit jobs etc
It is designed for writing more sophisiticated server-side control files that
can recursively add and manage other jobs.

We turn the JSON dictionaries into real objects that are more idiomatic

For docs, see:
    http://www.chromium.org/chromium-os/testing/afe-rpc-infrastructure
    http://docs.djangoproject.com/en/dev/ref/models/querysets/#queryset-api
"""

import getpass
import os
import re
import time
import traceback

import common
from autotest_lib.frontend.afe import rpc_client_lib
from autotest_lib.client.common_lib import control_data
from autotest_lib.client.common_lib import global_config
from autotest_lib.client.common_lib import utils
from autotest_lib.client.common_lib.cros.graphite import autotest_stats
from autotest_lib.tko import db


try:
    from autotest_lib.server.site_common import site_utils as server_utils
except:
    from autotest_lib.server import utils as server_utils
form_ntuples_from_machines = server_utils.form_ntuples_from_machines

GLOBAL_CONFIG = global_config.global_config
DEFAULT_SERVER = 'autotest'

_tko_timer = autotest_stats.Timer('tko')

def dump_object(header, obj):
    """
    Standard way to print out the frontend objects (eg job, host, acl, label)
    in a human-readable fashion for debugging
    """
    result = header + '\n'
    for key in obj.hash:
        if key == 'afe' or key == 'hash':
            continue
        result += '%20s: %s\n' % (key, obj.hash[key])
    return result


class RpcClient(object):
    """
    Abstract RPC class for communicating with the autotest frontend
    Inherited for both TKO and AFE uses.

    All the constructors go in the afe / tko class.
    Manipulating methods go in the object classes themselves
    """
    def __init__(self, path, user, server, print_log, debug, reply_debug):
        """
        Create a cached instance of a connection to the frontend

            user: username to connect as
            server: frontend server to connect to
            print_log: pring a logging message to stdout on every operation
            debug: print out all RPC traffic
        """
        if not user and utils.is_in_container():
            user = GLOBAL_CONFIG.get_config_value('SSP', 'user', default=None)
        if not user:
            user = getpass.getuser()
        if not server:
            if 'AUTOTEST_WEB' in os.environ:
                server = os.environ['AUTOTEST_WEB']
            else:
                server = GLOBAL_CONFIG.get_config_value('SERVER', 'hostname',
                                                        default=DEFAULT_SERVER)
        self.server = server
        self.user = user
        self.print_log = print_log
        self.debug = debug
        self.reply_debug = reply_debug
        headers = {'AUTHORIZATION': self.user}
        rpc_server = 'http://' + server + path
        if debug:
            print 'SERVER: %s' % rpc_server
            print 'HEADERS: %s' % headers
        self.proxy = rpc_client_lib.get_proxy(rpc_server, headers=headers)


    def run(self, call, **dargs):
        """
        Make a RPC call to the AFE server
        """
        rpc_call = getattr(self.proxy, call)
        if self.debug:
            print 'DEBUG: %s %s' % (call, dargs)
        try:
            result = utils.strip_unicode(rpc_call(**dargs))
            if self.reply_debug:
                print result
            return result
        except Exception:
            print 'FAILED RPC CALL: %s %s' % (call, dargs)
            raise


    def log(self, message):
        if self.print_log:
            print message


class Planner(RpcClient):
    def __init__(self, user=None, server=None, print_log=True, debug=False,
                 reply_debug=False):
        super(Planner, self).__init__(path='/planner/server/rpc/',
                                      user=user,
                                      server=server,
                                      print_log=print_log,
                                      debug=debug,
                                      reply_debug=reply_debug)


class TKO(RpcClient):
    def __init__(self, user=None, server=None, print_log=True, debug=False,
                 reply_debug=False):
        super(TKO, self).__init__(path='/new_tko/server/noauth/rpc/',
                                  user=user,
                                  server=server,
                                  print_log=print_log,
                                  debug=debug,
                                  reply_debug=reply_debug)
        self._db = None


    @_tko_timer.decorate
    def get_job_test_statuses_from_db(self, job_id):
        """Get job test statuses from the database.

        Retrieve a set of fields from a job that reflect the status of each test
        run within a job.
        fields retrieved: status, test_name, reason, test_started_time,
                          test_finished_time, afe_job_id, job_owner, hostname.

        @param job_id: The afe job id to look up.
        @returns a TestStatus object of the resulting information.
        """
        if self._db is None:
            self._db = db.db()
        fields = ['status', 'test_name', 'subdir', 'reason',
                  'test_started_time', 'test_finished_time', 'afe_job_id',
                  'job_owner', 'hostname', 'job_tag']
        table = 'tko_test_view_2'
        where = 'job_tag like "%s-%%"' % job_id
        test_status = []
        # Run commit before we query to ensure that we are pulling the latest
        # results.
        self._db.commit()
        for entry in self._db.select(','.join(fields), table, (where, None)):
            status_dict = {}
            for key,value in zip(fields, entry):
                # All callers expect values to be a str object.
                status_dict[key] = str(value)
            # id is used by TestStatus to uniquely identify each Test Status
            # obj.
            status_dict['id'] = [status_dict['reason'], status_dict['hostname'],
                                 status_dict['test_name']]
            test_status.append(status_dict)

        return [TestStatus(self, e) for e in test_status]


    def get_status_counts(self, job, **data):
        entries = self.run('get_status_counts',
                           group_by=['hostname', 'test_name', 'reason'],
                           job_tag__startswith='%s-' % job, **data)
        return [TestStatus(self, e) for e in entries['groups']]


class AFE(RpcClient):
    def __init__(self, user=None, server=None, print_log=True, debug=False,
                 reply_debug=False, job=None):
        self.job = job
        super(AFE, self).__init__(path='/afe/server/noauth/rpc/',
                                  user=user,
                                  server=server,
                                  print_log=print_log,
                                  debug=debug,
                                  reply_debug=reply_debug)


    def host_statuses(self, live=None):
        dead_statuses = ['Repair Failed', 'Repairing']
        statuses = self.run('get_static_data')['host_statuses']
        if live == True:
            return list(set(statuses) - set(dead_statuses))
        if live == False:
            return dead_statuses
        else:
            return statuses


    @staticmethod
    def _dict_for_host_query(hostnames=(), status=None, label=None):
        query_args = {}
        if hostnames:
            query_args['hostname__in'] = hostnames
        if status:
            query_args['status'] = status
        if label:
            query_args['labels__name'] = label
        return query_args


    def get_hosts(self, hostnames=(), status=None, label=None, **dargs):
        query_args = dict(dargs)
        query_args.update(self._dict_for_host_query(hostnames=hostnames,
                                                    status=status,
                                                    label=label))
        hosts = self.run('get_hosts', **query_args)
        return [Host(self, h) for h in hosts]


    def get_hostnames(self, status=None, label=None, **dargs):
        """Like get_hosts() but returns hostnames instead of Host objects."""
        # This implementation can be replaced with a more efficient one
        # that does not query for entire host objects in the future.
        return [host_obj.hostname for host_obj in
                self.get_hosts(status=status, label=label, **dargs)]


    def reverify_hosts(self, hostnames=(), status=None, label=None):
        query_args = dict(locked=False,
                          aclgroup__users__login=self.user)
        query_args.update(self._dict_for_host_query(hostnames=hostnames,
                                                    status=status,
                                                    label=label))
        return self.run('reverify_hosts', **query_args)


    def create_host(self, hostname, **dargs):
        id = self.run('add_host', hostname=hostname, **dargs)
        return self.get_hosts(id=id)[0]


    def get_host_attribute(self, attr, **dargs):
        host_attrs = self.run('get_host_attribute', attribute=attr, **dargs)
        return [HostAttribute(self, a) for a in host_attrs]


    def set_host_attribute(self, attr, val, **dargs):
        self.run('set_host_attribute', attribute=attr, value=val, **dargs)


    def get_labels(self, **dargs):
        labels = self.run('get_labels', **dargs)
        return [Label(self, l) for l in labels]


    def create_label(self, name, **dargs):
        id = self.run('add_label', name=name, **dargs)
        return self.get_labels(id=id)[0]


    def get_acls(self, **dargs):
        acls = self.run('get_acl_groups', **dargs)
        return [Acl(self, a) for a in acls]


    def create_acl(self, name, **dargs):
        id = self.run('add_acl_group', name=name, **dargs)
        return self.get_acls(id=id)[0]


    def get_users(self, **dargs):
        users = self.run('get_users', **dargs)
        return [User(self, u) for u in users]


    def generate_control_file(self, tests, **dargs):
        ret = self.run('generate_control_file', tests=tests, **dargs)
        return ControlFile(self, ret)


    def get_jobs(self, summary=False, **dargs):
        if summary:
            jobs_data = self.run('get_jobs_summary', **dargs)
        else:
            jobs_data = self.run('get_jobs', **dargs)
        jobs = []
        for j in jobs_data:
            job = Job(self, j)
            # Set up some extra information defaults
            job.testname = re.sub('\s.*', '', job.name) # arbitrary default
            job.platform_results = {}
            job.platform_reasons = {}
            jobs.append(job)
        return jobs


    def get_host_queue_entries(self, **data):
        entries = self.run('get_host_queue_entries', **data)
        job_statuses = [JobStatus(self, e) for e in entries]

        # Sadly, get_host_queue_entries doesn't return platforms, we have
        # to get those back from an explicit get_hosts queury, then patch
        # the new host objects back into the host list.
        hostnames = [s.host.hostname for s in job_statuses if s.host]
        host_hash = {}
        for host in self.get_hosts(hostname__in=hostnames):
            host_hash[host.hostname] = host
        for status in job_statuses:
            if status.host:
                status.host = host_hash.get(status.host.hostname)
        # filter job statuses that have either host or meta_host
        return [status for status in job_statuses if (status.host or
                                                      status.meta_host)]


    def get_special_tasks(self, **data):
        tasks = self.run('get_special_tasks', **data)
        return [SpecialTask(self, t) for t in tasks]


    def get_host_special_tasks(self, host_id, **data):
        tasks = self.run('get_host_special_tasks',
                         host_id=host_id, **data)
        return [SpecialTask(self, t) for t in tasks]


    def get_host_status_task(self, host_id, end_time):
        task = self.run('get_host_status_task',
                        host_id=host_id, end_time=end_time)
        return SpecialTask(self, task) if task else None


    def get_host_diagnosis_interval(self, host_id, end_time, success):
        return self.run('get_host_diagnosis_interval',
                        host_id=host_id, end_time=end_time,
                        success=success)


    def create_job_by_test(self, tests, kernel=None, use_container=False,
                           kernel_cmdline=None, **dargs):
        """
        Given a test name, fetch the appropriate control file from the server
        and submit it.

        @param kernel: A comma separated list of kernel versions to boot.
        @param kernel_cmdline: The command line used to boot all kernels listed
                in the kernel parameter.

        Returns a list of job objects
        """
        assert ('hosts' in dargs or
                'atomic_group_name' in dargs and 'synch_count' in dargs)
        if kernel:
            kernel_list =  re.split('[\s,]+', kernel.strip())
            kernel_info = []
            for version in kernel_list:
                kernel_dict = {'version': version}
                if kernel_cmdline is not None:
                    kernel_dict['cmdline'] = kernel_cmdline
                kernel_info.append(kernel_dict)
        else:
            kernel_info = None
        control_file = self.generate_control_file(
                tests=tests, kernel=kernel_info, use_container=use_container)
        if control_file.is_server:
            dargs['control_type'] = control_data.CONTROL_TYPE_NAMES.SERVER
        else:
            dargs['control_type'] = control_data.CONTROL_TYPE_NAMES.CLIENT
        dargs['dependencies'] = dargs.get('dependencies', []) + \
                                control_file.dependencies
        dargs['control_file'] = control_file.control_file
        if not dargs.get('synch_count', None):
            dargs['synch_count'] = control_file.synch_count
        if 'hosts' in dargs and len(dargs['hosts']) < dargs['synch_count']:
            # will not be able to satisfy this request
            return None
        return self.create_job(**dargs)


    def create_job(self, control_file, name=' ', priority='Medium',
                control_type=control_data.CONTROL_TYPE_NAMES.CLIENT, **dargs):
        id = self.run('create_job', name=name, priority=priority,
                 control_file=control_file, control_type=control_type, **dargs)
        return self.get_jobs(id=id)[0]


    def run_test_suites(self, pairings, kernel, kernel_label=None,
                        priority='Medium', wait=True, poll_interval=10,
                        email_from=None, email_to=None, timeout_mins=10080,
                        max_runtime_mins=10080, kernel_cmdline=None):
        """
        Run a list of test suites on a particular kernel.

        Poll for them to complete, and return whether they worked or not.

        @param pairings: List of MachineTestPairing objects to invoke.
        @param kernel: Name of the kernel to run.
        @param kernel_label: Label (string) of the kernel to run such as
                    '<kernel-version> : <config> : <date>'
                    If any pairing object has its job_label attribute set it
                    will override this value for that particular job.
        @param kernel_cmdline: The command line to boot the kernel(s) with.
        @param wait: boolean - Wait for the results to come back?
        @param poll_interval: Interval between polling for job results (in mins)
        @param email_from: Send notification email upon completion from here.
        @param email_from: Send notification email upon completion to here.
        """
        jobs = []
        for pairing in pairings:
            try:
                new_job = self.invoke_test(pairing, kernel, kernel_label,
                                           priority, timeout_mins=timeout_mins,
                                           kernel_cmdline=kernel_cmdline,
                                           max_runtime_mins=max_runtime_mins)
                if not new_job:
                    continue
                jobs.append(new_job)
            except Exception, e:
                traceback.print_exc()
        if not wait or not jobs:
            return
        tko = TKO()
        while True:
            time.sleep(60 * poll_interval)
            result = self.poll_all_jobs(tko, jobs, email_from, email_to)
            if result is not None:
                return result


    def result_notify(self, job, email_from, email_to):
        """
        Notify about the result of a job. Will always print, if email data
        is provided, will send email for it as well.

            job: job object to notify about
            email_from: send notification email upon completion from here
            email_from: send notification email upon completion to here
        """
        if job.result == True:
            subject = 'Testing PASSED: '
        else:
            subject = 'Testing FAILED: '
        subject += '%s : %s\n' % (job.name, job.id)
        text = []
        for platform in job.results_platform_map:
            for status in job.results_platform_map[platform]:
                if status == 'Total':
                    continue
                for host in job.results_platform_map[platform][status]:
                    text.append('%20s %10s %10s' % (platform, status, host))
                    if status == 'Failed':
                        for test_status in job.test_status[host].fail:
                            text.append('(%s, %s) : %s' % \
                                        (host, test_status.test_name,
                                         test_status.reason))
                        text.append('')

        base_url = 'http://' + self.server

        params = ('columns=test',
                  'rows=machine_group',
                  "condition=tag~'%s-%%25'" % job.id,
                  'title=Report')
        query_string = '&'.join(params)
        url = '%s/tko/compose_query.cgi?%s' % (base_url, query_string)
        text.append(url + '\n')
        url = '%s/afe/#tab_id=view_job&object_id=%s' % (base_url, job.id)
        text.append(url + '\n')

        body = '\n'.join(text)
        print '---------------------------------------------------'
        print 'Subject: ', subject
        print body
        print '---------------------------------------------------'
        if email_from and email_to:
            print 'Sending email ...'
            utils.send_email(email_from, email_to, subject, body)
        print


    def print_job_result(self, job):
        """
        Print the result of a single job.
            job: a job object
        """
        if job.result is None:
            print 'PENDING',
        elif job.result == True:
            print 'PASSED',
        elif job.result == False:
            print 'FAILED',
        elif job.result == "Abort":
            print 'ABORT',
        print ' %s : %s' % (job.id, job.name)


    def poll_all_jobs(self, tko, jobs, email_from=None, email_to=None):
        """
        Poll all jobs in a list.
            jobs: list of job objects to poll
            email_from: send notification email upon completion from here
            email_from: send notification email upon completion to here

        Returns:
            a) All complete successfully (return True)
            b) One or more has failed (return False)
            c) Cannot tell yet (return None)
        """
        results = []
        for job in jobs:
            if getattr(job, 'result', None) is None:
                job.result = self.poll_job_results(tko, job)
                if job.result is not None:
                    self.result_notify(job, email_from, email_to)

            results.append(job.result)
            self.print_job_result(job)

        if None in results:
            return None
        elif False in results or "Abort" in results:
            return False
        else:
            return True


    def _included_platform(self, host, platforms):
        """
        See if host's platforms matches any of the patterns in the included
        platforms list.
        """
        if not platforms:
            return True        # No filtering of platforms
        for platform in platforms:
            if re.search(platform, host.platform):
                return True
        return False


    def invoke_test(self, pairing, kernel, kernel_label, priority='Medium',
                    kernel_cmdline=None, **dargs):
        """
        Given a pairing of a control file to a machine label, find all machines
        with that label, and submit that control file to them.

        @param kernel_label: Label (string) of the kernel to run such as
                '<kernel-version> : <config> : <date>'
                If any pairing object has its job_label attribute set it
                will override this value for that particular job.

        @returns A list of job objects.
        """
        # The pairing can override the job label.
        if pairing.job_label:
            kernel_label = pairing.job_label
        job_name = '%s : %s' % (pairing.machine_label, kernel_label)
        hosts = self.get_hosts(multiple_labels=[pairing.machine_label])
        platforms = pairing.platforms
        hosts = [h for h in hosts if self._included_platform(h, platforms)]
        dead_statuses = self.host_statuses(live=False)
        host_list = [h.hostname for h in hosts if h.status not in dead_statuses]
        print 'HOSTS: %s' % host_list
        if pairing.atomic_group_sched:
            dargs['synch_count'] = pairing.synch_count
            dargs['atomic_group_name'] = pairing.machine_label
        else:
            dargs['hosts'] = host_list
        new_job = self.create_job_by_test(name=job_name,
                                          dependencies=[pairing.machine_label],
                                          tests=[pairing.control_file],
                                          priority=priority,
                                          kernel=kernel,
                                          kernel_cmdline=kernel_cmdline,
                                          use_container=pairing.container,
                                          **dargs)
        if new_job:
            if pairing.testname:
                new_job.testname = pairing.testname
            print 'Invoked test %s : %s' % (new_job.id, job_name)
        return new_job


    def _job_test_results(self, tko, job, debug, tests=[]):
        """
        Retrieve test results for a job
        """
        job.test_status = {}
        try:
            test_statuses = tko.get_status_counts(job=job.id)
        except Exception:
            print "Ignoring exception on poll job; RPC interface is flaky"
            traceback.print_exc()
            return

        for test_status in test_statuses:
            # SERVER_JOB is buggy, and often gives false failures. Ignore it.
            if test_status.test_name == 'SERVER_JOB':
                continue
            # if tests is not empty, restrict list of test_statuses to tests
            if tests and test_status.test_name not in tests:
                continue
            if debug:
                print test_status
            hostname = test_status.hostname
            if hostname not in job.test_status:
                job.test_status[hostname] = TestResults()
            job.test_status[hostname].add(test_status)


    def _job_results_platform_map(self, job, debug):
        # Figure out which hosts passed / failed / aborted in a job
        # Creates a 2-dimensional hash, stored as job.results_platform_map
        #     1st index - platform type (string)
        #     2nd index - Status (string)
        #         'Completed' / 'Failed' / 'Aborted'
        #     Data indexed by this hash is a list of hostnames (text strings)
        job.results_platform_map = {}
        try:
            job_statuses = self.get_host_queue_entries(job=job.id)
        except Exception:
            print "Ignoring exception on poll job; RPC interface is flaky"
            traceback.print_exc()
            return None

        platform_map = {}
        job.job_status = {}
        job.metahost_index = {}
        for job_status in job_statuses:
            # This is basically "for each host / metahost in the job"
            if job_status.host:
                hostname = job_status.host.hostname
            else:              # This is a metahost
                metahost = job_status.meta_host
                index = job.metahost_index.get(metahost, 1)
                job.metahost_index[metahost] = index + 1
                hostname = '%s.%s' % (metahost, index)
            job.job_status[hostname] = job_status.status
            status = job_status.status
            # Skip hosts that failed verify or repair:
            # that's a machine failure, not a job failure
            if hostname in job.test_status:
                verify_failed = False
                for failure in job.test_status[hostname].fail:
                    if (failure.test_name == 'verify' or
                            failure.test_name == 'repair'):
                        verify_failed = True
                        break
                if verify_failed:
                    continue
            if hostname in job.test_status and job.test_status[hostname].fail:
                # If the any tests failed in the job, we want to mark the
                # job result as failed, overriding the default job status.
                if status != "Aborted":         # except if it's an aborted job
                    status = 'Failed'
            if job_status.host:
                platform = job_status.host.platform
            else:              # This is a metahost
                platform = job_status.meta_host
            if platform not in platform_map:
                platform_map[platform] = {'Total' : [hostname]}
            else:
                platform_map[platform]['Total'].append(hostname)
            new_host_list = platform_map[platform].get(status, []) + [hostname]
            platform_map[platform][status] = new_host_list
        job.results_platform_map = platform_map


    def set_platform_results(self, test_job, platform, result):
        """
        Result must be None, 'FAIL', 'WARN' or 'GOOD'
        """
        if test_job.platform_results[platform] is not None:
            # We're already done, and results recorded. This can't change later.
            return
        test_job.platform_results[platform] = result
        # Note that self.job refers to the metajob we're IN, not the job
        # that we're excuting from here.
        testname = '%s.%s' % (test_job.testname, platform)
        if self.job:
            self.job.record(result, None, testname, status='')


    def poll_job_results(self, tko, job, enough=1, debug=False):
        """
        Analyse all job results by platform

          params:
            tko: a TKO object representing the results DB.
            job: the job to be examined.
            enough: the acceptable delta between the number of completed
                    tests and the total number of tests.
            debug: enable debugging output.

          returns:
            False: if any platform has more than |enough| failures
            None:  if any platform has less than |enough| machines
                   not yet Good.
            True:  if all platforms have at least |enough| machines
                   Good.
        """
        self._job_test_results(tko, job, debug)
        if job.test_status == {}:
            return None
        self._job_results_platform_map(job, debug)

        good_platforms = []
        failed_platforms = []
        aborted_platforms = []
        unknown_platforms = []
        platform_map = job.results_platform_map
        for platform in platform_map:
            if not job.platform_results.has_key(platform):
                # record test start, but there's no way to do this right now
                job.platform_results[platform] = None
            total = len(platform_map[platform]['Total'])
            completed = len(platform_map[platform].get('Completed', []))
            failed = len(platform_map[platform].get('Failed', []))
            aborted = len(platform_map[platform].get('Aborted', []))

            # We set up what we want to record here, but don't actually do
            # it yet, until we have a decisive answer for this platform
            if aborted or failed:
                bad = aborted + failed
                if (bad > 1) or (bad * 2 >= total):
                    platform_test_result = 'FAIL'
                else:
                    platform_test_result = 'WARN'

            if aborted > enough:
                aborted_platforms.append(platform)
                self.set_platform_results(job, platform, platform_test_result)
            elif (failed * 2 >= total) or (failed > enough):
                failed_platforms.append(platform)
                self.set_platform_results(job, platform, platform_test_result)
            elif (completed >= enough) and (completed + enough >= total):
                good_platforms.append(platform)
                self.set_platform_results(job, platform, 'GOOD')
            else:
                unknown_platforms.append(platform)
            detail = []
            for status in platform_map[platform]:
                if status == 'Total':
                    continue
                detail.append('%s=%s' % (status,platform_map[platform][status]))
            if debug:
                print '%20s %d/%d %s' % (platform, completed, total,
                                         ' '.join(detail))
                print

        if len(aborted_platforms) > 0:
            if debug:
                print 'Result aborted - platforms: ',
                print ' '.join(aborted_platforms)
            return "Abort"
        if len(failed_platforms) > 0:
            if debug:
                print 'Result bad - platforms: ' + ' '.join(failed_platforms)
            return False
        if len(unknown_platforms) > 0:
            if debug:
                platform_list = ' '.join(unknown_platforms)
                print 'Result unknown - platforms: ', platform_list
            return None
        if debug:
            platform_list = ' '.join(good_platforms)
            print 'Result good - all platforms passed: ', platform_list
        return True


    def abort_jobs(self, jobs):
        """Abort a list of jobs.

        Already completed jobs will not be affected.

        @param jobs: List of job ids to abort.
        """
        for job in jobs:
            self.run('abort_host_queue_entries', job_id=job)


class TestResults(object):
    """
    Container class used to hold the results of the tests for a job
    """
    def __init__(self):
        self.good = []
        self.fail = []
        self.pending = []


    def add(self, result):
        if result.complete_count > result.pass_count:
            self.fail.append(result)
        elif result.incomplete_count > 0:
            self.pending.append(result)
        else:
            self.good.append(result)


class RpcObject(object):
    """
    Generic object used to construct python objects from rpc calls
    """
    def __init__(self, afe, hash):
        self.afe = afe
        self.hash = hash
        self.__dict__.update(hash)


    def __str__(self):
        return dump_object(self.__repr__(), self)


class ControlFile(RpcObject):
    """
    AFE control file object

    Fields: synch_count, dependencies, control_file, is_server
    """
    def __repr__(self):
        return 'CONTROL FILE: %s' % self.control_file


class Label(RpcObject):
    """
    AFE label object

    Fields:
        name, invalid, platform, kernel_config, id, only_if_needed
    """
    def __repr__(self):
        return 'LABEL: %s' % self.name


    def add_hosts(self, hosts):
        return self.afe.run('label_add_hosts', id=self.id, hosts=hosts)


    def remove_hosts(self, hosts):
        return self.afe.run('label_remove_hosts', id=self.id, hosts=hosts)


class Acl(RpcObject):
    """
    AFE acl object

    Fields:
        users, hosts, description, name, id
    """
    def __repr__(self):
        return 'ACL: %s' % self.name


    def add_hosts(self, hosts):
        self.afe.log('Adding hosts %s to ACL %s' % (hosts, self.name))
        return self.afe.run('acl_group_add_hosts', self.id, hosts)


    def remove_hosts(self, hosts):
        self.afe.log('Removing hosts %s from ACL %s' % (hosts, self.name))
        return self.afe.run('acl_group_remove_hosts', self.id, hosts)


    def add_users(self, users):
        self.afe.log('Adding users %s to ACL %s' % (users, self.name))
        return self.afe.run('acl_group_add_users', id=self.name, users=users)


class Job(RpcObject):
    """
    AFE job object

    Fields:
        name, control_file, control_type, synch_count, reboot_before,
        run_verify, priority, email_list, created_on, dependencies,
        timeout, owner, reboot_after, id
    """
    def __repr__(self):
        return 'JOB: %s' % self.id


class JobStatus(RpcObject):
    """
    AFE job_status object

    Fields:
        status, complete, deleted, meta_host, host, active, execution_subdir, id
    """
    def __init__(self, afe, hash):
        super(JobStatus, self).__init__(afe, hash)
        self.job = Job(afe, self.job)
        if getattr(self, 'host'):
            self.host = Host(afe, self.host)


    def __repr__(self):
        if self.host and self.host.hostname:
            hostname = self.host.hostname
        else:
            hostname = 'None'
        return 'JOB STATUS: %s-%s' % (self.job.id, hostname)


class SpecialTask(RpcObject):
    """
    AFE special task object
    """
    def __init__(self, afe, hash):
        super(SpecialTask, self).__init__(afe, hash)
        self.host = Host(afe, self.host)


    def __repr__(self):
        return 'SPECIAL TASK: %s' % self.id


class Host(RpcObject):
    """
    AFE host object

    Fields:
        status, lock_time, locked_by, locked, hostname, invalid,
        synch_id, labels, platform, protection, dirty, id
    """
    def __repr__(self):
        return 'HOST OBJECT: %s' % self.hostname


    def show(self):
        labels = list(set(self.labels) - set([self.platform]))
        print '%-6s %-7s %-7s %-16s %s' % (self.hostname, self.status,
                                           self.locked, self.platform,
                                           ', '.join(labels))


    def delete(self):
        return self.afe.run('delete_host', id=self.id)


    def modify(self, **dargs):
        return self.afe.run('modify_host', id=self.id, **dargs)


    def get_acls(self):
        return self.afe.get_acls(hosts__hostname=self.hostname)


    def add_acl(self, acl_name):
        self.afe.log('Adding ACL %s to host %s' % (acl_name, self.hostname))
        return self.afe.run('acl_group_add_hosts', id=acl_name,
                            hosts=[self.hostname])


    def remove_acl(self, acl_name):
        self.afe.log('Removing ACL %s from host %s' % (acl_name, self.hostname))
        return self.afe.run('acl_group_remove_hosts', id=acl_name,
                            hosts=[self.hostname])


    def get_labels(self):
        return self.afe.get_labels(host__hostname__in=[self.hostname])


    def add_labels(self, labels):
        self.afe.log('Adding labels %s to host %s' % (labels, self.hostname))
        return self.afe.run('host_add_labels', id=self.id, labels=labels)


    def remove_labels(self, labels):
        self.afe.log('Removing labels %s from host %s' % (labels,self.hostname))
        return self.afe.run('host_remove_labels', id=self.id, labels=labels)


class User(RpcObject):
    def __repr__(self):
        return 'USER: %s' % self.login


class TestStatus(RpcObject):
    """
    TKO test status object

    Fields:
        test_idx, hostname, testname, id
        complete_count, incomplete_count, group_count, pass_count
    """
    def __repr__(self):
        return 'TEST STATUS: %s' % self.id


class HostAttribute(RpcObject):
    """
    AFE host attribute object

    Fields:
        id, host, attribute, value
    """
    def __repr__(self):
        return 'HOST ATTRIBUTE %d' % self.id


class MachineTestPairing(object):
    """
    Object representing the pairing of a machine label with a control file

    machine_label: use machines from this label
    control_file: use this control file (by name in the frontend)
    platforms: list of rexeps to filter platforms by. [] => no filtering
    job_label: The label (name) to give to the autotest job launched
            to run this pairing.  '<kernel-version> : <config> : <date>'
    """
    def __init__(self, machine_label, control_file, platforms=[],
                 container=False, atomic_group_sched=False, synch_count=0,
                 testname=None, job_label=None):
        self.machine_label = machine_label
        self.control_file = control_file
        self.platforms = platforms
        self.container = container
        self.atomic_group_sched = atomic_group_sched
        self.synch_count = synch_count
        self.testname = testname
        self.job_label = job_label


    def __repr__(self):
        return '%s %s %s %s' % (self.machine_label, self.control_file,
                                self.platforms, self.container)

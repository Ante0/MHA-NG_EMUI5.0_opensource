"""
Autotest AFE Cleanup used by the scheduler
"""


import time, logging, random

from autotest_lib.frontend.afe import models
from autotest_lib.scheduler import email_manager
from autotest_lib.scheduler import scheduler_config
from autotest_lib.client.common_lib import global_config
from autotest_lib.client.common_lib import host_protections
from autotest_lib.client.common_lib.cros.graphite import autotest_stats


class PeriodicCleanup(object):
    """Base class to schedule periodical cleanup work.
    """

    def __init__(self, db, clean_interval_minutes, run_at_initialize=False):
        self._db = db
        self.clean_interval_minutes = clean_interval_minutes
        self._last_clean_time = time.time()
        self._run_at_initialize = run_at_initialize


    def initialize(self):
        """Method called by scheduler at the startup.
        """
        if self._run_at_initialize:
            self._cleanup()


    def run_cleanup_maybe(self):
        """Test if cleanup method should be called.
        """
        should_cleanup = (self._last_clean_time +
                          self.clean_interval_minutes * 60
                          < time.time())
        if should_cleanup:
            self._cleanup()
            self._last_clean_time = time.time()


    def _cleanup(self):
        """Abrstract cleanup method."""
        raise NotImplementedError


class UserCleanup(PeriodicCleanup):
    """User cleanup that is controlled by the global config variable
       clean_interval_minutes in the SCHEDULER section.
    """
    timer = autotest_stats.Timer('monitor_db_cleanup.user_cleanup')


    def __init__(self, db, clean_interval_minutes):
        super(UserCleanup, self).__init__(db, clean_interval_minutes)
        self._last_reverify_time = time.time()


    @timer.decorate
    def _cleanup(self):
        logging.info('Running periodic cleanup')
        self._abort_timed_out_jobs()
        self._abort_jobs_past_max_runtime()
        self._clear_inactive_blocks()
        self._check_for_db_inconsistencies()
        self._reverify_dead_hosts()
        self._django_session_cleanup()


    @timer.decorate
    def _abort_timed_out_jobs(self):
        msg = 'Aborting all jobs that have timed out and are not complete'
        logging.info(msg)
        query = models.Job.objects.filter(hostqueueentry__complete=False).extra(
            where=['created_on + INTERVAL timeout_mins MINUTE < NOW()'])
        for job in query.distinct():
            logging.warning('Aborting job %d due to job timeout', job.id)
            job.abort()


    @timer.decorate
    def _abort_jobs_past_max_runtime(self):
        """
        Abort executions that have started and are past the job's max runtime.
        """
        logging.info('Aborting all jobs that have passed maximum runtime')
        rows = self._db.execute("""
            SELECT hqe.id
            FROM afe_host_queue_entries AS hqe
            INNER JOIN afe_jobs ON (hqe.job_id = afe_jobs.id)
            WHERE NOT hqe.complete AND NOT hqe.aborted AND
            hqe.started_on + INTERVAL afe_jobs.max_runtime_mins MINUTE <
            NOW()""")
        query = models.HostQueueEntry.objects.filter(
            id__in=[row[0] for row in rows])
        for queue_entry in query.distinct():
            logging.warning('Aborting entry %s due to max runtime', queue_entry)
            queue_entry.abort()


    @timer.decorate
    def _check_for_db_inconsistencies(self):
        logging.info('Cleaning db inconsistencies')
        self._check_all_invalid_related_objects()


    def _check_invalid_related_objects_one_way(self, first_model,
                                               relation_field, second_model):
        if 'invalid' not in first_model.get_field_dict():
            return []
        invalid_objects = list(first_model.objects.filter(invalid=True))
        first_model.objects.populate_relationships(invalid_objects,
                                                   second_model,
                                                   'related_objects')
        error_lines = []
        for invalid_object in invalid_objects:
            if invalid_object.related_objects:
                related_list = ', '.join(str(related_object) for related_object
                                         in invalid_object.related_objects)
                error_lines.append('Invalid %s %s is related to %ss: %s'
                                   % (first_model.__name__, invalid_object,
                                      second_model.__name__, related_list))
                related_manager = getattr(invalid_object, relation_field)
                related_manager.clear()
        return error_lines


    def _check_invalid_related_objects(self, first_model, first_field,
                                       second_model, second_field):
        errors = self._check_invalid_related_objects_one_way(
            first_model, first_field, second_model)
        errors.extend(self._check_invalid_related_objects_one_way(
            second_model, second_field, first_model))
        return errors


    def _check_all_invalid_related_objects(self):
        model_pairs = ((models.Host, 'labels', models.Label, 'host_set'),
                       (models.AclGroup, 'hosts', models.Host, 'aclgroup_set'),
                       (models.AclGroup, 'users', models.User, 'aclgroup_set'),
                       (models.Test, 'dependency_labels', models.Label,
                        'test_set'))
        errors = []
        for first_model, first_field, second_model, second_field in model_pairs:
            errors.extend(self._check_invalid_related_objects(
                first_model, first_field, second_model, second_field))

        if errors:
            subject = ('%s relationships to invalid models, cleaned all' %
                       len(errors))
            message = '\n'.join(errors)
            logging.warning(subject)
            logging.warning(message)
            email_manager.manager.enqueue_notify_email(subject, message)


    @timer.decorate
    def _clear_inactive_blocks(self):
        msg = 'Clear out blocks for all completed jobs.'
        logging.info(msg)
        # this would be simpler using NOT IN (subquery), but MySQL
        # treats all IN subqueries as dependent, so this optimizes much
        # better
        self._db.execute("""
            DELETE ihq FROM afe_ineligible_host_queues ihq
            LEFT JOIN (SELECT DISTINCT job_id FROM afe_host_queue_entries
                       WHERE NOT complete) hqe
            USING (job_id) WHERE hqe.job_id IS NULL""")


    def _should_reverify_hosts_now(self):
        reverify_period_sec = (scheduler_config.config.reverify_period_minutes
                               * 60)
        if reverify_period_sec == 0:
            return False
        return (self._last_reverify_time + reverify_period_sec) <= time.time()


    def _choose_subset_of_hosts_to_reverify(self, hosts):
        """Given hosts needing verification, return a subset to reverify."""
        max_at_once = scheduler_config.config.reverify_max_hosts_at_once
        if (max_at_once > 0 and len(hosts) > max_at_once):
            return random.sample(hosts, max_at_once)
        return sorted(hosts)


    @timer.decorate
    def _reverify_dead_hosts(self):
        if not self._should_reverify_hosts_now():
            return

        self._last_reverify_time = time.time()
        logging.info('Checking for dead hosts to reverify')
        hosts = models.Host.objects.filter(
                status=models.Host.Status.REPAIR_FAILED,
                locked=False,
                invalid=False)
        hosts = hosts.exclude(
                protection=host_protections.Protection.DO_NOT_VERIFY)
        if not hosts:
            return

        hosts = list(hosts)
        total_hosts = len(hosts)
        hosts = self._choose_subset_of_hosts_to_reverify(hosts)
        logging.info('Reverifying dead hosts (%d of %d) %s', len(hosts),
                     total_hosts, ', '.join(host.hostname for host in hosts))
        for host in hosts:
            models.SpecialTask.schedule_special_task(
                    host=host, task=models.SpecialTask.Task.VERIFY)


    @timer.decorate
    def _django_session_cleanup(self):
        """Clean up django_session since django doesn't for us.
           http://www.djangoproject.com/documentation/0.96/sessions/
        """
        logging.info('Deleting old sessions from django_session')
        sql = 'TRUNCATE TABLE django_session'
        self._db.execute(sql)


class TwentyFourHourUpkeep(PeriodicCleanup):
    """Cleanup that runs at the startup of monitor_db and every subsequent
       twenty four hours.
    """
    timer = autotest_stats.Timer('monitor_db_cleanup.twentyfourhour_cleanup')


    def __init__(self, db, drone_manager, run_at_initialize=True):
        """Initialize TwentyFourHourUpkeep.

        @param db: Database connection object.
        @param drone_manager: DroneManager to access drones.
        @param run_at_initialize: True to run cleanup when scheduler starts.
                                  Default is set to True.

        """
        self.drone_manager = drone_manager
        clean_interval_minutes = 24 * 60 # 24 hours
        super(TwentyFourHourUpkeep, self).__init__(
            db, clean_interval_minutes, run_at_initialize=run_at_initialize)


    @timer.decorate
    def _cleanup(self):
        logging.info('Running 24 hour clean up')
        self._check_for_uncleanable_db_inconsistencies()
        self._cleanup_orphaned_containers()


    @timer.decorate
    def _check_for_uncleanable_db_inconsistencies(self):
        logging.info('Checking for uncleanable DB inconsistencies')
        self._check_for_active_and_complete_queue_entries()
        self._check_for_multiple_platform_hosts()
        self._check_for_no_platform_hosts()
        self._check_for_multiple_atomic_group_hosts()


    @timer.decorate
    def _check_for_active_and_complete_queue_entries(self):
        query = models.HostQueueEntry.objects.filter(active=True, complete=True)
        if query.count() != 0:
            subject = ('%d queue entries found with active=complete=1'
                       % query.count())
            lines = []
            for entry in query:
                lines.append(str(entry.get_object_dict()))
                if entry.status == 'Aborted':
                    logging.error('Aborted entry: %s is both active and '
                                  'complete. Setting active value to False.',
                                  str(entry))
                    entry.active = False
                    entry.save()
            self._send_inconsistency_message(subject, lines)


    @timer.decorate
    def _check_for_multiple_platform_hosts(self):
        rows = self._db.execute("""
            SELECT afe_hosts.id, hostname, COUNT(1) AS platform_count,
                   GROUP_CONCAT(afe_labels.name)
            FROM afe_hosts
            INNER JOIN afe_hosts_labels ON
                    afe_hosts.id = afe_hosts_labels.host_id
            INNER JOIN afe_labels ON afe_hosts_labels.label_id = afe_labels.id
            WHERE afe_labels.platform
            GROUP BY afe_hosts.id
            HAVING platform_count > 1
            ORDER BY hostname""")
        if rows:
            subject = '%s hosts with multiple platforms' % self._db.rowcount
            lines = [' '.join(str(item) for item in row)
                     for row in rows]
            self._send_inconsistency_message(subject, lines)


    @timer.decorate
    def _check_for_no_platform_hosts(self):
        rows = self._db.execute("""
            SELECT hostname
            FROM afe_hosts
            LEFT JOIN afe_hosts_labels
              ON afe_hosts.id = afe_hosts_labels.host_id
              AND afe_hosts_labels.label_id IN (SELECT id FROM afe_labels
                                                WHERE platform)
            WHERE NOT afe_hosts.invalid AND afe_hosts_labels.host_id IS NULL""")
        if rows:
            logging.warning('%s hosts with no platform\n%s', self._db.rowcount,
                         ', '.join(row[0] for row in rows))


    @timer.decorate
    def _check_for_multiple_atomic_group_hosts(self):
        rows = self._db.execute("""
            SELECT afe_hosts.id, hostname,
                   COUNT(DISTINCT afe_atomic_groups.name) AS atomic_group_count,
                   GROUP_CONCAT(afe_labels.name),
                   GROUP_CONCAT(afe_atomic_groups.name)
            FROM afe_hosts
            INNER JOIN afe_hosts_labels ON
                    afe_hosts.id = afe_hosts_labels.host_id
            INNER JOIN afe_labels ON afe_hosts_labels.label_id = afe_labels.id
            INNER JOIN afe_atomic_groups ON
                       afe_labels.atomic_group_id = afe_atomic_groups.id
            WHERE NOT afe_hosts.invalid AND NOT afe_labels.invalid
            GROUP BY afe_hosts.id
            HAVING atomic_group_count > 1
            ORDER BY hostname""")
        if rows:
            subject = '%s hosts with multiple atomic groups' % self._db.rowcount
            lines = [' '.join(str(item) for item in row)
                     for row in rows]
            self._send_inconsistency_message(subject, lines)


    def _send_inconsistency_message(self, subject, lines):
        logging.error(subject)
        message = '\n'.join(lines)
        if len(message) > 5000:
            message = message[:5000] + '\n(truncated)\n'
        email_manager.manager.enqueue_notify_email(subject, message)


    @timer.decorate
    def _cleanup_orphaned_containers(self):
        """Cleanup orphaned containers in each drone.

        The function queues a lxc_cleanup call in each drone without waiting for
        the script to finish, as the cleanup procedure could take minutes and the
        script output is logged.

        """
        ssp_enabled = global_config.global_config.get_config_value(
                'AUTOSERV', 'enable_ssp_container')
        if not ssp_enabled:
            logging.info('Server-side packaging is not enabled, no need to clean'
                         ' up orphaned containers.')
            return
        self.drone_manager.cleanup_orphaned_containers()

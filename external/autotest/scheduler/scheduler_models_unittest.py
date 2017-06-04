#!/usr/bin/python
#pylint: disable-msg=C0111

import datetime
import common
from autotest_lib.frontend import setup_django_environment
from autotest_lib.frontend.afe import frontend_test_utils
from autotest_lib.client.common_lib import host_queue_entry_states
from autotest_lib.client.common_lib.test_utils import mock
from autotest_lib.client.common_lib.test_utils import unittest
from autotest_lib.database import database_connection
from autotest_lib.frontend.afe import models, model_attributes
from autotest_lib.scheduler import monitor_db
from autotest_lib.scheduler import scheduler_lib
from autotest_lib.scheduler import scheduler_models

_DEBUG = False


class BaseSchedulerModelsTest(unittest.TestCase,
                              frontend_test_utils.FrontendTestMixin):
    _config_section = 'AUTOTEST_WEB'

    def _do_query(self, sql):
        self._database.execute(sql)


    def _set_monitor_stubs(self):
        # Clear the instance cache as this is a brand new database.
        scheduler_models.DBObject._clear_instance_cache()

        self._database = (
            database_connection.TranslatingDatabase.get_test_database(
                translators=scheduler_lib._DB_TRANSLATORS))
        self._database.connect(db_type='django')
        self._database.debug = _DEBUG

        self.god.stub_with(scheduler_models, '_db', self._database)


    def setUp(self):
        self._frontend_common_setup()
        self._set_monitor_stubs()


    def tearDown(self):
        self._database.disconnect()
        self._frontend_common_teardown()


    def _update_hqe(self, set, where=''):
        query = 'UPDATE afe_host_queue_entries SET ' + set
        if where:
            query += ' WHERE ' + where
        self._do_query(query)


class DelayedCallTaskTest(unittest.TestCase):
    def setUp(self):
        self.god = mock.mock_god()


    def tearDown(self):
        self.god.unstub_all()


    def test_delayed_call(self):
        test_time = self.god.create_mock_function('time')
        test_time.expect_call().and_return(33)
        test_time.expect_call().and_return(34.01)
        test_time.expect_call().and_return(34.99)
        test_time.expect_call().and_return(35.01)
        def test_callback():
            test_callback.calls += 1
        test_callback.calls = 0
        delay_task = scheduler_models.DelayedCallTask(
                delay_seconds=2, callback=test_callback,
                now_func=test_time)  # time 33
        self.assertEqual(35, delay_task.end_time)
        delay_task.poll()  # activates the task and polls it once, time 34.01
        self.assertEqual(0, test_callback.calls, "callback called early")
        delay_task.poll()  # time 34.99
        self.assertEqual(0, test_callback.calls, "callback called early")
        delay_task.poll()  # time 35.01
        self.assertEqual(1, test_callback.calls)
        self.assert_(delay_task.is_done())
        self.assert_(delay_task.success)
        self.assert_(not delay_task.aborted)
        self.god.check_playback()


    def test_delayed_call_abort(self):
        delay_task = scheduler_models.DelayedCallTask(
                delay_seconds=987654, callback=lambda : None)
        delay_task.abort()
        self.assert_(delay_task.aborted)
        self.assert_(delay_task.is_done())
        self.assert_(not delay_task.success)
        self.god.check_playback()


class DBObjectTest(BaseSchedulerModelsTest):
    def test_compare_fields_in_row(self):
        host = scheduler_models.Host(id=1)
        fields = list(host._fields)
        row_data = [getattr(host, fieldname) for fieldname in fields]
        self.assertEqual({}, host._compare_fields_in_row(row_data))
        row_data[fields.index('hostname')] = 'spam'
        self.assertEqual({'hostname': ('host1', 'spam')},
                         host._compare_fields_in_row(row_data))
        row_data[fields.index('id')] = 23
        self.assertEqual({'hostname': ('host1', 'spam'), 'id': (1, 23)},
                         host._compare_fields_in_row(row_data))


    def test_compare_fields_in_row_datetime_ignores_microseconds(self):
        datetime_with_us = datetime.datetime(2009, 10, 07, 12, 34, 56, 7890)
        datetime_without_us = datetime.datetime(2009, 10, 07, 12, 34, 56, 0)
        class TestTable(scheduler_models.DBObject):
            _table_name = 'test_table'
            _fields = ('id', 'test_datetime')
        tt = TestTable(row=[1, datetime_without_us])
        self.assertEqual({}, tt._compare_fields_in_row([1, datetime_with_us]))


    def test_always_query(self):
        host_a = scheduler_models.Host(id=2)
        self.assertEqual(host_a.hostname, 'host2')
        self._do_query('UPDATE afe_hosts SET hostname="host2-updated" '
                       'WHERE id=2')
        host_b = scheduler_models.Host(id=2, always_query=True)
        self.assert_(host_a is host_b, 'Cached instance not returned.')
        self.assertEqual(host_a.hostname, 'host2-updated',
                         'Database was not re-queried')

        # If either of these are called, a query was made when it shouldn't be.
        host_a._compare_fields_in_row = lambda _: self.fail('eek! a query!')
        host_a._update_fields_from_row = host_a._compare_fields_in_row
        host_c = scheduler_models.Host(id=2, always_query=False)
        self.assert_(host_a is host_c, 'Cached instance not returned')


    def test_delete(self):
        host = scheduler_models.Host(id=3)
        host.delete()
        host = self.assertRaises(scheduler_models.DBError, scheduler_models.Host, id=3,
                                 always_query=False)
        host = self.assertRaises(scheduler_models.DBError, scheduler_models.Host, id=3,
                                 always_query=True)

    def test_save(self):
        # Dummy Job to avoid creating a one in the HostQueueEntry __init__.
        class MockJob(object):
            def __init__(self, id):
                pass
            def tag(self):
                return 'MockJob'
        self.god.stub_with(scheduler_models, 'Job', MockJob)
        hqe = scheduler_models.HostQueueEntry(
                new_record=True,
                row=[0, 1, 2, 'Queued', None, 0, 0, 0, '.', None, False, None,
                     None])
        hqe.save()
        new_id = hqe.id
        # Force a re-query and verify that the correct data was stored.
        scheduler_models.DBObject._clear_instance_cache()
        hqe = scheduler_models.HostQueueEntry(id=new_id)
        self.assertEqual(hqe.id, new_id)
        self.assertEqual(hqe.job_id, 1)
        self.assertEqual(hqe.host_id, 2)
        self.assertEqual(hqe.status, 'Queued')
        self.assertEqual(hqe.meta_host, None)
        self.assertEqual(hqe.active, False)
        self.assertEqual(hqe.complete, False)
        self.assertEqual(hqe.deleted, False)
        self.assertEqual(hqe.execution_subdir, '.')
        self.assertEqual(hqe.atomic_group_id, None)
        self.assertEqual(hqe.started_on, None)
        self.assertEqual(hqe.finished_on, None)


class HostTest(BaseSchedulerModelsTest):
    def test_cmp_for_sort(self):
        expected_order = [
                'alice', 'Host1', 'host2', 'host3', 'host09', 'HOST010',
                'host10', 'host11', 'yolkfolk']
        hostname_idx = list(scheduler_models.Host._fields).index('hostname')
        row = [None] * len(scheduler_models.Host._fields)
        hosts = []
        for hostname in expected_order:
            row[hostname_idx] = hostname
            hosts.append(scheduler_models.Host(row=row, new_record=True))

        host1 = hosts[expected_order.index('Host1')]
        host010 = hosts[expected_order.index('HOST010')]
        host10 = hosts[expected_order.index('host10')]
        host3 = hosts[expected_order.index('host3')]
        alice = hosts[expected_order.index('alice')]
        self.assertEqual(0, scheduler_models.Host.cmp_for_sort(host10, host10))
        self.assertEqual(1, scheduler_models.Host.cmp_for_sort(host10, host010))
        self.assertEqual(-1, scheduler_models.Host.cmp_for_sort(host010, host10))
        self.assertEqual(-1, scheduler_models.Host.cmp_for_sort(host1, host10))
        self.assertEqual(-1, scheduler_models.Host.cmp_for_sort(host1, host010))
        self.assertEqual(-1, scheduler_models.Host.cmp_for_sort(host3, host10))
        self.assertEqual(-1, scheduler_models.Host.cmp_for_sort(host3, host010))
        self.assertEqual(1, scheduler_models.Host.cmp_for_sort(host3, host1))
        self.assertEqual(-1, scheduler_models.Host.cmp_for_sort(host1, host3))
        self.assertEqual(-1, scheduler_models.Host.cmp_for_sort(alice, host3))
        self.assertEqual(1, scheduler_models.Host.cmp_for_sort(host3, alice))
        self.assertEqual(0, scheduler_models.Host.cmp_for_sort(alice, alice))

        hosts.sort(cmp=scheduler_models.Host.cmp_for_sort)
        self.assertEqual(expected_order, [h.hostname for h in hosts])

        hosts.reverse()
        hosts.sort(cmp=scheduler_models.Host.cmp_for_sort)
        self.assertEqual(expected_order, [h.hostname for h in hosts])


class HostQueueEntryTest(BaseSchedulerModelsTest):
    def _create_hqe(self, dependency_labels=(), **create_job_kwargs):
        job = self._create_job(**create_job_kwargs)
        for label in dependency_labels:
            job.dependency_labels.add(label)
        hqes = list(scheduler_models.HostQueueEntry.fetch(where='job_id=%d' % job.id))
        self.assertEqual(1, len(hqes))
        return hqes[0]


    def _check_hqe_labels(self, hqe, expected_labels):
        expected_labels = set(expected_labels)
        label_names = set(label.name for label in hqe.get_labels())
        self.assertEqual(expected_labels, label_names)


    def test_get_labels_empty(self):
        hqe = self._create_hqe(hosts=[1])
        labels = list(hqe.get_labels())
        self.assertEqual([], labels)


    def test_get_labels_metahost(self):
        hqe = self._create_hqe(metahosts=[2])
        self._check_hqe_labels(hqe, ['label2'])


    def test_get_labels_dependancies(self):
        hqe = self._create_hqe(dependency_labels=(self.label3, self.label4),
                               metahosts=[1])
        self._check_hqe_labels(hqe, ['label1', 'label3', 'label4'])


    def setup_abort_test(self, agent_finished=True):
        """Setup the variables for testing abort method.

        @param agent_finished: True to mock agent is finished before aborting
                               the hqe.
        @return hqe, dispatcher: Mock object of hqe and dispatcher to be used
                               to test abort method.
        """
        hqe = self._create_hqe(hosts=[1])
        hqe.aborted = True
        hqe.complete = False
        hqe.status = models.HostQueueEntry.Status.STARTING
        hqe.started_on = datetime.datetime.now()

        dispatcher = self.god.create_mock_class(monitor_db.BaseDispatcher,
                                                'BaseDispatcher')
        agent = self.god.create_mock_class(monitor_db.Agent, 'Agent')
        dispatcher.get_agents_for_entry.expect_call(hqe).and_return([agent])
        agent.is_done.expect_call().and_return(agent_finished)
        return hqe, dispatcher


    def test_abort_fail_with_unfinished_agent(self):
        """abort should fail if the hqe still has agent not finished.
        """
        hqe, dispatcher = self.setup_abort_test(agent_finished=False)
        self.assertIsNone(hqe.finished_on)
        with self.assertRaises(AssertionError):
            hqe.abort(dispatcher)
        self.god.check_playback()
        # abort failed, finished_on should not be set
        self.assertIsNone(hqe.finished_on)


    def test_abort_success(self):
        """abort should succeed if all agents for the hqe are finished.
        """
        hqe, dispatcher = self.setup_abort_test(agent_finished=True)
        self.assertIsNone(hqe.finished_on)
        hqe.abort(dispatcher)
        self.god.check_playback()
        self.assertIsNotNone(hqe.finished_on)


    def test_set_finished_on(self):
        """Test that finished_on is set when hqe completes."""
        for status in host_queue_entry_states.Status.values:
            hqe = self._create_hqe(hosts=[1])
            hqe.started_on = datetime.datetime.now()
            hqe.job.update_field('shard_id', 3)
            self.assertIsNone(hqe.finished_on)
            hqe.set_status(status)
            if status in host_queue_entry_states.COMPLETE_STATUSES:
                self.assertIsNotNone(hqe.finished_on)
                self.assertIsNone(hqe.job.shard_id)
            else:
                self.assertIsNone(hqe.finished_on)
                self.assertEquals(hqe.job.shard_id, 3)


class JobTest(BaseSchedulerModelsTest):
    def setUp(self):
        super(JobTest, self).setUp()

        def _mock_create(**kwargs):
            task = models.SpecialTask(**kwargs)
            task.save()
            self._tasks.append(task)
        self.god.stub_with(models.SpecialTask.objects, 'create', _mock_create)


    def _test_pre_job_tasks_helper(self,
                            reboot_before=model_attributes.RebootBefore.ALWAYS):
        """
        Calls HQE._do_schedule_pre_job_tasks() and returns the created special
        task
        """
        self._tasks = []
        queue_entry = scheduler_models.HostQueueEntry.fetch('id = 1')[0]
        queue_entry.job.reboot_before = reboot_before
        queue_entry._do_schedule_pre_job_tasks()
        return self._tasks


    def test_job_request_abort(self):
        django_job = self._create_job(hosts=[5, 6], atomic_group=1)
        job = scheduler_models.Job(django_job.id)
        job.request_abort()
        django_hqes = list(models.HostQueueEntry.objects.filter(job=job.id))
        for hqe in django_hqes:
            self.assertTrue(hqe.aborted)


    def test__atomic_and_has_started__on_atomic(self):
        self._create_job(hosts=[5, 6], atomic_group=1)
        job = scheduler_models.Job.fetch('id = 1')[0]
        self.assertFalse(job._atomic_and_has_started())

        self._update_hqe("status='Pending'")
        self.assertFalse(job._atomic_and_has_started())
        self._update_hqe("status='Verifying'")
        self.assertFalse(job._atomic_and_has_started())
        self.assertFalse(job._atomic_and_has_started())
        self._update_hqe("status='Failed'")
        self.assertFalse(job._atomic_and_has_started())
        self._update_hqe("status='Stopped'")
        self.assertFalse(job._atomic_and_has_started())

        self._update_hqe("status='Starting'")
        self.assertTrue(job._atomic_and_has_started())
        self._update_hqe("status='Completed'")
        self.assertTrue(job._atomic_and_has_started())
        self._update_hqe("status='Aborted'")


    def test__atomic_and_has_started__not_atomic(self):
        self._create_job(hosts=[1, 2])
        job = scheduler_models.Job.fetch('id = 1')[0]
        self.assertFalse(job._atomic_and_has_started())
        self._update_hqe("status='Starting'")
        self.assertFalse(job._atomic_and_has_started())


    def _check_special_tasks(self, tasks, task_types):
        self.assertEquals(len(tasks), len(task_types))
        for task, (task_type, queue_entry_id) in zip(tasks, task_types):
            self.assertEquals(task.task, task_type)
            self.assertEquals(task.host.id, 1)
            if queue_entry_id:
                self.assertEquals(task.queue_entry.id, queue_entry_id)


    def test_run_asynchronous(self):
        self._create_job(hosts=[1, 2])

        tasks = self._test_pre_job_tasks_helper()

        self._check_special_tasks(tasks, [(models.SpecialTask.Task.RESET, 1)])


    def test_run_asynchronous_skip_verify(self):
        job = self._create_job(hosts=[1, 2])
        job.run_verify = False
        job.save()

        tasks = self._test_pre_job_tasks_helper()

        self._check_special_tasks(tasks, [(models.SpecialTask.Task.RESET, 1)])


    def test_run_synchronous_verify(self):
        self._create_job(hosts=[1, 2], synchronous=True)

        tasks = self._test_pre_job_tasks_helper()

        self._check_special_tasks(tasks, [(models.SpecialTask.Task.RESET, 1)])


    def test_run_synchronous_skip_verify(self):
        job = self._create_job(hosts=[1, 2], synchronous=True)
        job.run_verify = False
        job.save()

        tasks = self._test_pre_job_tasks_helper()

        self._check_special_tasks(tasks, [(models.SpecialTask.Task.RESET, 1)])


    def test_run_asynchronous_do_not_reset(self):
        job = self._create_job(hosts=[1, 2])
        job.run_reset = False
        job.run_verify = False
        job.save()

        tasks = self._test_pre_job_tasks_helper()

        self.assertEquals(tasks, [])


    def test_run_synchronous_do_not_reset_no_RebootBefore(self):
        job = self._create_job(hosts=[1, 2], synchronous=True)
        job.reboot_before = model_attributes.RebootBefore.NEVER
        job.save()

        tasks = self._test_pre_job_tasks_helper(
                            reboot_before=model_attributes.RebootBefore.NEVER)

        self._check_special_tasks(tasks, [(models.SpecialTask.Task.VERIFY, 1)])


    def test_run_asynchronous_do_not_reset(self):
        job = self._create_job(hosts=[1, 2], synchronous=False)
        job.reboot_before = model_attributes.RebootBefore.NEVER
        job.save()

        tasks = self._test_pre_job_tasks_helper(
                            reboot_before=model_attributes.RebootBefore.NEVER)

        self._check_special_tasks(tasks, [(models.SpecialTask.Task.VERIFY, 1)])


    def test_run_atomic_group_already_started(self):
        self._create_job(hosts=[5, 6], atomic_group=1, synchronous=True)
        self._update_hqe("status='Starting', execution_subdir=''")

        job = scheduler_models.Job.fetch('id = 1')[0]
        queue_entry = scheduler_models.HostQueueEntry.fetch('id = 1')[0]
        assert queue_entry.job is job
        self.assertEqual(None, job.run(queue_entry))

        self.god.check_playback()


    def test_reboot_before_always(self):
        job = self._create_job(hosts=[1])
        job.reboot_before = model_attributes.RebootBefore.ALWAYS
        job.save()

        tasks = self._test_pre_job_tasks_helper()

        self._check_special_tasks(tasks, [
                (models.SpecialTask.Task.RESET, None)
            ])


    def _test_reboot_before_if_dirty_helper(self):
        job = self._create_job(hosts=[1])
        job.reboot_before = model_attributes.RebootBefore.IF_DIRTY
        job.save()

        tasks = self._test_pre_job_tasks_helper()
        task_types = [(models.SpecialTask.Task.RESET, None)]

        self._check_special_tasks(tasks, task_types)


    def test_reboot_before_if_dirty(self):
        models.Host.smart_get(1).update_object(dirty=True)
        self._test_reboot_before_if_dirty_helper()


    def test_reboot_before_not_dirty(self):
        models.Host.smart_get(1).update_object(dirty=False)
        self._test_reboot_before_if_dirty_helper()


    def test_next_group_name(self):
        django_job = self._create_job(metahosts=[1])
        job = scheduler_models.Job(id=django_job.id)
        self.assertEqual('group0', job._next_group_name())

        for hqe in django_job.hostqueueentry_set.filter():
            hqe.execution_subdir = 'my_rack.group0'
            hqe.save()
        self.assertEqual('my_rack.group1', job._next_group_name('my/rack'))


if __name__ == '__main__':
    unittest.main()

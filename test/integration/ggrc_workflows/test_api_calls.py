# Copyright (C) 2017 Google Inc.
# Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>

import datetime
import unittest

import ddt
import freezegun

from ggrc import db
from ggrc.models import all_models

from integration.ggrc import TestCase
from integration.ggrc.api_helper import Api
from integration.ggrc import generator
from integration.ggrc.models import factories
from integration.ggrc_workflows import generator as wf_generator
from integration.ggrc_workflows import WorkflowTestCase
from integration.ggrc_workflows.models import factories as wf_factories


@ddt.ddt
class TestWorkflowsApiPost(TestCase):

  def setUp(self):
    super(TestWorkflowsApiPost, self).setUp()
    self.api = Api()
    self.generator = wf_generator.WorkflowsGenerator()

  def tearDown(self):
    pass

  def test_send_invalid_data(self):
    data = self.get_workflow_dict()
    del data["workflow"]["title"]
    del data["workflow"]["context"]
    response = self.api.post(all_models.Workflow, data)
    self.assert400(response)
    # TODO: check why response.json["message"] is empty

  def test_create_one_time_workflows(self):
    data = self.get_workflow_dict()
    response = self.api.post(all_models.Workflow, data)
    self.assertEqual(response.status_code, 201)

  def test_create_weekly_workflow(self):
    """Test create valid weekly wf"""
    data = self.get_workflow_dict()
    data["workflow"]["repeat_every"] = 7
    data["workflow"]["unit"] = "day"
    data["workflow"]["title"] = "Weekly"
    response = self.api.post(all_models.Workflow, data)
    self.assertEqual(response.status_code, 201)

  def test_create_annually_workflow(self):
    """Test create valid annual wf"""
    data = self.get_workflow_dict()
    data["workflow"]["repeat_every"] = 12
    data["workflow"]["unit"] = "month"
    data["workflow"]["title"] = "Annually"
    response = self.api.post(all_models.Workflow, data)
    self.assertEqual(response.status_code, 201)

  @ddt.data("wrong value", 0, -4)
  def test_create_wrong_repeat_every_workflow(self, value):  # noqa pylint: disable=invalid-name
    """Test case for invalid repeat_every value"""
    data = self.get_workflow_dict()
    data["workflow"]["repeat_every"] = value
    data["workflow"]["unit"] = "month"
    data["workflow"]["title"] = "Wrong wf"
    response = self.api.post(all_models.Workflow, data)
    self.assertEqual(response.status_code, 400)

  def test_create_wrong_unit_workflow(self):
    """Test case for invalid unit value"""
    data = self.get_workflow_dict()
    data["workflow"]["repeat_every"] = 12
    data["workflow"]["unit"] = "wrong value"
    data["workflow"]["title"] = "Wrong wf"
    response = self.api.post(all_models.Workflow, data)
    self.assertEqual(response.status_code, 400)

  def test_create_task_group(self):
    wf_data = self.get_workflow_dict()
    wf_data["workflow"]["title"] = "Create_task_group"
    wf_response = self.api.post(all_models.Workflow, wf_data)

    data = self.get_task_group_dict(wf_response.json["workflow"])

    response = self.api.post(all_models.TaskGroup, data)
    self.assertEqual(response.status_code, 201)

  # TODO: Api should be able to handle invalid data
  @unittest.skip("Not implemented.")
  def test_create_task_group_invalid_workflow_data(self):  # noqa pylint: disable=invalid-name
    data = self.get_task_group_dict({"id": -1, "context": {"id": -1}})
    response = self.api.post(all_models.TaskGroup, data)
    self.assert400(response)

  @staticmethod
  def get_workflow_dict():
    data = {
        "workflow": {
            "custom_attribute_definitions": [],
            "custom_attributes": {},
            "title": "One_time",
            "description": "",
            "unit": None,
            "repeat_every": None,
            "notify_on_change": False,
            "task_group_title": "Task Group 1",
            "notify_custom_message": "",
            "is_verification_needed": True,
            "owners": None,
            "context": None,
        }
    }
    return data

  @staticmethod
  def get_task_group_dict(workflow):
    data = {
        "task_group": {
            "custom_attribute_definitions": [],
            "custom_attributes": {},
            "_transient": {},
            "contact": {
                "id": 1,
                "href": "/api/people/1",
                "type": "Person"
            },
            "workflow": {
                "id": workflow["id"],
                "href": "/api/workflows/%d" % workflow["id"],
                "type": "Workflow"
            },
            "context": {
                "id": workflow["context"]["id"],
                "href": "/api/contexts/%d" % workflow["context"]["id"],
                "type": "Context"
            },
            "modal_title": "Create Task Group",
            "title": "Create_task_group",
            "description": "",
        }
    }
    return data

  @ddt.data({},
            {"repeat_every": 5,
             "unit": "month"})
  def test_repeat_multiplier_field(self, data):
    """Check repeat_multiplier is set to 0 after wf creation.
    """
    with factories.single_commit():
      workflow = wf_factories.WorkflowFactory(**data)
    workflow_id = workflow.id
    self.assertEqual(
        0,
        all_models.Workflow.query.get(workflow_id).repeat_multiplier
    )

  # TODO: Unskip in the patch 2
  @unittest.skip("Will be activated in patch 2")
  def test_change_to_one_time_wf(self):
    """Check repeat_every and unit can be set to Null only together."""
    with factories.single_commit():
      workflow = wf_factories.WorkflowFactory(repeat_every=12,
                                              unit="day")
    resp = self.api.put(workflow, {"repeat_every": None,
                                   "unit": None})
    self.assert200(resp)

  @ddt.data({"repeat_every": 5},
            {"unit": "month"})
  def test_change_repeat_every(self, data):
    """Check repeat_every or unit can not be changed once set."""
    with factories.single_commit():
      workflow = wf_factories.WorkflowFactory()
    resp = self.api.put(workflow, data)
    self.assert400(resp)

  def test_not_change_to_one_time_wf(self):
    """Check repeat_every or unit can't be set to Null separately.
    This test will be useful in the 2nd patch, where we allow to change
    WF setup
    """
    with factories.single_commit():
      workflow = wf_factories.WorkflowFactory(repeat_every=12,
                                              unit="day")
    resp = self.api.put(workflow, {"repeat_every": None})
    self.assert400(resp)
    resp = self.api.put(workflow, {"unit": None})
    self.assert400(resp)

  @ddt.data(True, False)
  def test_autogen_verification_flag(self, flag):
    """Check is_verification_needed flag for activate WF action."""
    with factories.single_commit():
      workflow = wf_factories.WorkflowFactory(is_verification_needed=flag)
      group = wf_factories.TaskGroupFactory(workflow=workflow)
      wf_factories.TaskGroupTaskFactory(task_group=group)
    data = [{
        "cycle": {
            "autogenerate": True,
            "isOverdue": False,
            "workflow": {
                "id": workflow.id,
                "type": "Workflow",
            },
            "context": {
                "id": workflow.context_id,
                "type": "Context",
            },
        }
    }]
    resp = self.api.send_request(
        self.api.client.post,
        api_link="/api/cycles",
        data=data)
    cycle_id = resp.json[0][1]["cycle"]["id"]
    self.assertEqual(
        flag,
        all_models.Cycle.query.get(cycle_id).is_verification_needed)

  @ddt.data(True, False)
  def test_change_verification_flag_positive(self, flag):  # noqa pylint: disable=invalid-name
    """is_verification_needed flag is not changeable for DRAFT workflow."""
    with factories.single_commit():
      workflow = wf_factories.WorkflowFactory(is_verification_needed=flag)
    self.assertEqual(workflow.status, all_models.Workflow.DRAFT)
    workflow_id = workflow.id
    resp = self.api.put(workflow, {"is_verification_needed": not flag})
    self.assert400(resp)
    self.assertNotEqual(
        all_models.Workflow.query.get(workflow_id).is_verification_needed,
        not flag)

  @ddt.data(True, False)
  def test_change_verification_flag_negative(self, flag):  # noqa pylint: disable=invalid-name
    with freezegun.freeze_time("2017-08-10"):
      with factories.single_commit():
        workflow = wf_factories.WorkflowFactory(
            unit=all_models.Workflow.WEEK_UNIT,
            is_verification_needed=flag,
            repeat_every=1)
        wf_factories.TaskGroupTaskFactory(
            task_group=wf_factories.TaskGroupFactory(
                context=factories.ContextFactory(),
                workflow=workflow
            ),
            # Two cycles should be created
            start_date=datetime.date(2017, 8, 3),
            end_date=datetime.date(2017, 8, 7))
      workflow_id = workflow.id
      self.assertEqual(workflow.status, all_models.Workflow.DRAFT)
      self.generator.activate_workflow(workflow)
      workflow = all_models.Workflow.query.get(workflow_id)
      self.assertEqual(workflow.status, all_models.Workflow.ACTIVE)
      resp = self.api.put(workflow, {"is_verification_needed": not flag})
      self.assert400(resp)
      workflow = all_models.Workflow.query.get(workflow_id)
      self.assertEqual(workflow.is_verification_needed, flag)

      # End all current cycles
      for cycle in workflow.cycles:
        self.generator.modify_object(cycle, {'is_current': False})
      workflow = all_models.Workflow.query.filter(
          all_models.Workflow.id == workflow_id).first()
      self.assertEqual(workflow.status, all_models.Workflow.INACTIVE)
      resp = self.api.put(workflow, {"is_verification_needed": not flag})
      self.assert400(resp)
      workflow = all_models.Workflow.query.get(workflow_id)
      self.assertEqual(workflow.is_verification_needed, flag)

  @ddt.data(True, False)
  def test_not_change_vf_flag(self, flag):
    """Check is_verification_needed not change on update."""
    with factories.single_commit():
      workflow = wf_factories.WorkflowFactory(is_verification_needed=flag)
    workflow_id = workflow.id
    resp = self.api.put(workflow, {"is_verification_needed": flag})
    self.assert200(resp)
    self.assertEqual(
        flag,
        all_models.Workflow.query.get(workflow_id).is_verification_needed)

  @ddt.data(True, False, None)
  def test_create_vf_flag(self, flag):
    """Check is_verification_needed flag setup on create."""
    data = self.get_workflow_dict()
    if flag is None:
      data['workflow'].pop('is_verification_needed', None)
    else:
      data['workflow']['is_verification_needed'] = flag
    resp = self.api.post(all_models.Workflow, data)
    self.assertEqual(201, resp.status_code)
    workflow_id = resp.json['workflow']['id']
    self.assertEqual(
        flag if flag is not None else True,
        all_models.Workflow.query.get(workflow_id).is_verification_needed)


class TestTaskGroupTaskApiPost(WorkflowTestCase):
  """
  Tesk TestTaskGroupTask basic api actions
  """
  def test_create_tgt_correct_dates(self):
    """Test case for correct tgt start_ end_ dates"""
    response, _ = self.generator.generate_task_group_task(
        data={"start_date": datetime.date.today(),
              "end_date": datetime.date.today() + datetime.timedelta(days=4)}
    )
    self.assertEqual(response.status_code, 201)

  def test_create_tgt_wrong_dates(self):
    """Test case for tgt wrong start_ end_ dates"""
    with self.assertRaises(Exception):
      self.generator.generate_task_group_task(
          data={
              "start_date": datetime.date.today(),
              "end_date": datetime.date.today() - datetime.timedelta(days=4)
          }
      )

  def test_tgt_has_view_dates(self):
    """Test get view only fields for TGT."""
    workflow = wf_factories.WorkflowFactory()
    task_group = wf_factories.TaskGroupFactory(workflow=workflow)
    tgt = wf_factories.TaskGroupTaskFactory(task_group=task_group)
    resp = self.api.get(tgt, tgt.id)
    self.assertIn("task_group_task", resp.json)
    self.assertIn("view_start_date", resp.json["task_group_task"])
    self.assertIn("view_end_date", resp.json["task_group_task"])


@ddt.ddt
class TestStatusApiPost(TestCase):
  """Test for api calls changes states of Cycle, Tasks and Groups."""

  def setUp(self):
    super(TestStatusApiPost, self).setUp()
    self.api = Api()
    with factories.single_commit():
      self.workflow = wf_factories.WorkflowFactory()
      self.cycle = wf_factories.CycleFactory(workflow=self.workflow)
      self.group = wf_factories.CycleTaskGroupFactory(
          cycle=self.cycle,
          context=self.cycle.workflow.context
      )
      self.task = wf_factories.CycleTaskFactory(
          cycle=self.cycle,
          cycle_task_group=self.group,
          context=self.cycle.workflow.context
      )

  def setup_cycle_state(self, is_verification_needed):
    """Setup cycle is_verification_needed state."""
    self.cycle.is_verification_needed = is_verification_needed
    db.session.add(self.cycle)
    db.session.commit()

  @ddt.data(u"Assigned",
            u"InProgress",
            u"Finished",
            u"Verified",
            u"Declined")
  def test_set_state_verified_task(self, state):
    """Check state for verification required task."""
    self.setup_cycle_state(True)
    resp = self.api.put(self.task, data={"status": state})
    task = all_models.CycleTaskGroupObjectTask.query.get(
        resp.json["cycle_task_group_object_task"]["id"]
    )
    self.assertEqual(state, task.status)

  @ddt.data((u"Assigned", True),
            (u"InProgress", True),
            (u"Finished", True),
            (u"Verified", False),
            (u"Declined", False))
  @ddt.unpack
  def test_state_non_verified_task(self, state, is_valid):
    """Check state for verification non required task."""
    self.setup_cycle_state(False)
    resp = self.api.put(self.task, data={"status": state})
    if is_valid:
      task = all_models.CycleTaskGroupObjectTask.query.get(
          resp.json["cycle_task_group_object_task"]["id"]
      )
      self.assertEqual(state, task.status)
    else:
      self.assert400(resp)

  @ddt.data(u"Assigned",
            u"InProgress",
            u"Finished",
            u"Verified")
  def test_state_verified_group(self, state):
    """Check state for verification required group."""
    self.setup_cycle_state(True)
    resp = self.api.put(self.group, data={"status": state})
    group = all_models.CycleTaskGroup.query.get(
        resp.json["cycle_task_group"]["id"]
    )
    self.assertEqual(state, group.status)

  @ddt.data((u"Assigned", True),
            (u"InProgress", True),
            (u"Finished", True),
            (u"Verified", False))
  @ddt.unpack
  def test_state_non_verified_group(self, state, is_valid):
    """Check state for verification non required group."""
    self.setup_cycle_state(False)
    resp = self.api.put(self.group, data={"status": state})
    if is_valid:
      group = all_models.CycleTaskGroup.query.get(
          resp.json["cycle_task_group"]["id"]
      )
      self.assertEqual(state, group.status)
    else:
      self.assert400(resp)

  @ddt.data(u"Assigned",
            u"InProgress",
            u"Finished",
            u"Verified")
  def test_state_verified_cycle(self, state):
    """Check state for verification required cycle."""
    self.setup_cycle_state(True)
    resp = self.api.put(self.cycle, data={"status": state})
    cycle = all_models.Cycle.query.get(resp.json["cycle"]["id"])
    self.assertEqual(state, cycle.status)

  @ddt.data((u"Assigned", True),
            (u"InProgress", True),
            (u"Finished", True),
            (u"Verified", False))
  @ddt.unpack
  def test_state_non_verified_cycle(self, state, is_valid):
    """Check state for verification non required cycle."""
    self.setup_cycle_state(False)
    resp = self.api.put(self.cycle, data={"status": state})
    if is_valid:
      cycle = all_models.Cycle.query.get(resp.json["cycle"]["id"])
      self.assertEqual(state, cycle.status)
    else:
      self.assert400(resp)

  @ddt.data(True, False)
  def test_change_is_verification(self, flag):
    """Try to change cycle is_verification_needed."""
    self.setup_cycle_state(flag)
    resp = self.api.put(self.cycle, data={"is_verification_needed": flag})
    self.assert200(resp)
    cycle = all_models.Cycle.query.get(resp.json["cycle"]["id"])
    self.assertEqual(flag, cycle.is_verification_needed)

  @ddt.data(True, False)
  def test_change_is_vf_wrong(self, flag):
    """Try to change cycle is_verification_needed not changed."""
    self.setup_cycle_state(flag)
    resp = self.api.put(self.cycle, data={"is_verification_needed": not flag})
    self.assert200(resp)
    cycle = all_models.Cycle.query.get(resp.json["cycle"]["id"])
    self.assertEqual(flag, cycle.is_verification_needed)

  @ddt.data(True, False)
  def test_change_cycle_none_flag(self, flag):
    """Try to change cycle is_verification_needed not changed
    by not sending is_verification_flag."""
    self.setup_cycle_state(flag)
    resp = self.api.put(self.cycle, not_send_fields=["is_verification_needed"])
    self.assert200(resp)
    cycle = all_models.Cycle.query.get(resp.json["cycle"]["id"])
    self.assertEqual(flag, cycle.is_verification_needed)

  @ddt.data(True, False)
  def test_change_wf_none_flag(self, flag):
    """Try to change workflow is_verification_needed not changed by
    not sending is_verification_flag."""
    db.engine.execute(
        "update workflows set is_verification_needed={} where id={}".format(
            flag, self.workflow.id
        )
    )
    resp = self.api.put(self.workflow,
                        not_send_fields=["is_verification_needed"])
    self.assert200(resp)
    workflow = all_models.Workflow.query.get(resp.json["workflow"]["id"])
    self.assertEqual(flag, workflow.is_verification_needed)

  @ddt.data((u"InProgress", True, True),
            (u"InProgress", False, True),
            (u"Declined", True, True),
            (u"Verified", True, False),
            (u"Finished", True, True),
            (u"Finished", False, False))
  @ddt.unpack
  def test_move_to_history(self, state, is_vf_needed, is_current):
    """Moved to history if state changed."""
    self.setup_cycle_state(is_vf_needed)
    resp = self.api.put(self.task, data={"status": state})
    task = all_models.CycleTaskGroupObjectTask.query.get(
        resp.json["cycle_task_group_object_task"]["id"]
    )
    self.assertEqual(is_current, task.cycle.is_current)


@ddt.ddt
class TestCloneWorkflow(TestCase):

  def setUp(self):
    super(TestCloneWorkflow, self).setUp()
    self.object_generator = generator.ObjectGenerator()

  @ddt.data(
      (None, None),
      (all_models.Workflow.DAY_UNIT, 10),
      (all_models.Workflow.MONTH_UNIT, 10),
      (all_models.Workflow.WEEK_UNIT, 10),
  )
  @ddt.unpack
  def test_workflow_copy(self, unit, repeat_every):
    """Check clone wf with unit and repeat."""
    with factories.single_commit():
      workflow = wf_factories.WorkflowFactory(unit=unit,
                                              repeat_every=repeat_every)
    _, clone_wf = self.object_generator.generate_object(
        all_models.Workflow, {"title": "WF - copy 1", "clone": workflow.id})
    self.assertEqual(unit, clone_wf.unit)
    self.assertEqual(repeat_every, clone_wf.repeat_every)

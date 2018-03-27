# Copyright (C) 2018 Google Inc.
# Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>

"""Integration tests for IssueTracker integration"""

from collections import OrderedDict

from mock import patch

from ggrc import db
from ggrc import models
from ggrc.models import all_models
from ggrc.models.hooks import issue_tracker
from ggrc.integrations import issues as issues_module
from ggrc.integrations import utils

from integration.ggrc.models import factories
from integration.ggrc import generator
from integration.ggrc.access_control import acl_helper
from integration.ggrc.snapshotter import SnapshotterBaseTestCase


class TestIssueTrackerIntegration(SnapshotterBaseTestCase):

  """Test set for IssueTracker integration functionality"""

  # pylint: disable=invalid-name

  def setUp(self):
    # pylint: disable=super-on-old-class
    # pylint seems to get confused, mro chain successfully resolves and returns
    # <type 'object'> as last entry.
    super(TestIssueTrackerIntegration, self).setUp()

    self.client.get("/login")
    self.headers = {
        'Content-Type': 'application/json',
        "X-Requested-By": "GGRC",
        "X-export-view": "blocks",
    }

  # pylint: disable=unused-argument
  @patch('ggrc.integrations.issues.Client.update_issue')
  def test_update_issuetracker_info(self, mock_update_issue):
    """Test that issuetracker issues are updated by the utility"""
    with patch.object(issue_tracker, '_is_issue_tracker_enabled',
                      return_value=True):
      iti_issue_id = []
      for _ in range(2):
        iti = factories.IssueTrackerIssueFactory()
        iti_issue_id.append(iti.issue_id)
        asmt = iti.issue_tracked_obj
        asmt_id = asmt.id
        audit = asmt.audit
        self.api.modify_object(audit, {
            "issue_tracker": {
                "enabled": True,
                "component_id": "11111",
                "hotlist_id": "222222",
            },
        })
        asmt = db.session.query(models.Assessment).get(asmt_id)
        self.api.modify_object(asmt, {
            "issue_tracker": {
                "enabled": True,
                "component_id": "11111",
                "hotlist_id": "222222",
            },
        })
        asmt = db.session.query(models.Assessment).get(asmt_id)
        self.api.modify_object(asmt, {
            "issue_tracker": {
                "enabled": True,
                "component_id": "11111",
                "hotlist_id": "222222",
                "issue_priority": "P4",
                "issue_severity": "S3",
            },
        })
      self.api.delete(asmt)
      with patch.object(issues_module.Client, 'update_issue',
                        return_value=None) as mock_method:
        utils.sync_issue_tracker_statuses()
        mock_method.assert_called_once_with(iti_issue_id[0],
                                            {'status': 'ASSIGNED',
                                             'priority': u'P4',
                                             'type': None,
                                             'severity': u'S3'})

  @patch('ggrc.integrations.issues.Client.update_issue')
  def test_update_issuetracker_info_on_asmt_import(self, mock_update_issue):
    """Test issuetracker issue updated when comment for assessment imported"""
    with patch.object(issue_tracker, '_is_issue_tracker_enabled',
                      return_value=True):
      iti = factories.IssueTrackerIssueFactory(enabled=True)
      asmt = iti.issue_tracked_obj
      asmt_id = asmt.id
      audit = asmt.audit
      comment = "Some imported comment"
      self.import_data(OrderedDict([
          ("object_type", "Assessment"),
          ("Code*", asmt.slug),
          ("Audit", audit.slug),
          ("Comments", comment),
      ]), dry_run=False)
      asmt = db.session.query(models.Assessment).get(asmt_id)
      self.assertEqual(asmt.comments[0].description, "Some imported comment")
      mock_update_issue.assert_called_once_with(iti.issue_id,
                                                {'status': 'ASSIGNED',
                                                 'priority': None,
                                                 'type': None,
                                                 'severity': None,
                                                 'comment': comment})


@patch("ggrc.models.hooks.issue_tracker._is_issue_tracker_enabled",
       return_value=True)
@patch("ggrc.integrations.issues.Client")
class TestIssueTrackerIntegrationPeople(SnapshotterBaseTestCase):
  """Test people used in IssueTracker Issues."""

  EMAILS = {
      "Audit Captains": {"audit_captain_1@example.com",
                         "audit_captain_2@example.com"},
      "Auditors": {"auditor_1@example.com", "auditor_2@example.com"},
      "Creators": {"creator_1@example.com", "creator_2@example.com"},
      "Assignees": {"assignee_1@example.com", "assignee_2@example.com"},
      "Verifiers": {"verifier_1@example.com", "verifier_2@example.com"},
      "Primary Contacts": {"primary_contact_1@example.com",
                           "primary_contact_2@example.com"},
      "Secondary Contacts": {"secondary_contact_1@example.com",
                             "secondary_contact_2@example.com"},
      "Custom Role": {"curom_role_1@example.com"},
  }

  ROLE_NAMES = (
      "Creators",
      "Assignees",
      "Verifiers",
      "Primary Contacts",
      "Secondary Contacts",
      "Custom Role"
  )

  def setUp(self):
    super(TestIssueTrackerIntegrationPeople, self).setUp()
    self.generator = generator.ObjectGenerator()

    factories.AccessControlRoleFactory(
        name='Custom Role',
        internal=False,
        object_type="Assessment",
    )

    # fetch all roles mentioned in self.EMAILS
    self.roles = {
        role.name: role
        for role in all_models.AccessControlRole.query.filter(
            all_models.AccessControlRole.name.in_(
                self.EMAILS.keys(),
            ),
        )
    }

    with factories.single_commit():
      self.audit = factories.AuditFactory()

      self.people = {
          role_name: [factories.PersonFactory(email=email)
                      for email in emails]
          for role_name, emails in self.EMAILS.iteritems()
      }

  def setup_audit_people(self, role_name_to_people):
    """Assign roles to people provided."""
    with factories.single_commit():
      for role_name, people in role_name_to_people.iteritems():
        role = self.roles[role_name]
        for person in people:
          factories.AccessControlListFactory(person=person,
                                             ac_role=role,
                                             object=self.audit)

  def create_asmt_with_issue_tracker(self, role_name_to_people,
                                     issue_tracker=None):
    """Create Assessment with issue_tracker parameters and ACL."""
    access_control_list = acl_helper.get_acl_list({
        person.id: self.roles[role_name].id
        for role_name, people in role_name_to_people.iteritems()
        for person in people
    })
    issue_tracker_with_defaults = {
        "enabled": True,
        "component_id": hash("Default Component id"),
        "hotlist_id": hash("Default Hotlist id"),
        "issue_type": "Default Issue type",
        "issue_priority": "Default Issue priority",
        "issue_severity": "Default Issue severity",
    }
    issue_tracker_with_defaults.update(issue_tracker or {})

    _, asmt = self.generator.generate_object(
        all_models.Assessment,
        data={
            "audit": {"id": self.audit.id, "type": self.audit.type},
            "issue_tracker": issue_tracker_with_defaults,
            "access_control_list": access_control_list,
        }
    )

    return asmt

  def test_new_assessment_people(self, client_mock, _):
    """External Issue for Assessment contains correct people."""
    client_instance = client_mock.return_value
    client_instance.create_issue.return_value = {"issueId": 42}

    self.setup_audit_people({
        role_name: people for role_name, people in self.people.items()
        if role_name in ("Audit Captains", "Auditors")
    })

    component_id = hash("Component id")
    hotlist_id = hash("Hotlist id")
    issue_type = "Issue type"
    issue_priority = "Issue priority"
    issue_severity = "Issue severity"

    asmt = self.create_asmt_with_issue_tracker(
        role_name_to_people={
            role_name: people for role_name, people in self.people.items()
            if role_name in self.ROLE_NAMES
        },
        issue_tracker={
            "component_id": component_id,
            "hotlist_id": hotlist_id,
            "issue_type": issue_type,
            "issue_priority": issue_priority,
            "issue_severity": issue_severity,
        },
    )

    expected_cc_list = list(
        self.EMAILS["Assignees"] - {min(self.EMAILS["Assignees"])}
    )

    # pylint: disable=protected-access; we assert by non-exported constants
    client_instance.create_issue.assert_called_once_with({
        # common fields
        "comment": (issue_tracker._INITIAL_COMMENT_TMPL %
                    issue_tracker._get_assessment_url(asmt)),
        "component_id": component_id,
        "hotlist_ids": [hotlist_id],
        "priority": issue_priority,
        "severity": issue_severity,
        "status": "ASSIGNED",
        "title": asmt.title,
        "type": issue_type,

        # person-related fields
        "reporter": min(self.EMAILS["Audit Captains"]),
        "assignee": min(self.EMAILS["Assignees"]),
        "verifier": min(self.EMAILS["Assignees"]),
        "ccs": expected_cc_list,
    })

  def test_missing_audit_captains(self, client_mock, _):
    """Reporter email is None is no Audit Captains present."""
    client_instance = client_mock.return_value
    client_instance.create_issue.return_value = {"issueId": 42}

    self.setup_audit_people({
        "Audit Captains": [],
        "Auditors": self.people["Auditors"],
    })

    self.create_asmt_with_issue_tracker(
        role_name_to_people={
            role_name: people for role_name, people in self.people.items()
            if role_name in ("Creators", "Assignees", "Verifiers")
        },
    )

    client_instance.create_issue.assert_called_once()
    self.assertIs(client_instance.create_issue.call_args[0][0]["reporter"],
                  None)

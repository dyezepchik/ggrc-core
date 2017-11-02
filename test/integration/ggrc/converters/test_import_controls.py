# Copyright (C) 2017 Google Inc.
# Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>

# pylint: disable=maybe-no-member, invalid-name

"""Test request import and updates."""

import collections

from ggrc import models

from integration.ggrc import TestCase
from integration.ggrc.models import factories


class TestControlsImport(TestCase):
  """Basic Assessment import tests with.

  This test suite should test new Assessment imports, exports, and updates.
  The main focus of these tests is checking error messages for invalid state
  transitions.
  """

  def setUp(self):
    """Set up for Assessment test cases."""
    super(TestControlsImport, self).setUp()
    self.client.get("/login")

  def test_import_controls_with_evidence(self):
    """Test importing of assessments with templates."""
    response = self.import_file("controls_no_warnings.csv")
    self._check_csv_response(response, {})

    evidence = models.Document.query.filter_by(title="Some title 3").all()
    self.assertEqual(len(evidence), 1)
    control = models.Control.query.filter_by(slug="control-3").first()
    self.assertEqual(control.document_evidence[0].title, "Some title 3")

  def test_import_control_end_date(self):
    """End date on control should be non editable."""
    control = factories.ControlFactory()
    self.assertIsNone(control.end_date)
    resp = self.import_data(collections.OrderedDict([
        ("object_type", "Control"),
        ("code", control.slug),
        ("Last Deprecated Date", "06/06/2017"),
    ]))
    control = models.Control.query.get(control.id)
    self.assertEqual(1, len(resp))
    self.assertEqual(1, resp[0]["updated"])
    self.assertIsNone(control.end_date)

  def test_import_control_deprecated(self):
    """End date should be set up after import in deprecated state."""
    control = factories.ControlFactory()
    self.assertIsNone(control.end_date)
    resp = self.import_data(collections.OrderedDict([
        ("object_type", "Control"),
        ("code", control.slug),
        ("state", models.Control.DEPRECATED),
    ]))
    control = models.Control.query.get(control.id)
    self.assertEqual(1, len(resp))
    self.assertEqual(1, resp[0]["updated"])
    self.assertEqual(control.status, control.DEPRECATED)
    self.assertIsNotNone(control.end_date)

  def test_import_control_duplicate_slugs(self):
    """Test import does not fail when two objects with the same slug are
    imported."""
    with factories.single_commit():
      role_name = factories.AccessControlRoleFactory(
          object_type="Control").name
      emails = [factories.PersonFactory().email for _ in range(2)]

    control = factories.ControlFactory()
    self.import_data(collections.OrderedDict([
        ("object_type", "Control"),
        ("code", control.slug),
        ("title", "Title"),
        ("Admin", "user@example.com"),
        (role_name, "\n".join(emails)),
    ]))

    import_dicts = [
        collections.OrderedDict([
            ("object_type", "Control"),
            ("code", control.slug),
            ("title", "Title"),
            ("Admin", "user@example.com"),
            (role_name, "\n".join(emails)),
        ]),
        collections.OrderedDict([
            ("object_type", "Control"),
            ("code", control.slug),
            ("title", "Title"),
            ("Admin", "user@example.com"),
            (role_name, "\n".join(emails)),
        ]),
    ]
    response = self.import_data(*import_dicts)
    fail_response = {u'message': u'Import failed due to server error.',
                     u'code': 400}
    self.assertNotEqual(response, fail_response)

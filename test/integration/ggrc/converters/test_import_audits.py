# Copyright (C) 2018 Google Inc.
# Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>

# pylint: disable=maybe-no-member, invalid-name

"""Test request import and updates."""

import collections
import datetime
import ddt

from ggrc import models
from ggrc.converters import errors

from freezegun import freeze_time

from integration.ggrc import TestCase
from integration.ggrc.models import factories


@ddt.ddt
class TestAuditsImport(TestCase):
  """Basic Audits import tests with.

  This test suite should test new Audits imports.
  """

  def setUp(self):
    """Set up for Audit import test cases."""
    super(TestAuditsImport, self).setUp()
    self.client.get("/login")

  def test_import_audit_last_deprecated_date(self):
    """Last Deprecated Date on audit should be not importing."""
    with freeze_time("2017-01-25"):
      audit = factories.AuditFactory(status="Deprecated")

    resp = self.import_data(collections.OrderedDict([
        ("object_type", "Audit"),
        ("code", audit.slug),
        ("Last Deprecated Date", "02/25/2017"),
    ]))

    result_audit = models.Audit.query.get(audit.id)
    expected_error = errors.EXPORT_ONLY_WARNING.format(
        line=3, column_name="Last Deprecated Date")
    self.assertEqual(1, len(resp))
    self.assertEqual(expected_error, resp[0]["row_warnings"][0])
    self.assertEqual(result_audit.last_deprecated_date,
                     datetime.date(2017, 1, 25))

  def test_import_audit_status(self):
    """If import Deprecated status, then change last deprecated date"""
    audit = factories.AuditFactory()

    with freeze_time("2017-01-25"):
      resp = self.import_data(collections.OrderedDict([
          ("object_type", "Audit"),
          ("code", audit.slug),
          ("State", "Deprecated"),
      ]))

    result_audit = models.Audit.query.get(audit.id)

    self.assertEqual(1, len(resp))
    self.assertEqual(1, resp[0]["updated"])
    self.assertEqual(result_audit.last_deprecated_date,
                     datetime.date(2017, 1, 25))

  def test_import_audit_repeat_deprecated_status(self):
    """Last Deprecated Date on audit should be non editable."""
    with freeze_time("2017-01-25"):
      audit = factories.AuditFactory(status="Deprecated")

    resp = self.import_data(collections.OrderedDict([
        ("object_type", "Audit"),
        ("code", audit.slug),
        ("Status", "Deprecated"),
    ]))

    result_audit = models.Audit.query.get(audit.id)

    self.assertEqual(1, len(resp))
    self.assertEqual(1, resp[0]["updated"])
    self.assertEqual(result_audit.last_deprecated_date,
                     datetime.date(2017, 1, 25))

  def test_import_depr_audit_date(self):
    """Last Deprecated Date on audit should be updated to current date."""
    with freeze_time("2017-01-25"):
      audit = factories.AuditFactory()

    with freeze_time("2017-01-27"):
      resp = self.import_data(collections.OrderedDict([
          ("object_type", "Audit"),
          ("code", audit.slug),
          ("State", "Deprecated"),
          ("Last Deprecated Date", "02/25/2017"),
      ]))

    result_audit = models.Audit.query.get(audit.id)
    self.assertEqual(1, len(resp))
    self.assertEqual(1, resp[0]["updated"])
    self.assertEqual(result_audit.last_deprecated_date,
                     datetime.date(2017, 1, 27))

  @ddt.data((True, True), (False, True), (True, False), (False, False))
  def test_import_audit_cases(self, (empty_object, empty_import)):
    """Check different cases of import audits.

    In this test covered next scenarios:
    1) object has empty last_deprecated_date field, user imports empty
       field - no warnings
    2) object has non-empty last_deprecated_date field, user imports empty
       field - no warnings
    3) object has empty last_deprecated_date field, user imports non-empty
       field - warning
    4) object has non-empty last_deprecated_date field, user imports non-empty
       field - warning
    """
    if empty_object:
      audit = factories.AuditFactory()
    else:
      audit = factories.AuditFactory(status="Deprecated")
    if empty_import:
      resp = self.import_data(collections.OrderedDict([
          ("object_type", "Audit"),
          ("code", audit.slug),
          ("Last Deprecated Date", ""),
      ]))
    else:
      resp = self.import_data(collections.OrderedDict([
          ("object_type", "Audit"),
          ("code", audit.slug),
          ("Last Deprecated Date", "02/25/2017"),
      ]))

    expected_errors = {
        "Audit": {
            "row_warnings": {
                errors.EXPORT_ONLY_WARNING.format(
                    line=3,
                    column_name=u"Last Deprecated Date"
                )
            }
        }
    }

    if empty_import:
      self._check_csv_response(resp, {})
    else:
      self._check_csv_response(resp, expected_errors)

  @ddt.data("01/25/2017", "2017-01-25")
  def test_import_same_audit(self, formatted_date):
    """Check case of import the same last_deprecated_date field in audit.

    If user imports the audit with the same last_deprecated_date field -
    imported without warnings.
    """
    with freeze_time("2017-01-25"):
      audit = factories.AuditFactory(title="test", status="Deprecated")

    resp = self.import_data(collections.OrderedDict([
        ("object_type", "Audit"),
        ("code", audit.slug),
        ("title", "New title"),
        ("Last Deprecated Date", formatted_date),
    ]))

    self._check_csv_response(resp, {})

  def test_import_invalid_date(self):
    """Check case of import invalid last_deprecated_date field in audit."""
    with freeze_time("2017-01-25"):
      audit = factories.AuditFactory(title="test", status="Deprecated")

    resp = self.import_data(collections.OrderedDict([
        ("object_type", "Audit"),
        ("code", audit.slug),
        ("title", "New title"),
        ("Last Deprecated Date", "0125/2017"),
    ]))

    expected_errors = {
        "Audit": {
            "row_warnings": {
                errors.EXPORT_ONLY_WARNING.format(
                    line=3,
                    column_name=u"Last Deprecated Date"
                )
            }
        }
    }

    self._check_csv_response(resp, expected_errors)

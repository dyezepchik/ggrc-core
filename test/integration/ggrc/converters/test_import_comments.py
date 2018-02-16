# Copyright (C) 2018 Google Inc.
# Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>

"""Tests import of comments."""

import ddt

from integration.ggrc import TestCase
from ggrc.models import Assessment


@ddt.ddt
class TestCommentsImport(TestCase):
  """Test comments import"""

  @classmethod
  def setUpClass(cls):
    TestCase.clear_data()
    cls.response = TestCase._import_file("import_comments.csv")

  def setUp(self):
    """Log in before performing queries."""
    self._check_csv_response(self.response, {})
    self.client.get("/login")

  @ddt.data(("Assessment 1", ["comment"]),
            ("Assessment 2", ["some comment"]),
            ("Assessment 3", ["<a href=\"goooge.com\">link</a>"]),
            ("Assessment 4", ["comment1", "comment2", "comment3"]),
            ("Assessment 5", ["one;two", "three;", "four", "hello"]),
            ("Assessment 6", ["a normal comment with {} characters"]))
  @ddt.unpack
  def test_assessment_comments(self, slug, expected_comments):
    """Test assessment comments import"""
    asst = Assessment.query.filter_by(slug=slug).first()
    comments = [comment.description for comment in asst.comments]
    self.assertEqual(comments, expected_comments)

  def test_author_role_in_comment(self):
    """Test comment author's role is set correctly on import"""
    slug = "Assessment 1"
    asmt = Assessment.query.filter_by(slug=slug).first()
    comment = asmt.comments[0]
    self.assertIn("Assignees", comment.assignee_type)
    self.assertIn("Creators", comment.assignee_type)

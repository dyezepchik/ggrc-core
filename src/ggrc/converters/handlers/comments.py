# Copyright (C) 2018 Google Inc.
# Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>

"""Handlers comment entries."""

from ggrc import db

from ggrc.converters import errors
from ggrc.converters.handlers.handlers import ColumnHandler
from ggrc.models import all_models
from ggrc.login import get_current_user, get_current_user_id


class CommentColumnHandler(ColumnHandler):
  """ Handler for comments """

  COMMENTS_SEPARATOR = ";;"

  @staticmethod
  def split_comments(raw_value):
    """Split comments"""
    res = [comment.strip() for comment in
           raw_value.rsplit(CommentColumnHandler.COMMENTS_SEPARATOR)
           if comment.strip()]
    return res

  def parse_item(self):
    """Parse a list of comments to be mapped.

    Parse a COMMENTS_SEPARATOR separated list of comments

    Returns:
      list of comments
    """
    comments = self.split_comments(self.raw_value)
    if self.raw_value and not comments:
      self.add_warning(errors.WRONG_VALUE,
                       column_name=self.display_name)
    return comments

  def get_value(self):
    return ""

  def set_obj_attr(self):
    """ Create comments """
    if self.dry_run or not self.value:
      return
    current_obj = self.row_converter.obj
    for description in self.value:
      current_user = get_current_user()
      assignee_types = current_obj.assignees.get(current_user, [])
      assignee_type = ",".join(assignee_types) or None

      comment = all_models.Comment(description=description,
                        assignee_type=assignee_type,
                        modified_by_id=get_current_user_id())
      db.session.add(comment)
      mapping = all_models.Relationship(source=current_obj,
                                        destination=comment)
      db.session.add(mapping)

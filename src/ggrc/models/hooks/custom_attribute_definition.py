# Copyright (C) 2018 Google Inc.
# Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>

"""Custom Attribute Definition hooks"""

import datetime

from ggrc.models import all_models
from ggrc.services import signals
from ggrc.login import get_current_user_id


def init_hook():
  """Initialize CAD hooks"""
  # pylint: disable=unused-variable
  @signals.Restful.model_deleted.connect_via(
      all_models.CustomAttributeDefinition)
  def handle_cad_delete(sender, obj, src=None, service=None):
    """Make sure create revision after deleting CAD from admin panel"""
    # pylint: disable=unused-argument
    now = datetime.datetime.utcnow()
    current_user_id = get_current_user_id()
    for model in all_models.all_models:
      if model._inflector.table_singular != obj.definition_type:
        continue
      for instance in model.eager_query():
        instance.updated_at = now
        instance.modified_by_id = current_user_id
      return

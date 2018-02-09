# Copyright (C) 2018 Google Inc.
# Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>

"""Workflow specific Resources implementation."""

import datetime

import sqlalchemy as sa
from flask import current_app

from ggrc import db
from ggrc import utils
from ggrc.services import common

import ggrc_workflows


class CycleTaskResource(common.Resource):
  """Contains CycleTask's specific Resource implementation."""

  def propagate_status(self, updated_objects):
    """Propagate task status to upper tree instances."""
    if not updated_objects:
      return
    signal_context = []
    for instance in updated_objects:
      status_history = sa.inspect(instance).attrs["status"].history
      old_status = status_history.deleted[0]
      new_status = status_history.added[0]
      context_element = ggrc_workflows.Signals.StatusChangeSignalObjectContext(
          instance=instance,
          new_status=new_status,
          old_status=old_status
      )
      signal_context.append(context_element)
    ggrc_workflows.Signals.status_change.send(self.model,
                                              objs=signal_context)
    ggrc_workflows.update_cycle_task_tree(updated_objects)

  @staticmethod
  def log_event():
    """Log event action."""
    common.get_modified_objects(db.session)
    common.log_event(db.session, flush=False)

  def patch(self):
    """PATCH operation handler."""
    src = self.request.json
    if self.request.mimetype != 'application/json':
      return current_app.make_response(
          ('Content-Type must be application/json', 415, []))
    with utils.benchmark("Do bulk update"):
      updated_objects = self.model.bulk_update(src)
    with utils.benchmark("Status propagation on bulk update"):
      self.propagate_status(updated_objects)
    with utils.benchmark("Log Event"):
      self.log_event()
    with utils.benchmark("Commit"):
      db.session.commit()
    with utils.benchmark("Make response"):
      updated_ids = {u.id for u in updated_objects}
      skipped_ids = {int(item['id']) for item in src
                     if int(item["id"]) not in updated_ids}
      result = [{'status': 'updated', 'id': idx} for idx in updated_ids]
      result.extend([{'status': 'skipped', 'id': idx} for idx in skipped_ids])
      return self.json_success_response(result, datetime.datetime.utcnow())

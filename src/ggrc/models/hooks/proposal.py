# Copyright (C) 2018 Google Inc.
# Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>

"""AccessControlList creation hooks."""

import datetime

from sqlalchemy import inspect

from ggrc.services import signals
from ggrc.models import all_models
from ggrc.models import comment
from ggrc import login
from ggrc.utils.revisions_diff import applier
from ggrc.models import proposal as proposal_model


def is_status_changed_to(required_status, obj):
  return (inspect(obj).attrs.status.history.has_changes() and
          obj.status == required_status)


def add_comment_about(proposal, reason, txt):
  """Create comment about proposal for reason with required text."""
  if not isinstance(proposal.instance, comment.Commentable):
    return
  txt = txt or ""
  txt = txt.strip()
  if txt.startswith("<p>"):
    txt = txt[3:]
    if txt.endswith("</p>"):
      txt = txt[:-4]
  txt = txt.strip()
  comment_text = proposal.build_comment_text(reason, txt, proposal.proposed_by)
  created_comment = all_models.Comment(
      description=comment_text,
      modified_by_id=login.get_current_user_id(),
      initiator_instance=proposal)
  all_models.Relationship(
      source=proposal.instance,
      destination=created_comment)

# pylint: disable=unused-argument
# pylint: disable=too-many-arguments


def apply_proposal(
    sender, obj=None, src=None, service=None,
    event=None, initial_state=None):  # noqa
  """Apply proposal procedure hook."""
  if not is_status_changed_to(obj.STATES.APPLIED, obj):
    return
  current_user = login.get_current_user()
  now = datetime.datetime.utcnow()
  obj.applied_by = current_user
  obj.apply_datetime = now
  if applier.apply_action(obj.instance, obj.content):
    obj.instance.modified_by = current_user
    obj.instance.updated_at = now
  add_comment_about(obj, obj.STATES.APPLIED, obj.apply_reason)


def decline_proposal(
    sender, obj=None, src=None, service=None,
    event=None, initial_state=None):  # noqa
  """Decline proposal procedure hook."""
  if not is_status_changed_to(obj.STATES.DECLINED, obj):
    return
  obj.declined_by = login.get_current_user()
  obj.decline_datetime = datetime.datetime.utcnow()
  add_comment_about(obj, obj.STATES.DECLINED, obj.decline_reason)


def make_proposal(
    sender, obj=None, src=None, service=None,
    event=None, initial_state=None):  # noqa
  """Make proposal procedure hook."""
  obj.proposed_by = login.get_current_user()
  add_comment_about(obj, obj.STATES.PROPOSED, obj.agenda)


def set_permissions(sender, obj=None, src=None, service=None,
                    event=None, initial_state=None):  # noqa
  """Set permissions to proposals based on instance ACL model."""
  if sender == all_models.Proposal:
    proposal_model.set_acl_to(obj)
  else:
    proposal_model.set_acl_to_all_proposals_for(obj)

# pylint: enable=unused-argument
# pylint: enable=too-many-arguments


def init_hook():
  """Init proposal signal handlers."""
  signals.Restful.model_posted.connect(make_proposal,
                                       all_models.Proposal,
                                       weak=False)
  signals.Restful.model_put.connect(apply_proposal,
                                    all_models.Proposal,
                                    weak=False)
  signals.Restful.model_put.connect(decline_proposal,
                                    all_models.Proposal,
                                    weak=False)
  for model in all_models.all_models:
    signals.Restful.model_posted.connect(set_permissions,
                                         model,
                                         weak=False)
    signals.Restful.model_put.connect(set_permissions,
                                      model,
                                      weak=False)

# Copyright (C) 2018 Google Inc.
# Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>

"""Proposal utils methods."""

import collections
import datetime
import urlparse

from werkzeug import exceptions
import flask
from google.appengine.api import mail

from ggrc import db
from ggrc import rbac
from ggrc import settings
from ggrc import utils
from ggrc.access_control import roleable
from ggrc.models import all_models
from ggrc.models import reflection
from ggrc.fulltext import attributes as ft_attrs


EmailProposalContext = collections.namedtuple(
    "EmailProposalContext",
    ["agenda",
     "proposed_by_name",
     "instance",
     "values_dict",
     "values_list_dict",
     "object_url"]
)


def _get_object_presentation(obj_dict):
  """Returns one of object possible presentation:

  - display_name
  - title
  - name
  - slug

  if Nothing is presented in serrialized object
  than it will return `{tytle}_{id}` presentation.
  """
  keys = ("display_name", "title", "name", "slug")
  for key in keys:
    if obj_dict.get(key):
      return obj_dict[key]
  return "{}_{}".format(obj_dict["type"], obj_dict["id"])


def get_fields_list_values(proposal, acr_dict, person_dict):
  """Returns tree like:

    {
        "field_name_1": {
            "added": ["element_1", "element_2"],
            "deleted": ["element_3", "element_4"],
        },
        "field_name_2": {
            "added": ["element_1", "element_3"],
            "deleted": ["element_4", "element_5"],
        },
        "field_name_3": {
            "added": ["element_1", "element_3"],
        },
        "field_name_4": {
            "deleted": ["element_4", "element_5"],
        },
        ...
    }
  """
  list_fields = {}
  for acr_id, value in proposal.content["access_control_list"].iteritems():
    acr_id = int(acr_id)
    if acr_id not in acr_dict:
      continue
    propose_dict = {}
    for action, items in value.iteritems():
      propose_dict[action] = [person_dict[int(i["id"])] for i in items]
    list_fields[acr_dict[acr_id]] = propose_dict
  for field_name, value in proposal.content["mapping_list_fields"].iteritems():
    propose_dict = {}
    for action, items in value.iteritems():
      propose_dict[action] = [_get_object_presentation(i) for i in items]
    list_fields[field_name] = propose_dict
  return list_fields


def get_field_single_values(proposal, person_dict, cads_dict):
  """Returns dict of field name and proposed value."""
  values_dict = {}
  values_dict.update(proposal.content["fields"])
  cavs = proposal.content["custom_attribute_values"]
  for cad_id, value_obj in cavs.iteritems():
    cad_id = int(cad_id)
    if cad_id not in cads_dict:
      continue
    if value_obj.get("attribute_object_id"):
      if value_obj["attribute_value"] != "Person":
        # log it
        continue
      value = person_dict[int(value_obj["attribute_object_id"])]
    else:
      value = value_obj["attribute_value"]
    values_dict[cads_dict[cad_id]] = value

  values_dict.update({
      k: _get_object_presentation(v)
      for k, v in proposal.content["mapping_fields"].iteritems()
  })
  return values_dict


def get_object_url(obj):
  return urlparse.urljoin(utils.get_url_root(),
                          "{}/{}".format(obj._inflector.table_plural, obj.id))


def _get_presented_attrs(object_type):
  """Returns overwrite value mapping for current models."""
  if not hasattr(flask.g, "object_field_value_mapper"):
    flask.g.object_field_value_mapper = {}
  if object_type not in flask.g.object_field_value_mapper:
    all_attrs = reflection.AttributeInfo.gather_attrs(object_type,
                                                      "_fulltext_attrs")
    flask.g.object_field_value_mapper[object_type] = {
        a.alias: a.value_map for a in all_attrs
        if isinstance(a, ft_attrs.ValueMapFullTextAttr)
    }
  return flask.g.object_field_value_mapper[object_type]


def field_value_converter(values_dict, object_type):
  """Change value from collected in DB to User presented value."""
  attrs = _get_presented_attrs(object_type)
  for field in values_dict:
    if field in attrs:
      value = getattr(
          object_type,
          field
      ).property.columns[0].type.python_type(
          values_dict[field]
      )
      values_dict[field] = attrs[field].get(value)


def field_name_converter(values_dict, object_type):
  """Change field name to resented user valule."""
  aliases = reflection.AttributeInfo.gather_visible_aliases(object_type)
  for field_name in values_dict:
    if field_name not in aliases:
      continue
    display_name = aliases[field_name]
    if isinstance(display_name, dict):
      display_name = display_name["display_name"]
    values_dict[display_name] = values_dict.pop(field_name)


def addressee_body_generator(proposals):
  """Generator, that returns pairs addresse and text mailing to addressee."""
  # cache wormup
  cads_dict = dict(all_models.CustomAttributeDefinition.query.values(
      all_models.CustomAttributeDefinition.id,
      all_models.CustomAttributeDefinition.title,
  ))
  person_dict = dict(all_models.Person.query.values(
      all_models.Person.id,
      all_models.Person.email,
  ))
  acr_dict = dict(all_models.AccessControlRole.query.values(
      all_models.AccessControlRole.id,
      all_models.AccessControlRole.name
  ))

  email_pools = collections.defaultdict(dict)
  for proposal in proposals:
    if not isinstance(proposal.instance, roleable.Roleable):
      continue
    single_values = get_field_single_values(proposal, person_dict, cads_dict)
    list_values = get_fields_list_values(proposal, acr_dict, person_dict)
    field_value_converter(single_values, proposal.instance.__class__)
    field_value_converter(list_values, proposal.instance.__class__)
    field_name_converter(single_values, proposal.instance.__class__)
    field_name_converter(list_values, proposal.instance.__class__)
    if not (single_values or list_values):
      continue

    proposal_email_context = EmailProposalContext(
        proposal.agenda,
        proposal.proposed_by.name or proposal.proposed_by.email,
        proposal.instance,
        single_values,
        list_values,
        object_url=get_object_url(proposal.instance),
    )
    for acl in proposal.instance.access_control_list:
      if acl.person == proposal.proposed_by:
        # Don't need to send proposal digest to person who make proposal
        continue
      if acl.ac_role.notify_about_proposal:
        email_pools[acl.person][proposal.id] = proposal_email_context
  for addressee, proposal_dict in email_pools.iteritems():
    body = all_models.Proposal.NotificationContext.DIGEST_TMPL.render(
        proposals=proposal_dict.values())
    yield (addressee, body)


def get_email_proposal_list():
  return all_models.Proposal.query.filter(
      all_models.Proposal.proposed_notified_datetime.is_(None),
      all_models.Proposal.apply_datetime.is_(None),
      all_models.Proposal.decline_datetime.is_(None),
  ).all()


def send_notification():
  """Send notifications about proposals."""
  proposals = get_email_proposal_list()
  for addressee, html in addressee_body_generator(proposals):
    mail.send_mail(
        sender=getattr(settings, 'APPENGINE_EMAIL'),
        to=addressee.email,
        subject=all_models.Proposal.NotificationContext.DIGEST_TITLE,
        body="",
        html=html,
    )
  now = datetime.datetime.utcnow()
  for proposal in proposals:
    proposal.proposed_notified_datetime = now
  db.session.commit()


def present_notifications():
  """Present proposal notifications."""
  if not rbac.permissions.is_admin():
    raise exceptions.Forbidden()
  proposals = get_email_proposal_list()
  generator = (
      "<h1> email to {}</h1>\n {}".format(addressee.email, body)
      for addressee, body in addressee_body_generator(proposals)
  )
  return "".join(generator)

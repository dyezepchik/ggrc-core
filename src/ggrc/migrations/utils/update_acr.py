# Copyright (C) 2018 Google Inc.
# Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>

# disable Invalid constant name pylint warning for mandatory Alembic variables.

"""Helper for updating access_control_roles table with the missing records

"""
import json
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.sql import table, text, column
from alembic import op


def update_acr(role, model, **kwargs):
  """Update one row in acr"""
  connection = op.get_bind()
  # check if the role exists
  res = connection.execute(text(
      """
      SELECT * FROM access_control_roles
      WHERE name=:role AND object_type=:type;
      """
  ), role=role, type=model)
  if res.rowcount > 0:
    return
  role_content = "%\"name\": \"{}\"%".format(role)
  model_content = "%\"object_type\": \"{}\"%".format(model)
  # check if the role could be found among deleted revisions
  res = connection.execute(text(
      """
      SELECT content FROM revisions
      WHERE resource_type='AccessControlRole'
      AND action='deleted'
      AND content LIKE :role_content
      AND content LIKE :model_content
      ORDER BY created_at DESC;
      """
  ), role_content=role_content, model_content=model_content)
  acr = res.first()
  acr_id = None
  if acr:
    acr = json.loads(acr[0])
    acr_id = acr.get("id")
  # otherwise just insert a new one
  acr_table = table(
      "access_control_roles",
      column('id', sa.Integer()),
      column('name', sa.String),
      column('object_type', sa.String),
      column('created_at', sa.DateTime()),
      column('updated_at', sa.DateTime()),
      column('mandatory', sa.Boolean()),
      column('default_to_current_user', sa.Boolean()),
      column('non_editable', sa.Boolean()),
  )
  now = datetime.utcnow()
  update_dict = dict(id=acr_id, name=role, object_type=model,
                     created_at=now, updated_at=now)
  update_dict.update(kwargs)
  connection.execute(acr_table.insert(), [update_dict])


def update_ownable_models(models):
  for model in models:
    update_acr(
        "Admin",
        model,
        mandatory=u"1",
        default_to_current_user=u"1",
        non_editable=u"1",
    )


def update_models_with_contacts(models, roles):
  for model in models:
    for role in roles:
      update_acr(
          role,
          model,
          non_editable=u"1",
      )

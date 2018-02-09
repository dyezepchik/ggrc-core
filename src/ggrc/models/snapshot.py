# Copyright (C) 2018 Google Inc.
# Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>

"""Module for Snapshot object"""

import collections
from datetime import datetime

from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy import orm
from sqlalchemy import event
from sqlalchemy import inspect
from sqlalchemy.orm.session import Session
from sqlalchemy import func
from sqlalchemy.sql.expression import tuple_

from ggrc import builder
from ggrc import db
from ggrc.access_control.roleable import Roleable
from ggrc.utils import benchmark
from ggrc.login import get_current_user_id
from ggrc.models import mixins
from ggrc.models import reflection
from ggrc.models import relationship
from ggrc.models import revision
from ggrc.models.deferred import deferred
from ggrc.models.mixins.with_last_assessment_date import WithLastAssessmentDate


class Snapshot(Roleable, relationship.Relatable, WithLastAssessmentDate,
               mixins.Base, db.Model):
  """Snapshot object that holds a join of parent object, revision, child object
  and parent object's context.

  Conceptual model is that we have a parent snapshotable object (e.g. Audit)
  which will not create relationships to objects with automapper at the time of
  creation but will instead create snapshots of those objects based on the
  latest revision of the object at the time of create / update of the object.
  Objects that were supposed to be mapped are called child objects.
  """
  __tablename__ = "snapshots"

  _api_attrs = reflection.ApiAttributes(
      "parent",
      "child_id",
      "child_type",
      reflection.Attribute("revision", create=False, update=False),
      reflection.Attribute("revision_id", create=False, update=False),
      reflection.Attribute("archived", create=False, update=False),
      reflection.Attribute("revisions", create=False, update=False),
      reflection.Attribute("is_latest_revision", create=False, update=False),
      reflection.Attribute("original_object_deleted",
                           create=False,
                           update=False),
      reflection.Attribute("update_revision", read=False),
  )

  _include_links = [
      "revision"
  ]
  _aliases = {
      "attributes": "Attributes",
      "mappings": {
          "display_name": "Mappings",
          "type": "mapping",
      }
  }

  parent_id = deferred(db.Column(db.Integer, nullable=False), "Snapshot")
  parent_type = deferred(db.Column(db.String, nullable=False), "Snapshot")

  # Child ID and child type are data denormalisations - we could easily get
  # them from revision.content, but since that is a JSON field it will be
  # easier for development to just denormalise on write and not worry
  # about it.
  child_id = deferred(db.Column(db.Integer, nullable=False), "Snapshot")
  child_type = deferred(db.Column(db.String, nullable=False), "Snapshot")

  revision_id = deferred(db.Column(
      db.Integer,
      db.ForeignKey("revisions.id"),
      nullable=False
  ), "Snapshot")
  revision = db.relationship(
      "Revision",
  )
  _update_revision = None

  revisions = db.relationship(
      "Revision",
      primaryjoin="and_(Revision.resource_id == foreign(Snapshot.child_id),"
      "Revision.resource_type == foreign(Snapshot.child_type))",
      uselist=True,
  )

  @builder.simple_property
  def archived(self):
    return self.parent.archived if self.parent else False

  @builder.simple_property
  def is_latest_revision(self):
    """Flag if the snapshot has the latest revision."""
    return self.revisions and self.revision == self.revisions[-1]

  @builder.simple_property
  def original_object_deleted(self):
    """Flag if the snapshot has the latest revision."""
    return self.revisions and self.revisions[-1].action == "deleted"

  @classmethod
  def eager_query(cls):
    query = super(Snapshot, cls).eager_query()
    return cls.eager_inclusions(query, Snapshot._include_links).options(
        orm.subqueryload('revision'),
        orm.subqueryload('revisions'),
    )

  @hybrid_property
  def update_revision(self):
    return self.revision_id

  @update_revision.setter
  def update_revision(self, value):
    self._update_revision = value
    if value == "latest":
      _set_latest_revisions([self])

  @property
  def parent_attr(self):
    return '{0}_parent'.format(self.parent_type)

  @property
  def parent(self):
    return getattr(self, self.parent_attr)

  @parent.setter
  def parent(self, value):
    self.parent_id = getattr(value, 'id', None)
    self.parent_type = getattr(value, 'type', None)
    return setattr(self, self.parent_attr, value)

  @staticmethod
  def _extra_table_args(_):
    return (
        db.UniqueConstraint(
            "parent_type", "parent_id",
            "child_type", "child_id"),
        db.Index("ix_snapshots_parent", "parent_type", "parent_id"),
        db.Index("ix_snapshots_child", "child_type", "child_id"),
    )


class Snapshotable(object):
  """Provide `snapshotted_objects` on for parent objects."""

  _api_attrs = reflection.ApiAttributes("snapshotted_objects")

  @declared_attr
  def snapshotted_objects(cls):  # pylint: disable=no-self-argument
    """Return all snapshotted objects"""
    joinstr = "and_(remote(Snapshot.parent_id) == {type}.id, " \
              "remote(Snapshot.parent_type) == '{type}')"
    joinstr = joinstr.format(type=cls.__name__)
    return db.relationship(
        lambda: Snapshot,
        primaryjoin=joinstr,
        foreign_keys='Snapshot.parent_id,Snapshot.parent_type,',
        backref='{0}_parent'.format(cls.__name__),
        cascade='all, delete-orphan')

  @classmethod
  def eager_query(cls):
    query = super(Snapshotable, cls).eager_query()
    return query.options(
        orm.subqueryload("snapshotted_objects").undefer_group(
            "Snapshot_complete"
        ),
    )


def handle_post_flush(session, flush_context, instances):
  """Handle snapshot objects on api post requests."""
  # pylint: disable=unused-argument
  # Arguments here are set in the event listener and are mandatory.

  with benchmark("Snapshot pre flush handler"):

    snapshots = [o for o in session if isinstance(o, Snapshot)]
    if not snapshots:
      return

    with benchmark("Snapshot revert attrs"):
      _revert_attrs(snapshots)

    new_snapshots = [o for o in snapshots
                     if getattr(o, "_update_revision", "") == "new"]
    if new_snapshots:
      with benchmark("Snapshot post api set revisions"):
        _set_latest_revisions(new_snapshots)
      with benchmark("Snapshot post api ensure relationships"):
        _ensure_program_relationships(new_snapshots)


def _revert_attrs(objects):
  """Revert any modified attributes on snapshot.

  All snapshot attributes that are updatable with API calls should only be
  settable and not editable. This function reverts any possible edits to
  existing values.
  """
  attrs = ["parent_id", "parent_type", "child_id", "child_type"]
  for snapshot in objects:
    for attr in attrs:
      deleted = inspect(snapshot).attrs[attr].history.deleted
      if deleted:
        setattr(snapshot, attr, deleted[0])


def _ensure_program_relationships(objects):
  """Ensure that snapshotted object is related to audit program.

  This function is made to handle multiple snapshots for a single audit.
  Args:
    objects: list of snapshot objects with child_id, child_type and parent set.
  """
  # assert that every parent is an Audit as the code relies on program_id field
  assert {o.parent_type for o in objects} == {"Audit"}

  relationship_stub = collections.namedtuple(
      "RelationshipStub",
      ["source_id", "source_type", "destination_id", "destination_type"],
  )

  required_relationships = set(
      relationship_stub(o.parent.program_id, "Program",
                        o.child_id, o.child_type)
      for o in objects
  )

  if not required_relationships:
    # nothing to create
    return

  rel = relationship.Relationship
  columns = db.session.query(
      rel.source_id, rel.source_type,
      rel.destination_id, rel.destination_type,
  )

  existing_mappings = columns.filter(
      tuple_(rel.source_id, rel.source_type,
             rel.destination_id, rel.destination_type)
      .in_(required_relationships)
  )
  existing_mappings_reverse = columns.filter(
      tuple_(rel.destination_id, rel.destination_type,
             rel.source_id, rel.source_type)
      .in_(required_relationships)
  )

  required_relationships -= set(
      relationship_stub(row.source_id, row.source_type,
                        row.destination_id, row.destination_type)
      for row in existing_mappings
  )
  required_relationships -= set(
      relationship_stub(row.destination_id, row.destination_type,
                        row.source_id, row.source_type)
      for row in existing_mappings_reverse
  )

  _insert_program_relationships(required_relationships)


def _insert_program_relationships(relationship_stubs):
  """Insert missing obj-program relationships."""
  if not relationship_stubs:
    return
  current_user_id = get_current_user_id()
  now = datetime.utcnow()
  # We are doing an INSERT IGNORE INTO here to mitigate a race condition
  # that happens when multiple simultaneous requests create the same
  # automapping. If a relationship object fails our unique constraint
  # it means that the mapping was already created by another request
  # and we can safely ignore it.
  inserter = relationship.Relationship.__table__.insert().prefix_with(
      "IGNORE")
  db.session.execute(
      inserter.values([
          {
              "id": None,
              "modified_by_id": current_user_id,
              "created_at": now,
              "updated_at": now,
              "source_type": relationship_stub.source_type,
              "source_id": relationship_stub.source_id,
              "destination_type": relationship_stub.destination_type,
              "destination_id": relationship_stub.destination_id,
              "context_id": None,
              "status": None,
              "parent_id": None
          }
          for relationship_stub in relationship_stubs
      ])
  )


def _set_latest_revisions(objects):
  """Set latest revision_id for given child_type.

  Args:
    objects: list of snapshot objects with child_id and child_type set.
  """
  pairs = [(o.child_type, o.child_id) for o in objects]
  query = db.session.query(
      func.max(revision.Revision.id, name="id", identifier="id"),
      revision.Revision.resource_type,
      revision.Revision.resource_id,
  ).filter(
      tuple_(
          revision.Revision.resource_type,
          revision.Revision.resource_id,
      ).in_(pairs)
  ).group_by(
      revision.Revision.resource_type,
      revision.Revision.resource_id,
  )
  id_map = {(r_type, r_id): id_ for id_, r_type, r_id in query}
  for o in objects:
    o.revision_id = id_map.get((o.child_type, o.child_id))


event.listen(Session, 'before_flush', handle_post_flush)

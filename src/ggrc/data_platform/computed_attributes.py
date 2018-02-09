# Copyright (C) 2018 Google Inc.
# Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>

"""Module for computing values of computed attributes.


All objects here are represented with tuples containing
  (type, id).

Relationships are tuples with:
  (aggregate_type, aggregate_id, computed_type, computed_id)


Glossary:
aggregate object = object from which the computed value is read
computed object = object which will get the new computed value
"""

import datetime
import collections

import sqlalchemy as sa

from ggrc import db
from ggrc import login
from ggrc.utils import revisions as revision_utils
from ggrc.utils import benchmark
from ggrc.models import all_models as models

# Statement for inserting attribute values without explicit call of delete.
ATTRIBUTE_REPLACE_STATEMENT = """
  REPLACE INTO attributes (
        object_type,
        object_id,
        source_type,
        source_id,
        source_attr,
        value_datetime,
        value_integer,
        value_string,
        attribute_template_id,
        attribute_definition_id,
        created_at,
        updated_at,
        created_by_id,
        updated_by_id
  )
  VALUES (
      :object_type,
      :object_id,
      :source_type,
      :source_id,
      :source_attr,
      :value_datetime,
      :value_integer,
      :value_string,
      :attribute_template_id,
      :attribute_definition_id,
      :created_at,
      :updated_at,
      :created_by_id,
      :updated_by_id
  )
"""

INDEX_REPLACE_STATEMENT = """
  REPLACE INTO fulltext_record_properties (
      `key`,
      `type`,
      `tags`,
      `property`,
      `content`,
      `context_id`,
      `subproperty`
  )
  VALUES (
      :key,
      :type,
      :tags,
      :property,
      :content,
      :context_id,
      :subproperty
  )
"""


def get_computed_attributes():
  """Get all data platform attribute templates with computed flag."""
  return db.session.query(
      models.AttributeTemplates
  ).join(
      models.AttributeDefinitions
  ).join(
      models.AttributeTypes
  ).filter(
      models.AttributeTypes.computed == 1
  ).all()


def get_aggregate_type(attribute):
  afn = attribute.attribute_definition.attribute_type.aggregate_function
  return afn.split()[0]


def get_aggregate_field(attribute):
  afn = attribute.attribute_definition.attribute_type.aggregate_function
  return afn.split()[1]


def get_aggregate_function(attribute):
  """Get actual computed function from aggregate function field."""
  afn = attribute.attribute_definition.attribute_type.aggregate_function
  function_name = afn.split()[2]
  if function_name == "max":
    def max_(aggregate_values, rel_map):
      """Get maximum value and id from which the value was taken."""
      values = [
          (aggregate_values[aggregate_id], aggregate_id)
          for aggregate_id in rel_map
          if aggregate_values.get(aggregate_id) is not None
      ]
      if not values:
        return None, None

      value, source_id = max(values)
      return source_id, value

    return max_
  elif function_name == "last":
    def last_(aggregate_values, rel_map):
      """Get maximum value and id from which the value was taken."""
      values = [
          (aggregate_values[aggregate_id], aggregate_id)
          for aggregate_id in rel_map
          if aggregate_values.get(aggregate_id) is not None
      ]
      if not values:
        return None, None

      # Last value  = value with maximal id
      value, source_id = max(values, key=lambda i: i[1])
      return source_id, value

    return last_
  raise AttributeError("Attribute aggregate_function contains invalid data.")


def snapshot_from_rel(rel_revision):
  """Get snapshot objects from relationship revisions."""
  if rel_revision.source_type == "Snapshot":
    return models.Snapshot.query.get(rel_revision.source_id)
  elif rel_revision.destination_type == "Snapshot":
    return models.Snapshot.query.get(rel_revision.destination_id)
  return None


def _get_group_key(revision, aggregate_type, computed_object):
  """Get key for aggregate objects group.

  These groups are meant for easier calculation and optimization of
  calculation of computed attributes.
  """
  related_types = {computed_object, aggregate_type}
  related_snapshots = {"Snapshot", aggregate_type}
  key = None
  if revision.resource_type == aggregate_type:
    if revision.action == "deleted":
      key = "aggregate_deleted"
    else:
      key = "aggregate_objects"
  elif revision.resource_type == computed_object:
    key = "computed_objects"
  elif (revision.resource_type == "Snapshot" and
        # The following protected access is used to prevent calculation of all
        # fields in revision content, because they are not needed.
        # pylint: disable=protected-access
        revision._content["child_type"] == computed_object):
    key = "destination_snapshots"
  elif (revision.resource_type == "Relationship" and
        revision.source_type in related_types and
        revision.destination_type in related_types):
    key = "related_objects"
  elif (revision.resource_type == "Relationship" and
        revision.source_type in related_snapshots and
        revision.destination_type in related_snapshots):
    # computed source related to a snapshot of an object
    snapshot = snapshot_from_rel(revision)
    if snapshot and snapshot.child_type == computed_object:
      key = "related_snapshots"
  return key


def group_revisions(attributes, revisions):
  """Group revisions under attributes with correct group keys."""
  groups = collections.defaultdict(lambda: collections.defaultdict(set))
  for attr in attributes:
    aggregate_type = get_aggregate_type(attr)
    computed_object = attr.object_template.name
    for revision in revisions:
      key = _get_group_key(revision, aggregate_type, computed_object)
      if key:
        groups[attr][key].add((revision.resource_type, revision.resource_id))
  return groups


def _objects_from_snapshots(snapshots):
  """Get snapshot child objects set."""
  if not snapshots:
    return set()
  return set(db.session.query(
      models.Snapshot.child_type,
      models.Snapshot.child_id,
  ).filter(
      models.Snapshot.id.in_(snap[1] for snap in snapshots)
  ).distinct())


def _get_objects_from_aggregates(aggregate_objects, computed_object_type):
  """Get tuples of all original objects linked to aggregate_objects.

  args:
    aggregate_objects: tuples of object type and object id
    computed_object_type: object type of the destination for computed
        attribute. Object to which the computed attribute belongs.
  """
  if not aggregate_objects:
    return set()

  # Related original objects
  src = db.session.query(
      models.Relationship.source_type,
      models.Relationship.source_id,
  ).filter(
      sa.tuple_(
          models.Relationship.destination_type,
          models.Relationship.destination_id,
      ).in_(aggregate_objects),
      models.Relationship.source_type == computed_object_type,
  )
  dst = db.session.query(
      models.Relationship.destination_type,
      models.Relationship.destination_id,
  ).filter(
      sa.tuple_(
          models.Relationship.source_type,
          models.Relationship.source_id,
      ).in_(aggregate_objects),
      models.Relationship.destination_type == computed_object_type,
  )

  # Related snapshots
  snap_dst = db.session.query(
      models.Snapshot.child_type,
      models.Snapshot.child_id,
  ).join(
      models.Relationship,
      sa.and_(
          models.Relationship.destination_id == models.Snapshot.id,
          models.Relationship.destination_type == models.Snapshot.__name__,
          models.Snapshot.child_type == computed_object_type,
      )
  ).filter(
      sa.tuple_(
          models.Relationship.source_type,
          models.Relationship.source_id,
      ).in_(aggregate_objects),
  )
  snap_src = db.session.query(
      models.Snapshot.child_type,
      models.Snapshot.child_id,
  ).join(
      models.Relationship,
      sa.and_(
          models.Relationship.source_id == models.Snapshot.id,
          models.Relationship.source_type == models.Snapshot.__name__,
          models.Snapshot.child_type == computed_object_type,
      )
  ).filter(
      sa.tuple_(
          models.Relationship.destination_type,
          models.Relationship.destination_id,
      ).in_(aggregate_objects),
  )
  # Missing snapshots related to snapshot parent (currently only Audit)

  # TODO: benchmark and compare with:
  # return set(src.union(dst, snap_src, snap_dst))
  return set(src) | set(dst) | set(snap_src) | set(snap_dst)


def _get_objects_from_deleted(aggregate_deleted, aggregate_field):
  """Get objects with deleted source.

  This function returns all objects that have one computed value that belongs
  to a currently deleted aggregate object.
  """
  if not aggregate_deleted:
    return set()
  return set(db.session.query(
      models.Attributes.object_type,
      models.Attributes.object_id,
  ).filter(
      sa.tuple_(
          models.Attributes.source_type,
          models.Attributes.source_id,
      ).in_(aggregate_deleted),
      models.Attributes.source_attr == aggregate_field,
  ))


def get_affected_objects(attribute_groups):
  """Get a list off all affected objects grouped by attributes."""
  affected_objects = {}
  for attr, groups in attribute_groups.iteritems():
    objects = set()
    objects.update(groups["computed_objects"])
    objects.update(_objects_from_snapshots(groups["destination_snapshots"]))
    objects.update(_get_objects_from_aggregates(
        groups["aggregate_objects"],
        attr.object_template.name
    ))
    objects.update(_get_objects_from_deleted(
        groups["aggregate_deleted"],
        get_aggregate_field(attr)
    ))
    affected_objects[attr] = objects
  return affected_objects


def _get_aggregate_values(attr, aggregate_objects):
  """Get values from aggregate objects.

  This function should pull all values from which we can compute new values.
  """
  if not aggregate_objects:
    return {}

  ids = [obj[1] for obj in aggregate_objects]

  field_name = get_aggregate_field(attr)
  aggregate_type = get_aggregate_type(attr)
  # This line must raise an exception if the object does not exists and it
  # should not be handled quietly. If there is an exception here it indicates
  # data corruption in the attribute_types table
  aggregate_model = getattr(models, aggregate_type)
  query = db.session.query(
      aggregate_model.id,
      getattr(aggregate_model, field_name),
  ).filter(
      aggregate_model.id.in_(ids)
  )

  return dict(query)


def _get_relationships_map(relationships):
  """Get relationships map.

  Args:
    relationships: list of tuples containing relationships data.

  Returns:
    a map from computed object ids to a list of aggregate object ids.
  """
  rel_map = collections.defaultdict(set)
  for _, aggregate_id, computed_type, computed_id in relationships:
    rel_map[(computed_type, computed_id)].add(aggregate_id)
  return rel_map


def compute_values(affected_objects, all_relationships, snapshot_map):
  """Compute new values for affected objects."""
  # pylint: disable=too-many-locals
  computed_values = collections.defaultdict(dict)

  for attr, objects in affected_objects.iteritems():
    aggregate_objects = {(r[0], r[1]) for r in all_relationships[attr]}
    aggregate_values = _get_aggregate_values(attr, aggregate_objects)
    rel_map = _get_relationships_map(all_relationships[attr])

    aggregate_type = get_aggregate_type(attr)
    aggregate_function = get_aggregate_function(attr)
    for obj in objects:
      source_id, value = aggregate_function(aggregate_values, rel_map[obj])
      if source_id is None:
        continue

      computed_value_dict = {
          "source_type": aggregate_type,
          "source_id": source_id,
          "value_datetime": None,
          "value_integer": None,
          "value_string": "",
      }
      field_type = attr.attribute_definition.attribute_type.field_type
      if field_type in ("value_datetime", "value_integer", "value_string"):
        computed_value_dict[field_type] = value
      else:
        computed_value_dict["value_datetime"] = value
      computed_values[attr][obj] = computed_value_dict
      for snapshot_id in snapshot_map.get(obj, set()):
        computed_values[attr][(u"Snapshot", snapshot_id)] = computed_value_dict

  return computed_values


def _get_relationships(aggregate_type, objects):
  """Get all mappings between aggregate_type and objects."""
  # Related original objects
  if not objects:
    return set()

  src = db.session.query(
      models.Relationship.source_type,
      models.Relationship.source_id,
      models.Relationship.destination_type,
      models.Relationship.destination_id,
  ).filter(
      sa.tuple_(
          models.Relationship.destination_type,
          models.Relationship.destination_id,
      ).in_(objects),
      models.Relationship.source_type == aggregate_type,
  )
  dst = db.session.query(
      models.Relationship.destination_type,
      models.Relationship.destination_id,
      models.Relationship.source_type,
      models.Relationship.source_id,
  ).filter(
      sa.tuple_(
          models.Relationship.source_type,
          models.Relationship.source_id,
      ).in_(objects),
      models.Relationship.destination_type == aggregate_type,
  )

  # Related snapshots
  # These queries should be optimized to not use full outer join.
  snap_dst = db.session.query(
      models.Relationship.destination_type,
      models.Relationship.destination_id,
      models.Snapshot.child_type,
      models.Snapshot.child_id,
  ).filter(
      models.Relationship.source_type == models.Snapshot.__name__,
      models.Relationship.source_id == models.Snapshot.id,
      models.Relationship.destination_type == aggregate_type,
      sa.tuple_(
          models.Snapshot.child_type,
          models.Snapshot.child_id,
      ).in_(objects),
  )
  snap_src = db.session.query(
      models.Relationship.source_type,
      models.Relationship.source_id,
      models.Snapshot.child_type,
      models.Snapshot.child_id,
  ).filter(
      models.Relationship.destination_type == models.Snapshot.__name__,
      models.Relationship.destination_id == models.Snapshot.id,
      models.Relationship.source_type == aggregate_type,
      sa.tuple_(
          models.Snapshot.child_type,
          models.Snapshot.child_id,
      ).in_(objects),
  )
  # Missing snapshots related to snapshot parent (currently only Audit)

  # TODO: benchmark and compare with:
  # return set(src.union(dst, snap_src, snap_dst))
  return set(src) | set(dst) | set(snap_src) | set(snap_dst)


def get_relationships(affected_objects):
  """Get all mappings for computed objects and aggregates."""
  relationships = {}
  for attr, objects in affected_objects.iteritems():
    aggregate_type = get_aggregate_type(attr)
    relationships[attr] = _get_relationships(aggregate_type, objects)
  return relationships


def get_snapshot_data(affected_objects):
  """Get data needed for indexing snapshot values."""
  all_objects = set()
  for objects in affected_objects.itervalues():
    all_objects.update(objects)

  if not all_objects:
    return set(), set()

  query = db.session.query(
      models.Snapshot.child_type,
      models.Snapshot.child_id,
      models.Snapshot.id
  ).filter(
      sa.tuple_(
          models.Snapshot.child_type,
          models.Snapshot.child_id,
      ).in_(all_objects)
  )
  all_ids = []
  snapshot_map = collections.defaultdict(list)
  for computed_type, computed_id, snapshot_id in query:
    snapshot_map[(computed_type, computed_id)].append(snapshot_id)
    all_ids.append(snapshot_id)

  snapshot_tag_map = {}
  if all_ids:
    query = db.session.query(
        models.Snapshot.id,
        sa.func.concat_ws(
            "-",
            models.Snapshot.parent_type,
            models.Snapshot.parent_id,
            models.Snapshot.child_type,
        )
    ).filter(
        models.Snapshot.id.in_(all_ids)
    )
    snapshot_tag_map = dict(query)

  return snapshot_map, snapshot_tag_map


def get_attributes_data(computed_values):
  """Store computed values in the database."""
  data = []
  user_id = login.get_current_user_id()
  for attr, objects in computed_values.iteritems():
    aggregate_type = get_aggregate_type(attr)
    aggregate_field = get_aggregate_field(attr)
    definition_id = attr.attribute_definition.attribute_definition_id
    for obj, computed_value in objects.iteritems():
      data.append({
          "object_type": unicode(obj[0]),
          "object_id": obj[1],
          "source_type": unicode(aggregate_type),
          "source_id": computed_value["source_id"],
          "source_attr": unicode(aggregate_field),
          "value_datetime": computed_value["value_datetime"],
          "value_string": computed_value["value_string"] or "",
          "value_integer": computed_value["value_integer"],
          "attribute_template_id": attr.attribute_template_id,
          "attribute_definition_id": definition_id,
          "created_at": datetime.datetime.utcnow(),
          "updated_at": datetime.datetime.utcnow(),
          "created_by_id": user_id,
          "updated_by_id": user_id,
      })
  return data


def get_index_data(computed_values, snapshot_tag_map):
  """Store new computed values in full text index table."""
  data = []
  for attr, objects in computed_values.iteritems():
    for obj, computed_value in objects.iteritems():
      value = (computed_value["value_datetime"] or
               computed_value["value_string"] or "")
      tags = u""
      if obj[0] == "Snapshot":
        tags = snapshot_tag_map.get(obj[1], u"")
      data.append({
          "key": obj[1],
          "type": obj[0],
          "tags": tags,
          "property": attr.attribute_definition.name,
          "content": value,
          "context_id": None,
          "subproperty": u"",
      })
  return data


def store_data(attributes_data, index_data):
  """Store new computed values to the database."""
  if attributes_data:
    db.session.execute(ATTRIBUTE_REPLACE_STATEMENT, attributes_data)
  if index_data:
    db.session.execute(INDEX_REPLACE_STATEMENT, index_data)
  db.session.commit()


def get_all_latest_revisions_ids():
  """Get latest revisions for aggregate objects."""
  with benchmark("Get all latest revision ids"):
    attributes = get_computed_attributes()
    revision_ids = []
    for attribute in attributes:
      aggregate_type = get_aggregate_type(attribute)
      revisions = revision_utils.get_revisions_by_type(aggregate_type)
      revision_ids.extend(revisions.values())
    return revision_ids


def delete_all_computed_values():
  """Remove all attribute values for computed attributes."""
  with benchmark("Delete all computed attribute values"):
    attributes = get_computed_attributes()
    models.Attributes.query.filter_by(
        models.Attributes.attribute_template.in_(attributes)
    ).delete()


def get_revisions(revision_ids):
  """Get revision properties needed for computed attributes.

  Fetch revision properties based on resource type. This is an optimization to
  avoid fetching a lot of content for all objects when it is only needed to get
  snapshot resource type. In the future we might store snapshot resource type
  into a separate revision column just fully avoid fetching content from the
  database.

  Args:
    revision_ids: list of ids for revisions that will be used in calculating
      new computed attribute values.

  Returns:
    list of named tuples with all needed revision data to compute the new
    attribute values. Note that snapshot revisions also contain content field
    that they need to specify the snapshot object type.
  """

  non_snapshot_revisions = db.session.query(
      models.Revision.action,
      models.Revision.resource_type,
      models.Revision.resource_id,
      models.Revision.source_type,
      models.Revision.destination_type,
  ).filter(
      models.Revision.resource_type != "Snapshot",
      models.Revision.id.in_(revision_ids)
  ).all()
  snapshot_revisions = db.session.query(
      models.Revision.action,
      models.Revision.resource_type,
      models.Revision.resource_id,
      # The following protected access is used to prevent calculation of all
      # fields in revision content, because they are not needed.
      models.Revision._content,  # pylint: disable=protected-access
  ).filter(
      models.Revision.resource_type == "Snapshot",
      models.Revision.id.in_(revision_ids)
  ).all()
  return non_snapshot_revisions + snapshot_revisions


def compute_attributes(revision_ids):
  """Compute new values based an changed objects.

  Args:
    objects: array of object stubs of modified objects.
  """

  with benchmark("Compute attributes"):

    if revision_ids == "all_latest":
      with benchmark("Get all latest revisions ids"):
        revision_ids = get_all_latest_revisions_ids()

    if not revision_ids:
      return

    with benchmark("Get revisions."):
      revisions = get_revisions(revision_ids)

    with benchmark("Get all computed attributes"):
      attributes = get_computed_attributes()

    with benchmark("Group revisions by computed attributes"):
      attribute_groups = group_revisions(attributes, revisions)
    with benchmark("get all objects affected by computed attributes"):
      affected_objects = get_affected_objects(attribute_groups)
    with benchmark("Get all relationships for these computed objects"):
      relationships = get_relationships(affected_objects)
    with benchmark("Get snapshot data"):
      snapshot_map, snapshot_tag_map = get_snapshot_data(affected_objects)

    with benchmark("Compute values"):
      computed_values = compute_values(affected_objects, relationships,
                                       snapshot_map)

    with benchmark("Get computed attributes data"):
      attributes_data = get_attributes_data(computed_values)
    with benchmark("Get computed attribute full-text index data"):
      index_data = get_index_data(computed_values, snapshot_tag_map)
    with benchmark("Store attribute data and full-text index data"):
      store_data(attributes_data, index_data)

# Copyright (C) 2017 Google Inc.
# Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>

"""Module for handling a single import block.

Each import block should contain data for one Object type. The blocks are
separated in the csv file with empty lines.
"""

from logging import getLogger
from collections import defaultdict
from collections import OrderedDict
from collections import Counter

from cached_property import cached_property
from sqlalchemy import exc
from sqlalchemy import or_
from sqlalchemy import and_
from sqlalchemy.orm.exc import UnmappedInstanceError

from ggrc import db
from ggrc import models
from ggrc.rbac import permissions
from ggrc.utils import benchmark
from ggrc.utils import structures
from ggrc.converters import errors
from ggrc.converters import get_shared_unique_rules
from ggrc.converters import pre_commit_checks
from ggrc.converters.base_row import RowConverter
from ggrc.converters.import_helper import get_column_order
from ggrc.converters.import_helper import get_object_column_definitions
from ggrc.services.common import get_modified_objects
from ggrc.services.common import update_snapshot_index
from ggrc.services.common import update_memcache_after_commit
from ggrc.services.common import update_memcache_before_commit
from ggrc.utils.log_event import log_event
from ggrc.services import signals
from ggrc_workflows.models.cycle_task_group_object_task import \
    CycleTaskGroupObjectTask


# pylint: disable=invalid-name
logger = getLogger(__name__)

CACHE_EXPIRY_IMPORT = 600


class BlockConverter(object):
  # pylint: disable=too-many-public-methods

  """ Main block converter class for dealing with csv files and data

  Attributes:
    attr_index (dict): reverse index for getting attribute name from
      display_name
    block_errors (list of str): list containing fatal import errors
    block_warnings (list of str): list containing blokc level import warnings
    row_errors (list of str): list containing row errors
    row_warnings (list of str): list containing row warnings
    object_ids (list of int): list containing all ids for the converted objects
    rows (list of list of str): 2D array containing csv data
    row_converters (list of RowConverter): list of row convertor objects with
      data from the coresponding row in rows attribute
    object_headers (dict): A dictionary containing object headers
    headers (dict): A dictionary containing csv headers with additional
      information. Keys are object attributes such as "title", "slug"...
      Example:
        {"slug": {
            "display_name": "Code",
            "mandatory": True,
            "default": "value or a callabe function that returns the value",
            "validator": validator_function,
            "handler": HandlerClass,
            "description": "description or function that returns description"
            "valid_values": "list of valid values"

  """

  def get_unique_counts_dict(self, object_class):
    """ get a the varible for storing unique counts

    Make sure to always return the same variable for object with shared tables,
    as defined in sharing rules.
    """
    sharing_rules = get_shared_unique_rules()
    classes = sharing_rules.get(object_class, object_class)
    shared_state = self.converter.shared_state
    if classes not in shared_state:
      shared_state[classes] = defaultdict(
          lambda: structures.CaseInsensitiveDefaultDict(set)
      )
    return shared_state[classes]

  def __init__(self, converter, **options):
    # pylint: disable=too-many-instance-attributes,protected-access
    # This class holds cache and object data for all rows and handlers below
    # it, so it is expected to hold a lot of instance attributes.
    # The protected access is a false warning for inflector access.
    self.revision_ids = []
    self._mapping_cache = None
    self._owners_cache = None
    self._roles_cache = None
    self._user_roles_cache = None
    self._ca_definitions_cache = None
    self.converter = converter
    self.offset = options.get("offset", 0)  # offset to the current block
    self.object_class = options.get("object_class")
    self.rows = options.get("rows", [])
    self.operation = 'import' if self.rows else 'export'
    self.object_ids = options.get("object_ids", [])
    self.block_errors = []
    self.block_warnings = []
    self.row_errors = []
    self.row_warnings = []
    self.row_converters = []
    self.ignore = False
    self._has_non_importable_columns = False
    # For import contains model name from csv file.
    # For export contains 'Model.__name__' value.
    self.class_name = options.get("class_name", "")
    # TODO: remove 'if' statement. Init should initialize only.
    if self.object_class:
      self.object_headers = get_object_column_definitions(self.object_class)
      all_header_names = [unicode(key)
                          for key in self.get_header_names().keys()]
      raw_headers = options.get("raw_headers", all_header_names)
      self.check_for_duplicate_columns(raw_headers)
      self.headers = self.clean_headers(raw_headers)
      self.unique_counts = self.get_unique_counts_dict(self.object_class)
      self.table_singular = self.object_class._inflector.table_singular
      self.name = self.object_class._inflector.human_singular.title()
      self.organize_fields(options.get("fields", []))
    else:
      self.name = ""

  def check_block_restrictions(self):
    """Check some block related restrictions"""
    if not self.object_class:
      self.add_errors(errors.WRONG_OBJECT_TYPE, line=self.offset + 2,
                      object_name=self.class_name)
      return
    if (self.operation == 'import' and
            self.object_class is CycleTaskGroupObjectTask and
            not permissions.is_admin()):
      self.add_errors(errors.PERMISSION_ERROR, line=self.offset + 2)
      logger.error("Import failed with: Only admin can update existing "
                   "cycle-tasks via import")
    if self._has_non_importable_columns:
      importable_column_names = []
      for field_name in self.object_class.IMPORTABLE_FIELDS:
        if field_name == 'slug':
          continue
        if field_name not in self.headers:
          continue
        importable_column_names.append(
            self.headers[field_name]["display_name"])
      self.add_warning(errors.ONLY_IMPORTABLE_COLUMNS_WARNING,
                       line=self.offset + 2,
                       columns=", ".join(importable_column_names))

  def _create_ca_definitions_cache(self):
    """Create dict cache for custom attribute definitions.

    Returns:
        dict containing custom attribute definitions for the current object
        type.
    """
    cad = models.CustomAttributeDefinition
    defs = cad.eager_query().filter(cad.definition_type == self.table_singular)
    return {(d.definition_id, d.title): d for d in defs}

  def get_ca_definitions_cache(self):
    """Return cached property value _ca_definitions_cache."""
    if self._ca_definitions_cache is None:
      self._ca_definitions_cache = self._create_ca_definitions_cache()
    return self._ca_definitions_cache

  def _get_relationships(self):
    """Get all relationships for any of the object in the current block."""
    relationship = models.Relationship
    with benchmark("Fetch all block relationships"):
      relationships = []
      if self.object_ids:
        relationships = db.session.query(
            relationship.source_id,
            relationship.source_type,
            relationship.destination_id,
            relationship.destination_type,
        ).filter(or_(
            and_(
                relationship.source_type == self.object_class.__name__,
                relationship.source_id.in_(self.object_ids),
            ),
            and_(
                relationship.destination_type == self.object_class.__name__,
                relationship.destination_id.in_(self.object_ids),
            )
        )).all()
      return relationships

  def _get_identifier_mappings(self, relationships):
    """Get object and id mapping to user visible identifier."""
    object_ids = defaultdict(set)
    for rel in relationships:
      if rel.source_type == self.object_class.__name__:
        object_ids[rel.destination_type].add(rel.destination_id)
      else:
        object_ids[rel.source_type].add(rel.source_id)

    id_map = {}
    for object_type, ids in object_ids.items():
      model = getattr(models.all_models, object_type, None)
      if hasattr(model, "slug"):
        id_column = getattr(model, "slug")
      elif hasattr(model, "email"):
        id_column = getattr(model, "email")
      else:
        continue
      query = db.session.query(model.id, id_column).filter(model.id.in_(ids))
      id_map[object_type] = dict(query)
    return id_map

  def _create_mapping_cache(self):
    """Create mapping cache for object in the current block."""

    with benchmark("cache for: {}".format(self.object_class.__name__)):
      relationships = self._get_relationships()
      id_map = self._get_identifier_mappings(relationships)
      with benchmark("building cache"):
        cache = defaultdict(lambda: defaultdict(list))
        for rel in relationships:
          if rel.source_type == self.object_class.__name__:
            identifier = id_map.get(rel.destination_type, {}).get(
                rel.destination_id)
            if identifier:
              cache[rel.source_id][rel.destination_type].append(identifier)
          else:
            identifier = id_map.get(rel.source_type, {}).get(rel.source_id)
            if identifier:
              cache[rel.destination_id][rel.source_type].append(identifier)
      return cache

  def get_mapping_cache(self):
    """Return mapping_cache attribute."""
    if self._mapping_cache is None:
      self._mapping_cache = self._create_mapping_cache()
    return self._mapping_cache

  def get_role(self, name):
    """Get role from local cache for a given name."""
    if not self._roles_cache:
      self._roles_cache = {role.name: role for role in
                           models.all_models.Role.query}
    return self._roles_cache[name]

  def _create_user_roles_cache(self):
    """Create cache for user roles.

    The cache returns a list of emails for a role in a context.
    """
    cache = defaultdict(lambda: defaultdict(set))
    context_ids = {rc.obj.context_id for rc in self.row_converters}
    user_roles = db.session.query(
        models.all_models.UserRole.context_id,
        models.all_models.UserRole.role_id,
        models.all_models.UserRole.person_id,
    ).filter(
        models.all_models.UserRole.context_id.in_(context_ids)
    ).all()

    if not user_roles:
      return cache

    people_ids = {role[2] for role in user_roles}

    emails_map = dict(db.session.query(
        models.Person.id,
        models.Person.email
    ).filter(
        models.Person.id.in_(people_ids)
    ))

    for context_id, role_id, person_id in user_roles:
      cache[context_id][role_id].add(emails_map[person_id])
    return cache

  def get_user_roles_cache(self):
    """Get cache for emails on user roles by context."""
    if self._user_roles_cache is None:
      self._user_roles_cache = self._create_user_roles_cache()
    return self._user_roles_cache

  def _create_owners_cache(self):
    """Create a cache of emails for all object owners."""
    owner_ids = set()
    for row_converter in self.row_converters:
      owners = getattr(row_converter.obj, "object_owners", None)
      if owners:
        owner_ids |= {o.person_id for o in owners}
    if not owner_ids:
      return {}
    query = db.session.query(
        models.Person.id,
        models.Person.email
    ).filter(
        models.Person.id.in_(owner_ids)
    )
    return dict(query)

  def get_owners_cache(self):
    """Get object owners email cache."""
    if self._owners_cache is None:
      self._owners_cache = self._create_owners_cache()
    return self._owners_cache

  @cached_property
  def mapped_snapshots(self):
    """Cached property of mapped to audit snapshots"""
    # pylint: disable=protected-access
    snapshots = defaultdict(lambda: defaultdict(set))
    query = db.session.query(
        models.Revision.resource_slug,
        models.Snapshot.parent_id,
        models.Snapshot.child_type,
    ).join(models.Snapshot).filter(
        models.Snapshot.parent_type == self.object_class.__name__,
        models.Snapshot.parent_id.in_(self.object_ids),
    )
    for slug, parent_id, child_type in query:
      snapshots[parent_id][child_type].add(slug)
    return snapshots

  def check_for_duplicate_columns(self, raw_headers):
    """Check for duplicate column names in the current block.

    Having duplicate column names can happen with custom attribute names and in
    that case it is impossible to determine the correct handler for all
    columns. Blocks with duplicate names are ignored.
    """
    counter = Counter(header.strip().rstrip("*").lower()
                      for header in raw_headers)
    duplicates = [header for header, count in counter.items() if count > 1]
    if duplicates:
      self.add_errors(errors.DUPLICATE_COLUMN,
                      line=self.offset + 1,
                      duplicates=", ".join(duplicates))

  def organize_fields(self, fields):
    """Setup fields property."""
    if fields == "all":
      fields = self.object_headers.keys()
    self.fields = get_column_order(fields)

  def generate_csv_header(self):
    """ Generate 2D array with csv headre description """
    headers = []
    for field in self.fields:
      description = self.object_headers[field]["description"]
      display_name = self.object_headers[field]["display_name"]
      if self.object_headers[field]["mandatory"]:
        display_name += "*"
      headers.append([description, display_name])
    return [list(header) for header in zip(*headers)]

  def generate_csv_body(self):
    """ Generate 2D array populated with object values """
    return [r.to_array(self.fields) for r in self.row_converters]

  def to_array(self):
    """Return tuple of csv_header and csv_body."""
    csv_header = self.generate_csv_header()
    csv_body = self.generate_csv_body()
    return csv_header, csv_body

  def get_header_names(self):
    """ Get all posible user column names for current object """
    header_names = {
        v["display_name"].lower(): k for k, v in self.object_headers.items()}
    return header_names

  def clean_headers(self, raw_headers):
    """ Sanitize columns from csv file

    Clear out all the bad column headers and remove corresponding column in the
    rows data.

    Args:
      raw_headers (list of str): unmodified header row from csv file

    Returns:
      Ordered Dictionary containing all valid headers
    """
    clean_headers = OrderedDict()
    header_names = self.get_header_names()
    removed_count = 0
    for index, raw_header in enumerate(raw_headers):
      header = self._sanitize_header(raw_header)
      if header in header_names:
        field_name = header_names[header]
        if (self.operation == 'import' and
                hasattr(self.object_class, "IMPORTABLE_FIELDS") and
                field_name not in self.object_class.IMPORTABLE_FIELDS):
          self._has_non_importable_columns = True
          self.remove_column(index - removed_count)
          removed_count += 1
          continue
        clean_headers[field_name] = self.object_headers[field_name]
      else:
        self.add_warning(errors.UNKNOWN_COLUMN,
                         line=self.offset + 2,
                         column_name=header)
        self.remove_column(index - removed_count)
        removed_count += 1
    return clean_headers

  def remove_column(self, index):
    """ Remove a column from all rows """
    for row in self.rows:
      if len(row) > index:
        row.pop(index)

  def row_converters_from_csv(self):
    """ Generate a row converter object for every csv row """
    if self.ignore:
      return
    self.row_converters = []
    for i, row in enumerate(self.rows):
      row = RowConverter(self, self.object_class, row=row,
                         headers=self.headers, index=i)
      self.row_converters.append(row)

  def row_converters_from_ids(self):
    """ Generate a row converter object for every csv row """
    if self.ignore or not self.object_ids:
      return
    self.row_converters = []
    objects = self.object_class.eager_query().filter(
        self.object_class.id.in_(self.object_ids)).all()
    for i, obj in enumerate(objects):
      row = RowConverter(self, self.object_class, obj=obj,
                         headers=self.headers, index=i)
      self.row_converters.append(row)

  def handle_row_data(self, field_list=None):
    """Call handle row data on all row converters.

    Note: When field_list is set, we are handling priority columns and we
    don't have all the data needed for checking mandatory and duplicate values.

    Args:
      filed_list (list of strings): list of fields that should be handled by
        row converters. This is used only for handling priority columns.
    """
    if self.ignore:
      return
    for row_converter in self.row_converters:
      row_converter.handle_row_data(field_list)
    if field_list is None:
      self.check_mandatory_fields()
      self.check_unique_columns()

  def check_mandatory_fields(self):
    for row_converter in self.row_converters:
      row_converter.check_mandatory_fields()

  def check_unique_columns(self):
    self.generate_unique_counts()
    for key, counts in self.unique_counts.items():
      self.remove_duplicate_keys(key, counts)

  def get_info(self):
    """Returns info dict for current block."""
    created = 0
    updated = 0
    ignored = 0
    deleted = 0
    deprecated = 0
    for row in self.row_converters:
      if row.ignore:
        ignored += 1
        continue
      if row.is_delete:
        deleted += 1
        continue
      if row.is_new:
        created += 1
      else:
        updated += 1
      deprecated += int(row.is_deprecated)
    info = {
        "name": self.name,
        "rows": len(self.rows),
        "created": created,
        "updated": updated,
        "ignored": ignored,
        "deleted": deleted,
        "deprecated": deprecated,
        "block_warnings": self.block_warnings,
        "block_errors": self.block_errors,
        "row_warnings": self.row_warnings,
        "row_errors": self.row_errors,
    }

    return info

  def import_secondary_objects(self):
    """Import secondary objects procedure."""
    for row_converter in self.row_converters:
      row_converter.setup_secondary_objects()

    if not self.converter.dry_run:
      for row_converter in self.row_converters:
        try:
          row_converter.insert_secondary_objects()
        except exc.SQLAlchemyError as err:
          db.session.rollback()
          logger.exception("Import failed with: %s", err.message)
          row_converter.add_error(errors.UNKNOWN_ERROR)
      self.save_import()

  def _import_objects_prepare(self):
    """Setup all objects and do pre-commit checks for them."""
    for row_converter in self.row_converters:
      row_converter.setup_object()

    for row_converter in self.row_converters:
      self._check_object(row_converter)

    self.clean_session_from_ignored_objs()

  def import_objects(self):
    """Add all objects to the database.

    This function flushes all objects to the database if the dry_run flag is
    not set and all signals for the imported objects get sent.
    """
    if self.ignore:
      return

    self._import_objects_prepare()

    if not self.converter.dry_run:
      new_objects = []
      for row_converter in self.row_converters:
        row_converter.send_pre_commit_signals()
      for row_converter in self.row_converters:
        try:
          row_converter.insert_object()
          db.session.flush()
        except exc.SQLAlchemyError as err:
          db.session.rollback()
          logger.exception("Import failed with: %s", err.message)
          row_converter.add_error(errors.UNKNOWN_ERROR)
        else:
          if row_converter.is_new and not row_converter.ignore:
            new_objects.append(row_converter.obj)
      self.send_collection_post_signals(new_objects)
      import_event = self.save_import()
      for row_converter in self.row_converters:
        row_converter.send_post_commit_signals(event=import_event)

  def clean_session_from_ignored_objs(self):
    """Clean DB session from ignored objects.

    This function expunges objects from 'db.session' which are in rows that
    marked as 'ignored' before commit.
    """
    for row_converter in self.row_converters:
      obj = row_converter.obj
      try:
        if row_converter.do_not_expunge:
          continue
        if row_converter.ignore and obj in db.session:
          db.session.expunge(obj)
      except UnmappedInstanceError:
        continue

  @staticmethod
  def send_collection_post_signals(new_objects):
    """Send bulk create pre-commit signals."""
    if not new_objects:
      return
    collections = {}
    for obj in new_objects:
      collections.setdefault(obj.__class__, []).append(obj)
    for object_class, objects in collections.iteritems():
      signals.Restful.collection_posted.send(
          object_class,
          objects=objects,
          sources=[{} for _ in xrange(len(objects))],
      )

  def _store_revision_ids(self, event):
    """Store revision ids from the current event."""
    if event:
      self.revision_ids.extend(revision.id for revision in event.revisions)

  def save_import(self):
    """Commit all changes in the session and update memcache."""
    try:
      modified_objects = get_modified_objects(db.session)
      import_event = log_event(db.session, None)
      update_memcache_before_commit(
          self, modified_objects, CACHE_EXPIRY_IMPORT)
      db.session.commit()
      self._store_revision_ids(import_event)
      update_memcache_after_commit(self)
      update_snapshot_index(db.session, modified_objects)
      return import_event
    except exc.SQLAlchemyError as err:
      db.session.rollback()
      logger.exception("Import failed with: %s", err.message)
      self.add_errors(errors.UNKNOWN_ERROR, line=self.offset + 2)

  def add_errors(self, template, **kwargs):
    """Add errors for current block."""
    message = template.format(**kwargs)
    self.block_errors.append(message)
    self.ignore = True

  def add_warning(self, template, **kwargs):
    message = template.format(**kwargs)
    self.block_warnings.append(message)

  def generate_unique_counts(self):
    """Populate unique_counts for sent data."""
    for key, header in self.headers.items():
      if not header["unique"]:
        continue
      for index, row in enumerate(self.row_converters):
        value = row.get_value(key)
        if value:
          self.unique_counts[key][value].add(index + self.offset + 3)

  def in_range(self, index, remove_offset=True):
    if remove_offset:
      index -= 3 + self.offset
    return index >= 0 and index < len(self.row_converters)

  def remove_duplicate_keys(self, key, counts):

    for value, indexes in counts.items():
      if not any(self.in_range(index) for index in indexes):
        continue  # ignore duplicates in other related code blocks

      indexes = sorted(list(indexes))
      if len(indexes) > 1:
        str_indexes = [str(index) for index in indexes]
        self.row_errors.append(
            errors.DUPLICATE_VALUE_IN_CSV.format(
                line_list=", ".join(str_indexes),
                column_name=self.headers[key]["display_name"],
                s="s" if len(str_indexes) > 2 else "",
                value=value,
                ignore_lines=", ".join(str_indexes[1:]),
            )
        )
        if key == "slug":  # mark obj not to be expunged from the session
          for index in indexes:
            offset_index = index - 3 - self.offset
            if self.in_range(offset_index, remove_offset=False):
              self.row_converters[offset_index].set_do_not_expunge()

      for index in indexes[1:]:
        offset_index = index - 3 - self.offset
        if self.in_range(offset_index, remove_offset=False):
          self.row_converters[offset_index].set_ignore()

  @staticmethod
  def _sanitize_header(header):
    """Sanitaze column header string.

    Since we rely on header names to get the correct handlers, we should allow
    some room in the names for special characters for mandatory columns and we
    should treat "map :  control" same as "map: control" or "map:control" to
    make the headers more user friendly.

    Args:
      header (basestring): Raw header value found in the cells of each row of
        all blocks in the imported file.

    Returs:
      String without "*" on mandatory columns and with removed extra spaces in
      the mapping columns.
    """
    header = header.strip("*").lower()
    if header.startswith("map:") or header.startswith("unmap:"):
      header = ":".join(part.strip() for part in header.split(":"))
    return header

  @staticmethod
  def _check_object(row_converter):
    """Check object if it has any pre commit checks.

    The check functions can mutate the row_converter object and mark it
    to be ignored if there are any errors detected.

    Args:
      row_converter: Row converter for the row we want to check
    """
    checker = pre_commit_checks.CHECKS.get(type(row_converter.obj).__name__)
    if checker and callable(checker):
      checker(row_converter)

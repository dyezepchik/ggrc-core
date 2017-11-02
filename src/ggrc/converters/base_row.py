# Copyright (C) 2017 Google Inc.
# Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>

"""This module is used for handling a single line from a csv file.
"""

import collections

import ggrc.services
from ggrc import db
from ggrc.converters import errors
from ggrc.converters import get_importables
from ggrc.login import get_current_user_id
from ggrc.models.reflection import AttributeInfo
from ggrc.rbac import permissions
from ggrc.services import signals


class RowConverter(object):
  """Base class for handling row data."""

  def __init__(self, block_converter, object_class, **options):
    self.block_converter = block_converter
    self.options = options.copy()
    self.object_class = object_class
    self.obj = options.get("obj")
    self.from_ids = self.obj is not None
    self.is_new = True
    self.is_delete = False
    self.is_deprecated = False
    self.do_not_expunge = False
    self.ignore = False
    self.index = options.get("index", -1)
    self.row = options.get("row", [])
    self.attrs = collections.OrderedDict()
    self.objects = collections.OrderedDict()
    self.id_key = ""
    offset = 3  # 2 header rows and 1 for 0 based index
    self.line = self.index + self.block_converter.offset + offset
    self.headers = options.get("headers", [])

  def add_error(self, template, **kwargs):
    """Add error for current row.

    Add an error entry for the current row and mark it as ignored. If the error
    occurred on a new object, it gets removed from the new object cache dict.

    Args:
      template: String template.
      **kwargs: Arguments needed to format the string template.
    """
    message = template.format(line=self.line, **kwargs)
    self.block_converter.row_errors.append(message)
    new_objects = self.block_converter.converter.new_objects[self.object_class]
    key = self.get_value(self.id_key)
    if key in new_objects:
      del new_objects[key]
    self.ignore = True

  def add_warning(self, template, **kwargs):
    message = template.format(line=self.line, **kwargs)
    self.block_converter.row_warnings.append(message)

  def handle_csv_row_data(self, field_list=None):
    """ Pack row data with handlers """
    handle_fields = self.headers if field_list is None else field_list
    for i, (attr_name, header_dict) in enumerate(self.headers.items()):
      if attr_name not in handle_fields or \
              attr_name in self.attrs or \
              self.is_delete:
        continue
      handler = header_dict["handler"]
      item = handler(self, attr_name, parse=True,
                     raw_value=self.row[i], **header_dict)
      if header_dict.get("type") == AttributeInfo.Type.PROPERTY:
        self.attrs[attr_name] = item
      else:
        self.objects[attr_name] = item
      if not self.ignore:
        if attr_name == "status" and hasattr(self.obj, "DEPRECATED"):
          self.is_deprecated = (
              self.obj.DEPRECATED == item.value != self.obj.status
          )
        if attr_name in ("slug", "email"):
          self.id_key = attr_name
          self.obj = self.get_or_generate_object(attr_name)
          item.set_obj_attr()
      item.check_unique_consistency()

  def handle_obj_row_data(self):
    for attr_name, header_dict in self.headers.items():
      handler = header_dict["handler"]
      item = handler(self, attr_name, **header_dict)
      if header_dict.get("type") == AttributeInfo.Type.PROPERTY:
        self.attrs[attr_name] = item
      else:
        self.objects[attr_name] = item

  def handle_row_data(self, field_list=None):
    if self.from_ids:
      self.handle_obj_row_data()
    else:
      self.handle_csv_row_data(field_list)

  def check_mandatory_fields(self):
    """Check if the new object contains all mandatory columns."""
    if not self.is_new or self.is_delete or self.ignore:
      return
    headers = self.block_converter.object_headers
    mandatory = [key for key, header in headers.items() if header["mandatory"]]
    missing_keys = set(mandatory).difference(set(self.headers.keys()))
    # TODO: fix mandatory checks for individual rows based on object level
    # custom attributes.
    missing = [headers[key]["display_name"] for key in missing_keys if
               headers[key]["type"] != AttributeInfo.Type.OBJECT_CUSTOM]
    if missing:
      self.add_error(errors.MISSING_COLUMN,
                     s="s" if len(missing) > 1 else "",
                     column_names=", ".join(missing))

  def find_by_key(self, key, value):
    return self.object_class.query.filter_by(**{key: value}).first()

  def get_value(self, key):
    item = self.attrs.get(key) or self.objects.get(key)
    if item:
      return item.value
    return None

  def set_ignore(self, ignore=True):
    self.ignore = ignore

  def set_do_not_expunge(self, do_not_expunge=True):
    """Mark an ignored object not to be expunged from a session

    We may not expunge objects with duplicate slugs, because they represent
    the same object.
    """
    self.do_not_expunge = do_not_expunge

  def get_or_generate_object(self, attr_name):
    """Fetch an existing object if possible or create and return a new one.

    Note: Person object is the only exception here since it does not have a
    slug field.
    """
    value = self.get_value(attr_name)
    new_objects = self.block_converter.converter.new_objects[self.object_class]
    if value in new_objects:
      return new_objects[value]
    obj = self.get_object_by_key(attr_name)
    if value:
      new_objects[value] = obj
    obj.modified_by_id = get_current_user_id()
    return obj

  def get_object_by_key(self, key="slug"):
    """ Get object if the slug is in the system or return a new object """
    value = self.get_value(key)
    self.is_new = False
    obj = self.find_by_key(key, value)
    if not obj:
      # We assume that 'get_importables()' returned value contains
      # names of the objects that cannot be created via import but
      # can be updated.
      if self.block_converter.class_name.lower() not in get_importables():
        self.add_error(errors.CREATE_INSTANCE_ERROR)
      obj = self.object_class()
      self.is_new = True
    elif not permissions.is_allowed_update_for(obj):
      self.ignore = True
      self.add_error(errors.PERMISSION_ERROR)
    return obj

  def setup_secondary_objects(self):
    """Import secondary objects.

    This function creates and stores all secondary object such as relationships
    and any linked object that need the original object to be saved before they
    can be processed. This is usually due to needing the id of the original
    object that is created with a csv import.
    """
    if not self.obj or self.ignore or self.is_delete:
      return
    for mapping in self.objects.values():
      mapping.set_obj_attr()

  def setup_object(self):
    """ Set the object values or relate object values

    Set all object attributes to the value specified in attrs. If the value
    is in some related object such as "UserRole" it should be added there and
    handled by the handler defined in attrs.
    """
    if self.ignore:
      return

    for item_handler in self.attrs.values():
      if not item_handler.view_only:
        item_handler.set_obj_attr()

  def send_post_commit_signals(self, event=None):
    """Send after commit signals for all objects

    This function sends proper signals for all objects depending if the object
    was created, updated or deleted.
    Note: signals are only sent for the row objects. Secondary objects such as
    Relationships do not get any signals triggered.
    ."""
    if self.ignore:
      return
    service_class = getattr(ggrc.services, self.object_class.__name__)
    service_class.model = self.object_class
    if self.is_delete:
      signals.Restful.model_deleted_after_commit.send(
          self.object_class, obj=self.obj, service=service_class, event=event)
    elif self.is_new:
      signals.Restful.model_posted_after_commit.send(
          self.object_class, obj=self.obj, src={}, service=service_class,
          event=event)
    else:
      signals.Restful.model_put_after_commit.send(
          self.object_class, obj=self.obj, src={}, service=service_class,
          event=event)

  def send_pre_commit_signals(self):
    """Send before commit signals for all objects.

    This function sends proper signals for all objects depending if the object
    was created, updated or deleted.
    Note: signals are only sent for the row objects. Secondary objects such as
    Relationships do not get any signals triggered.
    """
    if self.ignore:
      return
    service_class = getattr(ggrc.services, self.object_class.__name__)
    service_class.model = self.object_class
    if self.is_delete:
      signals.Restful.model_deleted.send(
          self.object_class, obj=self.obj, service=service_class)
    elif self.is_new:
      signals.Restful.model_posted.send(
          self.object_class, obj=self.obj, src={}, service=service_class)
    else:
      signals.Restful.model_put.send(
          self.object_class, obj=self.obj, src={}, service=service_class)

  def insert_object(self):
    """Add the row object to the current database session."""
    if self.ignore or self.is_delete:
      return

    if self.is_new:
      db.session.add(self.obj)
    for handler in self.attrs.values():
      handler.insert_object()

  def insert_secondary_objects(self):
    """Add additional objects to the current database session.

    This is used for adding any extra created objects such as Relationships, to
    the current session to be committed.
    """
    if not self.obj or self.ignore or self.is_delete:
      return
    for secondery_object in self.objects.values():
      secondery_object.insert_object()

  def to_array(self, fields):
    """Get an array representation of the current row.

    Fiter the values to match the fields array and return the string
    representation of the values.

    Args:
      fields (list of strings): A list of columns that will be included in the
        output array. This is basically a filter of all possible fields that
        this row contains.

    Returns:
      list of strings where each cell contains a string value of the
      coresponding field.
    """
    row = []
    for field in fields:
      field_type = self.headers.get(field, {}).get("type")
      if field_type == AttributeInfo.Type.PROPERTY:
        field_handler = self.attrs.get(field)
      else:
        field_handler = self.objects.get(field)
      value = field_handler.get_value() if field_handler else ""
      row.append(value or "")
    return row

# Copyright (C) 2018 Google Inc.
# Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>

"""RBAC module"""

import datetime
import itertools

import sqlalchemy.orm
from sqlalchemy import and_
from sqlalchemy import literal
from sqlalchemy import or_
from sqlalchemy.orm import aliased
from flask import Blueprint
from flask import g

from ggrc import db
from ggrc import settings
from ggrc.app import app
from ggrc.login import get_current_user
from ggrc.models import all_models
from ggrc.models.audit import Audit
from ggrc.models.program import Program
from ggrc.rbac import permissions as rbac_permissions
from ggrc.rbac.permissions_provider import DefaultUserPermissions
from ggrc.services.common import _get_cache_manager
from ggrc.services import signals
from ggrc.services.registry import service
from ggrc.utils import benchmark
from ggrc_basic_permissions import basic_roles
from ggrc_basic_permissions.contributed_roles import BasicRoleDeclarations
from ggrc_basic_permissions.contributed_roles import BasicRoleImplications
from ggrc_basic_permissions.converters.handlers import COLUMN_HANDLERS
from ggrc_basic_permissions.models import ContextImplication
from ggrc_basic_permissions.models import get_ids_related_to
from ggrc_basic_permissions.models import Role
from ggrc_basic_permissions.models import UserRole


blueprint = Blueprint(
    'permissions',
    __name__,
    template_folder='templates',
    static_folder='static',
    static_url_path='/static/ggrc_basic_permissions',
)

PERMISSION_CACHE_TIMEOUT = 3600  # 60 minutes


def get_public_config(_):
  """Expose additional permissions-dependent config to client.
    Specifically here, expose GGRC_BOOTSTRAP_ADMIN values to ADMIN users.
  """
  public_config = {}
  if rbac_permissions.is_admin():
    if hasattr(settings, 'BOOTSTRAP_ADMIN_USERS'):
      public_config['BOOTSTRAP_ADMIN_USERS'] = settings.BOOTSTRAP_ADMIN_USERS
  return public_config


class CompletePermissionsProvider(object):
  """Permission provider set in the USER_PERMISSIONS_PROVIDER setting"""

  def __init__(self, _):
    pass

  def permissions_for(self, _):
    """Load user permissions and make sure they get loaded into session"""
    ret = UserPermissions()
    # force the permissions to be loaded into session, otherwise templates
    # that depend on the permissions being available in session may assert
    # the user has no permissions!
    ret.check_permissions()
    return ret

  def handle_admin_user(self, user):
    pass


class BasicUserPermissions(DefaultUserPermissions):
  """User permissions that aren't kept in session."""

  def __init__(self, user):
    self.user = user
    with benchmark('BasicUserPermissions > load permissions for user'):
      self.permissions = load_permissions_for(user)

  def _permissions(self):
    return self.permissions


class UserPermissions(DefaultUserPermissions):
  """User permissions cached in the global session object"""

  @property
  def _request_permissions(self):
    return getattr(g, '_request_permissions', None)

  @_request_permissions.setter
  def _request_permissions(self, value):
    setattr(g, '_request_permissions', value)

  def _permissions(self):
    self.check_permissions()
    return self._request_permissions

  def check_permissions(self):
    if not self._request_permissions:
      self.load_permissions()

  def get_email_for(self, user):
    return user.email if hasattr(user, 'email') else 'ANONYMOUS'

  def load_permissions(self):
    """Load permissions for the currently logged in user"""
    user = get_current_user()
    email = self.get_email_for(user)
    self._request_permissions = {}
    self._request_permissions['__user'] = email
    if user is None or user.is_anonymous():
      self._request_permissions = {}
    else:
      with benchmark('load_permissions'):
        self._request_permissions = load_permissions_for(user)


def collect_permissions(src_permissions, context_id, permissions):
  for action, resource_permissions in src_permissions.items():
    if not resource_permissions:
      permissions.setdefault(action, dict())
    for resource_permission in resource_permissions:
      if type(resource_permission) in [str, unicode]:
        resource_type = str(resource_permission)
        condition = None
      else:
        resource_type = str(resource_permission['type'])
        condition = resource_permission.get('condition', None)
        terms = resource_permission.get('terms', [])
      permissions.setdefault(action, {})\
          .setdefault(resource_type, dict())\
          .setdefault('contexts', list())
      if context_id is not None:
        permissions[action][resource_type]['contexts'].append(context_id)
      elif condition in (None, "forbid"):
        permissions[action][resource_type]['contexts'].append(context_id)
      if condition:
        permissions[action][resource_type]\
            .setdefault('conditions', dict())\
            .setdefault(context_id, list())\
            .append({
                'condition': condition,
                'terms': terms,
            })


def query_memcache(key):
  """Check if cached permissions are available

  Args:
      key (string): key of the stored permissions
  Returns:
      cache (memcache_client): memcache client or None if caching
                               is not available
      permissions_cache (dict): dict with all permissions or None if there
                                was a cache miss
  """
  if not getattr(settings, 'MEMCACHE_MECHANISM', False):
    return None, None

  cache = _get_cache_manager().cache_object.memcache_client
  cached_keys_set = cache.get('permissions:list') or set()
  if key not in cached_keys_set:
    # We set the permissions:list variable so that we are able to batch
    # remove all permissions related keys from memcache
    cached_keys_set.add(key)
    cache.set('permissions:list', cached_keys_set, PERMISSION_CACHE_TIMEOUT)
    return cache, None

  permissions_cache = cache.get(key)
  if permissions_cache:
    # If the key is both in permissions:list and in memcache itself
    # it is safe to return the cached permissions
    return cache, permissions_cache
  return cache, None


def load_default_permissions(permissions):
  """Load default permissions for all users

  Args:
      permissions (dict): dict where the permissions will be stored
  Returns:
      None
  """
  default_permissions = {
      "read": [
          "Help",
          "CustomAttributeDefinition",
          {
              "type": "CustomAttributeValue",
              "terms": {
                  "list_property": "owners",
                  "value": "$current_user"
              },
              "condition": "contains"
          },
          {
              "type": "NotificationConfig",
              "terms": {
                  "property_name": "person",
                  "value": "$current_user"
              },
              "condition": "is"
          },
      ],
      "create": [
          {
              "type": "NotificationConfig",
              "terms": {
                  "property_name": "person",
                  "value": "$current_user"
              },
              "condition": "is"
          },
      ],
      "update": [
          {
              "type": "NotificationConfig",
              "terms": {
                  "property_name": "person",
                  "value": "$current_user"
              },
              "condition": "is"
          },
      ]
  }
  collect_permissions(default_permissions, None, permissions)


def load_bootstrap_admin(user, permissions):
  """Add bootstrap admin permissions if user is in BOOTSTRAP_ADMIN_USERS

  Args:
      user (Person): Person object
      permissions (dict): dict where the permissions will be stored
  Returns:
      None
  """
  # Add `ADMIN_PERMISSION` for "bootstrap admin" users
  if hasattr(settings, 'BOOTSTRAP_ADMIN_USERS') \
     and user.email in settings.BOOTSTRAP_ADMIN_USERS:
    admin_permissions = {
        DefaultUserPermissions.ADMIN_PERMISSION.action: [
            DefaultUserPermissions.ADMIN_PERMISSION.resource_type
        ]
    }
    collect_permissions(
        admin_permissions,
        DefaultUserPermissions.ADMIN_PERMISSION.context_id,
        permissions)


def load_user_roles(user, permissions):
  """Load all user roles for user

  Args:
      user (Person): Person object
      permissions (dict): dict where the permissions will be stored
  Returns:
      source_contexts_to_rolenames (dict): Role names for contexts
  """
  # Add permissions from all DB-managed roles
  user_roles = db.session.query(UserRole)\
      .options(
          sqlalchemy.orm.undefer_group('UserRole_complete'),
          sqlalchemy.orm.undefer_group('Role_complete'),
          sqlalchemy.orm.joinedload('role'))\
      .filter(UserRole.person_id == user.id)\
      .order_by(UserRole.updated_at.desc())\
      .all()

  source_contexts_to_rolenames = {}
  for user_role in user_roles:
    source_contexts_to_rolenames.setdefault(
        user_role.context_id, list()).append(user_role.role.name)
    if isinstance(user_role.role.permissions, dict):
      collect_permissions(
          user_role.role.permissions, user_role.context_id, permissions)
  return source_contexts_to_rolenames


def load_personal_context(user, permissions):
  """Load personal context for user

  Args:
      user (Person): Person object
      permissions (dict): dict where the permissions will be stored
  Returns:
      None
  """
  personal_context = _get_or_create_personal_context(user)

  permissions.setdefault('__GGRC_ADMIN__', {})\
      .setdefault('__GGRC_ALL__', dict())\
      .setdefault('contexts', list())\
      .append(personal_context.id)


def load_access_control_list(user, permissions):
  """Load permissions from access_control_list"""
  acl = all_models.AccessControlList
  acr = all_models.AccessControlRole
  access_control_list = db.session.query(
      acl.object_type, acl.object_id, acr.read, acr.update, acr.delete
  ).filter(and_(all_models.AccessControlList.person_id == user.id,
                all_models.AccessControlList.ac_role_id == acr.id)).all()

  for object_type, object_id, read, update, delete in access_control_list:
    actions = (("read", read), ("view_object_page", read),
               ("update", update), ("delete", delete))
    for action, allowed in actions:
      if not allowed:
        continue
      permissions.setdefault(action, {})\
          .setdefault(object_type, {})\
          .setdefault('resources', set())\
          .add(object_id)


def load_backlog_workflows(permissions):
  """Load permissions for backlog workflows

  Args:
      permissions (dict): dict where the permissions will be stored
  Returns:
      None
  """
  # add permissions for backlog workflows to everyone
  actions = ["read", "edit", "update"]
  _types = ["Workflow", "Cycle", "CycleTaskGroup",
            "CycleTaskGroupObjectTask", "TaskGroup", "CycleTaskEntry"]
  for _, _, wf_context_id in backlog_workflows().all():
    for _type in _types:
      if _type == "CycleTaskGroupObjectTask":
        actions += ["delete"]
      if _type == "CycleTaskEntry":
        actions += ["create"]
      for action in actions:
        permissions.setdefault(action, {})\
            .setdefault(_type, {})\
            .setdefault('contexts', list())\
            .append(wf_context_id)


def store_results_into_memcache(permissions, cache, key):
  """Load personal context for user

  Args:
      permissions (dict): dict where the permissions will be stored
      cache (cache_manager): Cache manager that should be used for storing
                             permissions
      key (string): key of under which permissions should be stored
  Returns:
      None
  """
  if cache is None:
    return

  cached_keys_set = cache.get('permissions:list') or set()
  if key in cached_keys_set:
    # We only add the permissions to the cache if the
    # key still exists in the permissions:list after
    # the query has executed.
    cache.set(key, permissions, PERMISSION_CACHE_TIMEOUT)


def load_permissions_for(user):
  """Permissions is dictionary that can be exported to json to share with
  clients. Structure is:
  ..

    permissions[action][resource_type][contexts]
                                      [conditions][context][context_conditions]

  'action' is one of 'create', 'read', 'update', 'delete'.
  'resource_type' is the name of a valid GGRC resource type.
  'contexts' is a list of context_id where the action is allowed.
  'conditions' is a dictionary of 'context_conditions' indexed by 'context'
    where 'context' is a context_id.
  'context_conditions' is a list of dictionaries with 'condition' and 'terms'
    keys.
  'condition' is the string name of a conditional operator, such as 'contains'.
  'terms' are the arguments to the 'condition'.
  """
  permissions = {}
  key = 'permissions:{}'.format(user.id)

  with benchmark("load_permissions > query memcache"):
    cache, result = query_memcache(key)
    if result:
      return result

  with benchmark("load_permissions > load default permissions"):
    load_default_permissions(permissions)

  with benchmark("load_permissions > load bootstrap admins"):
    load_bootstrap_admin(user, permissions)

  with benchmark("load_permissions > load user roles"):
    load_user_roles(user, permissions)

  with benchmark("load_permissions > load personal context"):
    load_personal_context(user, permissions)

  with benchmark("load_permissions > load access control list"):
    load_access_control_list(user, permissions)

  with benchmark("load_permissions > load backlog workflows"):
    load_backlog_workflows(permissions)

  with benchmark("load_permissions > store results into memcache"):
    store_results_into_memcache(permissions, cache, key)

  return permissions


def backlog_workflows():
  """Creates a query that returns all backlog workflows which
  all users can access.

    Returns:
        db.session.query object that selects the following columns:
            | id | type | context_id |
  """
  _workflow = aliased(all_models.Workflow, name="wf")
  return db.session.query(_workflow.id,
                          literal("Workflow").label("type"),
                          _workflow.context_id)\
      .filter(_workflow.kind == "Backlog")


def _get_or_create_personal_context(user):
  personal_context = user.get_or_create_object_context(
      context=1,
      name='Personal Context for {0}'.format(user.id),
      description='')
  return personal_context


@signals.Restful.model_posted.connect_via(Program)
def handle_program_post(sender, obj=None, src=None, service=None):
  db.session.flush()
  # get the personal context for this logged in user
  user = get_current_user()
  personal_context = _get_or_create_personal_context(user)
  context = obj.build_object_context(
      context=personal_context,
      name='{object_type} Context {timestamp}'.format(
          object_type=service.model.__name__,
          timestamp=datetime.datetime.utcnow()),
      description='',
  )
  context.modified_by = get_current_user()

  db.session.add(obj)
  db.session.flush()
  db.session.add(context)
  db.session.flush()
  obj.contexts.append(context)
  obj.context = context

  # add a user_roles mapping assigning the user creating the program
  # the ProgramOwner role in the program's context.
  program_owner_role = basic_roles.program_owner()
  user_role = UserRole(
      person=get_current_user(),
      role=program_owner_role,
      context=context,
      modified_by=get_current_user())
  # pass along a temporary attribute for logging the events.
  user_role._display_related_title = obj.title
  db.session.add(user_role)
  db.session.flush()

  # Create the context implication for Program roles to default context
  db.session.add(ContextImplication(
      source_context=context,
      context=None,
      source_context_scope='Program',
      context_scope=None,
      modified_by=get_current_user()))

  if not src.get('private'):
    # Add role implication - all users can read a public program
    add_public_program_context_implication(context)


def add_public_program_context_implication(context, check_exists=False):
  if check_exists and db.session.query(ContextImplication)\
      .filter(
          and_(ContextImplication.context_id == context.id,
               ContextImplication.source_context_id.is_(None))).count() > 0:
    return
  db.session.add(ContextImplication(
      source_context=None,
      context=context,
      source_context_scope=None,
      context_scope='Program',
      modified_by=get_current_user(),
  ))


def create_audit_context(audit):
  # Create an audit context
  context = audit.build_object_context(
      context=audit.context,
      name='Audit Context {timestamp}'.format(
          timestamp=datetime.datetime.utcnow()),
      description='',
  )
  context.modified_by = get_current_user()
  db.session.add(context)
  db.session.flush()

  # Create the program -> audit implication
  db.session.add(ContextImplication(
      source_context=audit.context,
      context=context,
      source_context_scope='Program',
      context_scope='Audit',
      modified_by=get_current_user(),
  ))

  db.session.add(audit)

  # Create the role implication for Auditor from Audit for default context
  db.session.add(ContextImplication(
      source_context=context,
      context=None,
      source_context_scope='Audit',
      context_scope=None,
      modified_by=get_current_user(),
  ))
  db.session.flush()

  # Place the audit in the audit context
  audit.context = context


@signals.Restful.collection_posted.connect_via(Audit)
def handle_audit_post(sender, objects=None, sources=None):
  for obj, src in itertools.izip(objects, sources):
    if not src.get("operation", None):
      db.session.flush()
      create_audit_context(obj)


@signals.Restful.model_deleted.connect
def handle_resource_deleted(sender, obj=None, service=None):
  if obj.context \
     and obj.context.related_object_id \
     and obj.id == obj.context.related_object_id \
     and obj.__class__.__name__ == obj.context.related_object_type:
    db.session.query(UserRole) \
        .filter(UserRole.context_id == obj.context_id) \
        .delete()
    db.session.query(ContextImplication) \
        .filter(
            or_(ContextImplication.context_id == obj.context_id,
                ContextImplication.source_context_id == obj.context_id))\
        .delete()
    # Deleting the context itself is problematic, because unattached objects
    #   may still exist and cause a database error.  Instead of implicitly
    #   cascading to delete those, just leave the `Context` object in place.
    #   It and its objects will be visible *only* to Admin users.
    # db.session.delete(obj.context)


@app.context_processor
def authorized_users_for():
  return {'authorized_users_for': UserRole.role_assignments_for}


def contributed_services():
  """The list of all collections provided by this extension."""
  return [
      service('roles', Role),
      service('user_roles', UserRole),
  ]


def contributed_object_views():
  from ggrc.views.registry import object_view
  return [
      object_view(Role)
  ]


def contributed_column_handlers():
  return COLUMN_HANDLERS


ROLE_DECLARATIONS = BasicRoleDeclarations()
ROLE_IMPLICATIONS = BasicRoleImplications()

contributed_get_ids_related_to = get_ids_related_to

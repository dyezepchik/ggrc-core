# Copyright (C) 2017 Google Inc.
# Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>

"""Checker function for import pre commit hooks."""

from collections import OrderedDict
from ggrc.converters import errors
from ggrc_basic_permissions.models import UserRole


def check_tasks(row_converter):
  """Checker for task group task objects.

  This checker should make sure if a task group task has any invalid values
  that should be ignored. Object will not be checked if there's already
  an error on and it's marked as ignored.

  Args:
    row_converter: RowConverter object with row data for a task group task
      import.
  """
  if row_converter.ignore:
    return

  obj = row_converter.obj
  if obj.start_date > obj.end_date:
    row_converter.add_error(
        errors.INVALID_START_END_DATES,
        start_date="Start date",
        end_date="End date",
    )


DENY_FINISHED_DATES_STATUSES_STR = ("<'Assigned' / 'In Progress' / "
                                    "'Declined' / 'Deprecated'>")
DENY_VERIFIED_DATES_STATUSES_STR = ("<'Assigned' / 'In Progress' / "
                                    "'Declined' / 'Deprecated' / 'Finished'>")


def check_cycle_tasks(row_converter):  # noqa
  """Checker for CycleTaskGroupObjectTask model objects.

  This checker should make sure if a cycle-task has any invalid values
  that should be ignored during update via import.

  Args:
    row_converter: RowConverter object with row data for a cycle-task
      import.
  """
  # Cycle-Task creation is denied. Don't need checks for new items.
  if row_converter.is_new:
    return
  obj = row_converter.obj
  if obj.start_date > obj.end_date:
    row_converter.add_error(
        errors.INVALID_START_END_DATES,
        start_date="Start Date",
        end_date="Due Date",
    )
  if (obj.finished_date and obj.verified_date and
          obj.finished_date > obj.verified_date):
    row_converter.add_error(
        errors.INVALID_START_END_DATES,
        start_date="Actual Finish Date",
        end_date="Actual Verified Date",
    )
  if obj.status not in (obj.FINISHED, obj.VERIFIED):
    if obj.finished_date:
      row_converter.add_error(
          errors.INVALID_STATUS_DATE_CORRELATION,
          date="Actual Finish Date",
          deny_states=DENY_FINISHED_DATES_STATUSES_STR,
      )
    if obj.verified_date:
      row_converter.add_error(
          errors.INVALID_STATUS_DATE_CORRELATION,
          date="Actual Verified Date",
          deny_states=DENY_VERIFIED_DATES_STATUSES_STR,
      )
  if obj.status == obj.FINISHED and obj.verified_date:
    row_converter.add_error(
        errors.INVALID_STATUS_DATE_CORRELATION,
        date="Actual Verified Date",
        deny_states=DENY_VERIFIED_DATES_STATUSES_STR,
    )


def check_workflows(row_converter):
  """Checker for Workflow object.

  Check if a Workflow has any invalid values. If so, it should be ignored.
  Object will not be checked if there's already an error exists
  and it's marked as ignored.

  Args:
    row_converter: RowConverter object with row data for a task group task
      import.
  """
  if row_converter.ignore:
    return

  obj = row_converter.obj
  if (obj.unit is None and obj.repeat_every is not None or
          obj.unit is not None and obj.repeat_every is None):
    row_converter.add_error(
        errors.VALIDATION_ERROR,
        column_name="'repeat_every', 'unit'",
        message="'repeat_every' and 'unit' fields can be set to NULL only"
                " simultaneously",
    )


def check_assessment(row_converter):
  """Checker for Assessment model instance.

  This checker should make sure if an assessment are invalid or non-importable
  and should be ignored.

  Args:
      row_converter: RowConverter object with row data for an assessment
        import.
      kwargs: Dict with options.
  """
  if row_converter.obj.archived:
    row_converter.add_error(errors.ARCHIVED_IMPORT_ERROR)


def check_assessment_status(row_converter):
  """Verify Assessment status.

  This function should make sure if an assessment can set-up new status.

  Args:
      row_converter: RowConverter object with row data for an assessment
        import.
  """
  try:
    row_converter.obj.validate_done_state(
        row_converter.old_values.get("status"),
        row_converter.obj.status
    )
  except ValueError as exp:
    status_alias = row_converter.headers.get("status", {}).get("display_name")
    row_converter.add_error(
        errors.VALIDATION_ERROR, column_name=status_alias, message=exp.message
    )


def check_program_roles(row_converter):
  """Checks for one person to have a single program role after the import.

  For this to happen, pull all people for empty imported values. Since
  these values are not going to be deleted, duplicate people might appear
  after import is finished. Roles could be raised by import but can not be
  lowered.
  E.g.:
              prg_owner    prg_editor    prg_reader
    was:        user1        user2         user3
    importing:  user4        user3

    After the import user3 should obtain prg_editor role, prg_reader should
    be deleted

              prg_owner    prg_editor    prg_reader
    was:        user1        user2         user3
    importing:  user4                      user2

    After the import user2, user3 remain as they were

  Args:
    row_converter: RowConverter object with row data for Program
  """
  roles_lo_to_hi = OrderedDict([('program_reader', 'ProgramReader'),
                                ('program_editor', 'ProgramEditor'),
                                ('program_owner', 'ProgramOwner')])
  roles_index = row_converter.object_roles.copy()  # {'program_editor': user1}
  reverse_roles_index = {}  # {user1: 'program_editor':}

  # complete role index with roles not being imported
  for role_attr, role_name in roles_lo_to_hi.items():
    role = row_converter.block_converter.get_role(role_name)
    user_roles = UserRole.query.filter_by(
        role=role,
        context_id=row_converter.obj.context_id
    )
    roles_index[role_attr].update([ur.person for ur in user_roles])

  # replace roles for users with the higher ones(going from low to high role)
  for role_attr, role_name in roles_lo_to_hi.items():
    for user in roles_index[role_attr]:
      if user in reverse_roles_index:
        # conflict found! Add warning, replace with a higher role
        row_converter.add_warning(errors.DUPLICATE_PERSON_FOR_OBJECT_ROLES,
                                  person=user.email)
        # mark this UserRole for deletion under the conflicting column handler
        col_handler = row_converter.objects.get(role_attr)
        if col_handler:
          col_handler.delete_user_roles.append(
              (roles_lo_to_hi[reverse_roles_index[user]], user)
          )
      reverse_roles_index[user] = role_attr

  # get back from inverted index to forward index
  row_converter.object_roles.clear()
  for user, role in reverse_roles_index.items():
    row_converter.object_roles[role].add(user)

  # assign clean values to column handlers
  for role_attr in roles_lo_to_hi.keys():
    if role_attr in row_converter.objects:
      people = row_converter.object_roles.get(role_attr)
      row_converter.objects[role_attr].value = list(people) if people else None


CHECKS = {
    "TaskGroupTask": check_tasks,
    "CycleTaskGroupObjectTask": check_cycle_tasks,
    "Workflow": check_workflows,
    "Assessment": check_assessment,
    "Program": check_program_roles,
}

SECONDARY_CHECKS = {
    "Assessment": check_assessment_status
}

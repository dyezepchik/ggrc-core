# Copyright (C) 2018 Google Inc.
# Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>

"""
Check if audit has a custom attribute named "State" since Audit's Status is
renamed to State

Create Date: 2018-02-07 14:55:21.450857
"""
# disable Invalid constant name pylint warning for mandatory Alembic variables.
# pylint: disable=invalid-name

from ggrc.app import app
from ggrc.migrations.utils.resolve_duplicates import rename_ca_title


# revision identifiers, used by Alembic.
revision = '4e5ef956af94'
down_revision = '4906ff3f9c7b'


def upgrade():
  """Upgrade database schema and/or data, creating a new revision."""
  with app.app_context():
    rename_ca_title("state", ["audit"])


def downgrade():
  """Downgrade database schema and/or data back to the previous revision."""
  # Renamed CAs can't be rolled back as we don't know
  # which of them were renamed.

"""Add title and notes to ChatUser.

Revision ID: f8acbd22162
Revises: 32615979a6ce
Create Date: 2016-01-14 22:01:24.290897

"""

# revision identifiers, used by Alembic.
revision = 'f8acbd22162'
down_revision = '32615979a6ce'
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('chat_users', sa.Column('notes', sa.UnicodeText(), nullable=True))
    op.add_column('chat_users', sa.Column('title', sa.Unicode(length=50), nullable=True))
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('chat_users', 'title')
    op.drop_column('chat_users', 'notes')
    ### end Alembic commands ###
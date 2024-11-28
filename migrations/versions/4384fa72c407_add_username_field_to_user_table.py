"""Add username field to User table

Revision ID: 4384fa72c407
Revises: 
Create Date: 2024-11-28 16:23:20.503163

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '4384fa72c407'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('username', sa.String(length=120), nullable=False))
        batch_op.create_unique_constraint('uq_user_username', ['username'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_constraint('uq_user_username', type_='unique')
        batch_op.drop_column('username')

    # ### end Alembic commands ###

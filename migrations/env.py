# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Alembic environment for the async Skills Hub database."""

from __future__ import annotations

import asyncio
from logging.config import fileConfig
from os import environ

from alembic import context
from sqlalchemy import Connection, pool
from sqlalchemy.ext.asyncio import async_engine_from_config

from hub.db._models import Base
from hub.db.session import normalise_async_database_url

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

configured_url = environ.get(
    "HUB_DATABASE_URL",
    config.get_main_option("sqlalchemy.url"),
)
config.set_main_option(
    "sqlalchemy.url",
    normalise_async_database_url(configured_url).render_as_string(hide_password=False),
)
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations without creating an Engine."""

    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """Configure and run migrations over a synchronous connection facade."""

    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Create an async engine and execute migrations."""

    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations with an async database driver."""

    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

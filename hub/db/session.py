# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Async database engine and transaction lifecycle."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import event
from sqlalchemy.engine import URL, make_url
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from hub.db._models import Base
from hub.db.errors import DatabaseConfigurationError


def normalise_async_database_url(database_url: str) -> URL:
    """Normalise the supported SQLite shorthand to its async driver URL."""

    try:
        url = make_url(database_url)
    except (TypeError, ValueError) as exc:
        raise DatabaseConfigurationError("HUB_DATABASE_URL is invalid") from exc

    if url.get_backend_name() != "sqlite":
        raise DatabaseConfigurationError(
            "only SQLite is supported by the current Hub bootstrap"
        )
    if url.drivername == "sqlite":
        return url.set(drivername="sqlite+aiosqlite")
    if url.drivername != "sqlite+aiosqlite":
        raise DatabaseConfigurationError(
            "SQLite HUB_DATABASE_URL must use the aiosqlite async driver"
        )
    return url


def _prepare_sqlite_path(url: URL) -> None:
    database = url.database
    if not database or database == ":memory:" or database.startswith("file:"):
        return
    Path(database).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)


def _configure_sqlite_connection(
    dbapi_connection: Any, _connection_record: Any
) -> None:
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA journal_mode=WAL")
    finally:
        cursor.close()


class Database:
    """Own the async engine and provide transaction-scoped sessions."""

    def __init__(self, database_url: str, *, echo: bool = False) -> None:
        self.url = normalise_async_database_url(database_url)
        engine_options: dict[str, Any] = {"echo": echo, "pool_pre_ping": True}

        if self.url.get_backend_name() == "sqlite":
            _prepare_sqlite_path(self.url)
            if self.url.database in {None, "", ":memory:"}:
                engine_options["poolclass"] = StaticPool

        try:
            self.engine: AsyncEngine = create_async_engine(self.url, **engine_options)
        except (ImportError, ModuleNotFoundError) as exc:
            raise DatabaseConfigurationError(
                f"async database driver is unavailable for {self.url.drivername}"
            ) from exc

        if self.url.get_backend_name() == "sqlite":
            event.listen(
                self.engine.sync_engine,
                "connect",
                _configure_sqlite_connection,
            )

        self._session_factory = async_sessionmaker(
            bind=self.engine,
            expire_on_commit=False,
            autoflush=False,
        )

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[AsyncSession]:
        """Commit a unit of work or roll it back on any failure."""

        async with self._session_factory() as session:
            async with session.begin():
                yield session

    async def bootstrap_schema(self) -> None:
        """Create missing tables for local/test bootstrap; safe to call repeatedly."""

        async with self.engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

    async def dispose(self) -> None:
        """Release all pooled database connections."""

        await self.engine.dispose()

"""
Database Configuration and Connection Management

This module handles database connections, session management, and table creation
for the PhishGuard enterprise security platform.
"""

import asyncio
from typing import AsyncGenerator

from sqlalchemy import MetaData, create_engine, event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool, QueuePool

from .utils.config import settings
from .utils.logger import logger

# Create async engine with optimized connection pooling
engine = create_async_engine(
    settings.DATABASE_URL,
    poolclass=QueuePool,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
    pool_pre_ping=True,
    pool_recycle=3600,  # Recycle connections every hour
    echo=settings.DEBUG,
)

# Create sync engine for migrations
sync_engine = create_engine(
    settings.DATABASE_URL.replace("+asyncpg", ""),
    poolclass=QueuePool,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    pool_recycle=3600,
    echo=settings.DEBUG,
)

# Session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=sync_engine,
)

# Base class for models
Base = declarative_base()

# Metadata for table creation
metadata = MetaData()


# Database event listeners for connection optimization
@event.listens_for(sync_engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Set database connection parameters for optimal performance."""
    if "postgresql" in settings.DATABASE_URL:
        cursor = dbapi_connection.cursor()
        # Set optimal PostgreSQL parameters
        cursor.execute("SET timezone TO 'UTC'")
        cursor.execute("SET statement_timeout = '300s'")
        cursor.execute("SET lock_timeout = '30s'")
        cursor.close()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency function to get database session.

    Yields:
        AsyncSession: Database session for dependency injection

    Example:
        ```python
        @app.get("/users")
        async def get_users(db: AsyncSession = Depends(get_db)):
            # Use db session here
            pass
        ```
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception as e:
            await session.rollback()
            logger.error(f"Database session error: {str(e)}")
            raise
        finally:
            await session.close()


async def create_tables():
    """
    Create all database tables asynchronously.

    This function imports all models to ensure they are registered
    with the Base metadata before creating tables.
    """
    try:
        # Import all models to register them
        from .models import (
            audit_log,
            base,
            email,
            notification,
            quarantine,
            simulation,
            user,
        )

        logger.info("📊 Creating database tables...")

        async with engine.begin() as conn:
            # Create tables
            await conn.run_sync(Base.metadata.create_all)

        logger.info("✅ Database tables created successfully")

    except Exception as e:
        logger.error(f"❌ Failed to create database tables: {str(e)}")
        raise


async def drop_tables():
    """
    Drop all database tables asynchronously.

    Warning: This will delete all data! Only use in development.
    """
    try:
        logger.warning("⚠️ Dropping all database tables...")

        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

        logger.info("🗑️ Database tables dropped successfully")

    except Exception as e:
        logger.error(f"❌ Failed to drop database tables: {str(e)}")
        raise


async def check_database_connection() -> bool:
    """
    Check if database connection is healthy.

    Returns:
        bool: True if connection is healthy, False otherwise
    """
    try:
        async with AsyncSessionLocal() as session:
            await session.execute("SELECT 1")
            return True
    except Exception as e:
        logger.error(f"Database connection check failed: {str(e)}")
        return False


class DatabaseHealthCheck:
    """Database health monitoring utilities."""

    @staticmethod
    async def get_connection_stats() -> dict:
        """
        Get database connection pool statistics.

        Returns:
            dict: Connection pool statistics
        """
        try:
            pool = engine.pool
            return {
                "pool_size": pool.size(),
                "checked_in": pool.checkedin(),
                "checked_out": pool.checkedout(),
                "overflow": pool.overflow(),
                "invalid": pool.invalid(),
            }
        except Exception as e:
            logger.error(f"Failed to get connection stats: {str(e)}")
            return {}

    @staticmethod
    async def test_query_performance() -> dict:
        """
        Test database query performance.

        Returns:
            dict: Performance metrics
        """
        import time

        try:
            start_time = time.time()

            async with AsyncSessionLocal() as session:
                await session.execute("SELECT version()")

            end_time = time.time()
            query_time = round((end_time - start_time) * 1000, 2)  # Convert to ms

            return {
                "query_time_ms": query_time,
                "status": "healthy" if query_time < 100 else "slow",
            }
        except Exception as e:
            logger.error(f"Database performance test failed: {str(e)}")
            return {
                "query_time_ms": -1,
                "status": "error",
                "error": str(e),
            }


# Initialize database connection on module import
async def init_database():
    """Initialize database connection and verify connectivity."""
    try:
        logger.info("🔄 Initializing database connection...")

        # Test connection
        is_connected = await check_database_connection()
        if not is_connected:
            raise Exception("Failed to establish database connection")

        logger.info("✅ Database connection established")

    except Exception as e:
        logger.error(f"❌ Database initialization failed: {str(e)}")
        raise


# Context manager for database transactions
class DatabaseTransaction:
    """Context manager for database transactions with automatic rollback."""

    def __init__(self):
        self.session = None

    async def __aenter__(self) -> AsyncSession:
        self.session = AsyncSessionLocal()
        return self.session

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            await self.session.rollback()
            logger.error(f"Transaction rolled back due to error: {exc_val}")
        else:
            await self.session.commit()

        await self.session.close()

        # Return False to propagate any exception
        return False


# Database utilities
class DatabaseUtils:
    """Database utility functions for common operations."""

    @staticmethod
    async def execute_raw_query(query: str, params: dict = None) -> list:
        """
        Execute raw SQL query safely.

        Args:
            query: SQL query string
            params: Query parameters

        Returns:
            list: Query results
        """
        try:
            async with AsyncSessionLocal() as session:
                result = await session.execute(query, params or {})
                return result.fetchall()
        except Exception as e:
            logger.error(f"Raw query execution failed: {str(e)}")
            raise

    @staticmethod
    async def get_table_stats() -> dict:
        """
        Get statistics for all tables.

        Returns:
            dict: Table statistics
        """
        try:
            stats = {}

            async with AsyncSessionLocal() as session:
                # Get table row counts
                tables = [
                    "users",
                    "emails",
                    "quarantine_items",
                    "notifications",
                    "audit_logs",
                ]

                for table in tables:
                    try:
                        result = await session.execute(f"SELECT COUNT(*) FROM {table}")
                        count = result.scalar()
                        stats[table] = {"row_count": count}
                    except Exception as table_error:
                        stats[table] = {"error": str(table_error)}

            return stats

        except Exception as e:
            logger.error(f"Failed to get table stats: {str(e)}")
            return {}


# Export commonly used objects
__all__ = [
    "engine",
    "sync_engine",
    "AsyncSessionLocal",
    "SessionLocal",
    "Base",
    "metadata",
    "get_db",
    "create_tables",
    "drop_tables",
    "check_database_connection",
    "DatabaseHealthCheck",
    "DatabaseTransaction",
    "DatabaseUtils",
    "init_database",
]

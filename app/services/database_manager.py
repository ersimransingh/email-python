import asyncio
from typing import Optional, Dict, Any
from contextlib import asynccontextmanager
from datetime import datetime
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.exc import SQLAlchemyError

try:
    import pyodbc
    HAS_PYODBC = True
except ImportError:
    HAS_PYODBC = False

from app.core.config import DatabaseConfig
from app.core.security import SecurityManager
from app.models.database import Base


class DatabaseManager:
    def __init__(self):
        self.engine = None
        self.async_engine = None
        self.session_factory = None
        self.config: Optional[DatabaseConfig] = None
        self.security_manager = SecurityManager()

    async def load_config(self) -> Optional[DatabaseConfig]:
        """Load database configuration from encrypted file"""
        config_data = self.security_manager.load_encrypted_config("database")
        if config_data:
            self.config = DatabaseConfig(**config_data)
            return self.config
        return None

    def _build_connection_string(self, config: DatabaseConfig, async_driver: bool = False) -> str:
        """Build SQL Server connection string"""
        if not HAS_PYODBC:
            # Fallback to SQLite for testing (sync only)
            return "sqlite:///email_service.db"

        # Try different ODBC drivers in order of preference
        drivers = [
            "ODBC Driver 17 for SQL Server",  # This one is available on this system
            "ODBC Driver 18 for SQL Server",
            "SQL Server Native Client 11.0",
            "SQL Server"
        ]

        # Use the first available driver (we know 17 is available)
        driver = drivers[0]

        # URL encode password if it contains special characters
        from urllib.parse import quote_plus
        encoded_password = quote_plus(config.password)

        # Enhanced connection string with timeout settings
        connection_params = [
            f"driver={driver}",
            "TrustServerCertificate=yes",
            "Connection Timeout=60",
            "Command Timeout=60",
            "MARS_Connection=yes",
            "Encrypt=no"
        ]

        connection_string = f"mssql+pyodbc://{config.user}:{encoded_password}@{config.server}:{config.port}/{config.database}?" + "&".join(connection_params)

        return connection_string

    async def initialize_connection(self, config: DatabaseConfig):
        """Initialize database connection with provided config"""
        try:
            connection_string = self._build_connection_string(config)

            # Create sync engine (SQL Server works best with sync operations)
            self.engine = create_engine(
                connection_string,
                echo=False,
                pool_pre_ping=True,
                pool_recycle=3600,
                connect_args={
                    "timeout": 60,
                    "check_same_thread": False
                },
                pool_timeout=60,
                pool_reset_on_return='commit'
            )

            # Test the connection
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))

            # For async operations, we'll use the sync engine in thread pool
            # since SQL Server async support is limited with pyodbc
            self.async_engine = None
            self.session_factory = None

            self.config = config
            print(f"Database connection initialized successfully to {config.server}:{config.port}/{config.database}")

        except Exception as e:
            raise Exception(f"Failed to initialize database connection: {str(e)}")

    async def test_connection(self, config: DatabaseConfig) -> tuple[bool, str, Optional[int]]:
        """Test database connection with provided config"""
        start_time = datetime.now()
        try:
            connection_string = self._build_connection_string(config)
            print(f"Testing connection with: {connection_string[:50]}...") # Debug info

            test_engine = create_engine(
                connection_string,
                echo=False,
                connect_args={
                    "timeout": 60,
                    "check_same_thread": False
                },
                pool_timeout=60
            )

            with test_engine.connect() as conn:
                result = conn.execute(text("SELECT 1 as test_value"))
                row = result.fetchone()
                print(f"Connection test result: {row}")

            response_time = int((datetime.now() - start_time).total_seconds() * 1000)
            test_engine.dispose()

            return True, "Connection successful", response_time

        except Exception as e:
            response_time = int((datetime.now() - start_time).total_seconds() * 1000)
            error_msg = f"Connection failed: {str(e)}"
            print(f"Database connection error: {error_msg}")
            return False, error_msg, response_time

    @asynccontextmanager
    async def get_session(self):
        """Get database session (using sync engine in async context)"""
        if not self.engine:
            raise Exception("Database not initialized. Call initialize_connection first.")

        # Use sync session since we're using pyodbc
        from sqlalchemy.orm import sessionmaker
        Session = sessionmaker(bind=self.engine)
        session = Session()

        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    def get_sync_session(self):
        """Get synchronous database session"""
        if not self.engine:
            raise Exception("Database not initialized. Call initialize_connection first.")

        from sqlalchemy.orm import sessionmaker
        Session = sessionmaker(bind=self.engine)
        return Session()

    async def create_tables(self):
        """Create database tables"""
        if not self.engine:
            raise Exception("Database not initialized")

        # Use sync engine to create tables
        Base.metadata.create_all(self.engine)

    async def check_database_status(self) -> Dict[str, Any]:
        """Check current database connection status"""
        if not self.config:
            return {
                "connected": False,
                "server": None,
                "database": None,
                "last_checked": datetime.now().isoformat(),
                "response_time": None,
                "error": "No database configuration"
            }

        success, message, response_time = await self.test_connection(self.config)

        return {
            "connected": success,
            "server": self.config.server,
            "database": self.config.database,
            "last_checked": datetime.now().isoformat(),
            "response_time": response_time,
            "message": message
        }

    def save_config(self, config: DatabaseConfig):
        """Save database configuration"""
        config_data = config.model_dump()
        self.security_manager.save_encrypted_config(config_data, "database")

    def config_exists(self) -> bool:
        """Check if database configuration exists"""
        return self.security_manager.config_exists("database")

    async def close_connection(self):
        """Close database connections"""
        if self.engine:
            self.engine.dispose()
            self.engine = None
        self.config = None

    async def execute_query(self, query: str, params: Optional[Dict] = None):
        """Execute raw SQL query"""
        async with self.get_session() as session:
            result = session.execute(text(query), params or {})
            return result.fetchall()

    async def get_table_info(self, table_name: str) -> Dict[str, Any]:
        """Get information about a specific table"""
        query = """
        SELECT
            COLUMN_NAME,
            DATA_TYPE,
            IS_NULLABLE,
            COLUMN_DEFAULT
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_NAME = :table_name
        """

        try:
            result = await self.execute_query(query, {"table_name": table_name})
            return {
                "table_name": table_name,
                "columns": [dict(row._mapping) for row in result]
            }
        except Exception as e:
            return {"error": str(e)}


# Global database manager instance
db_manager = DatabaseManager()
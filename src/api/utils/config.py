"""
PhishGuard Configuration Management

This module handles application configuration using environment variables
with validation and type checking for enterprise deployment.
"""

from pathlib import Path
from typing import List, Optional

try:
    from pydantic import BaseSettings, Field, validator
    from pydantic_settings import BaseSettings
except ImportError:
    # Fallback for older versions
    class BaseSettings:
        def __init__(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)


class Settings(BaseSettings):
    """
    PhishGuard application settings with validation and environment variable support.

    All settings can be overridden via environment variables with the same name.
    """

    # Application Settings
    APP_NAME: str = Field(default="PhishGuard", description="Application name")
    APP_VERSION: str = Field(default="1.0.0", description="Application version")
    ENVIRONMENT: str = Field(
        default="production", description="Environment (development/staging/production)"
    )
    DEBUG: bool = Field(default=False, description="Debug mode")
    API_PREFIX: str = Field(default="/api/v1", description="API route prefix")

    # Security Configuration
    SECRET_KEY: str = Field(
        default="change-this-secret-key-in-production",
        description="Application secret key",
    )
    JWT_SECRET_KEY: str = Field(
        default="change-this-jwt-secret-in-production", description="JWT secret key"
    )
    JWT_ALGORITHM: str = Field(default="HS256", description="JWT algorithm")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(
        default=30, description="Access token expiration in minutes"
    )
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(
        default=30, description="Refresh token expiration in days"
    )

    # CORS Settings
    ALLOWED_ORIGINS: List[str] = Field(
        default=["http://localhost:3000", "https://localhost:3000"],
        description="Allowed CORS origins",
    )
    ALLOWED_METHODS: List[str] = Field(
        default=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        description="Allowed HTTP methods",
    )
    ALLOWED_HEADERS: List[str] = Field(default=["*"], description="Allowed headers")

    # Database Configuration
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://phishguard:password@localhost:5432/phishguard_db",
        description="Database connection URL",
    )
    DATABASE_POOL_SIZE: int = Field(
        default=20, description="Database connection pool size"
    )
    DATABASE_MAX_OVERFLOW: int = Field(
        default=30, description="Database max overflow connections"
    )

    # Redis Configuration
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0", description="Redis connection URL"
    )
    REDIS_PASSWORD: Optional[str] = Field(default=None, description="Redis password")
    REDIS_SSL: bool = Field(default=False, description="Use SSL for Redis")

    # Celery Configuration
    CELERY_BROKER_URL: str = Field(
        default="redis://localhost:6379/1", description="Celery broker URL"
    )
    CELERY_RESULT_BACKEND: str = Field(
        default="redis://localhost:6379/2", description="Celery result backend URL"
    )
    CELERY_TASK_SERIALIZER: str = Field(
        default="json", description="Celery task serializer"
    )
    CELERY_RESULT_SERIALIZER: str = Field(
        default="json", description="Celery result serializer"
    )
    CELERY_ACCEPT_CONTENT: List[str] = Field(
        default=["json"], description="Celery accepted content types"
    )
    CELERY_TIMEZONE: str = Field(default="UTC", description="Celery timezone")

    # Email Configuration
    SMTP_HOST: str = Field(default="smtp.gmail.com", description="SMTP server host")
    SMTP_PORT: int = Field(default=587, description="SMTP server port")
    SMTP_USERNAME: Optional[str] = Field(default=None, description="SMTP username")
    SMTP_PASSWORD: Optional[str] = Field(default=None, description="SMTP password")
    SMTP_TLS: bool = Field(default=True, description="Use TLS for SMTP")
    SMTP_SSL: bool = Field(default=False, description="Use SSL for SMTP")

    # Gmail API Configuration
    GMAIL_CREDENTIALS_FILE: Optional[str] = Field(
        default=None, description="Gmail API credentials file path"
    )
    GMAIL_TOKEN_FILE: Optional[str] = Field(
        default=None, description="Gmail API token file path"
    )
    GMAIL_SCOPES: List[str] = Field(
        default=["https://www.googleapis.com/auth/gmail.readonly"],
        description="Gmail API scopes",
    )

    # Microsoft 365 Configuration
    AZURE_CLIENT_ID: Optional[str] = Field(
        default=None, description="Azure AD client ID"
    )
    AZURE_CLIENT_SECRET: Optional[str] = Field(
        default=None, description="Azure AD client secret"
    )
    AZURE_TENANT_ID: Optional[str] = Field(
        default=None, description="Azure AD tenant ID"
    )
    MICROSOFT_GRAPH_SCOPES: List[str] = Field(
        default=["https://graph.microsoft.com/Mail.Read"],
        description="Microsoft Graph API scopes",
    )

    # Slack Integration
    SLACK_WEBHOOK_URL: Optional[str] = Field(
        default=None, description="Slack webhook URL"
    )
    SLACK_BOT_TOKEN: Optional[str] = Field(default=None, description="Slack bot token")
    SLACK_CHANNEL: str = Field(
        default="#security-alerts", description="Default Slack channel"
    )

    # AI/ML Configuration
    ML_MODEL_PATH: str = Field(
        default="src/ai_engine/models/phishing_classifier.pkl",
        description="Path to ML model file",
    )
    FEATURE_EXTRACTION_CONFIG: str = Field(
        default="src/ai_engine/config/features.json",
        description="Feature extraction configuration file",
    )
    ML_CONFIDENCE_THRESHOLD: float = Field(
        default=0.75, description="ML confidence threshold"
    )
    ML_BATCH_SIZE: int = Field(default=32, description="ML batch processing size")
    ML_MAX_EMAIL_LENGTH: int = Field(
        default=10000, description="Maximum email length for processing"
    )

    # File Storage
    QUARANTINE_STORAGE_PATH: str = Field(
        default="src/quarantine_storage", description="Quarantine storage directory"
    )
    ATTACHMENT_STORAGE_PATH: str = Field(
        default="src/quarantine_storage/attachments",
        description="Attachment storage directory",
    )
    LOG_STORAGE_PATH: str = Field(
        default="src/quarantine_storage/logs", description="Log storage directory"
    )
    MAX_ATTACHMENT_SIZE_MB: int = Field(
        default=25, description="Maximum attachment size in MB"
    )

    # Monitoring and Observability
    PROMETHEUS_METRICS_PORT: int = Field(
        default=8001, description="Prometheus metrics server port"
    )
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")
    LOG_FORMAT: str = Field(default="json", description="Log format (json/text)")
    METRICS_ENABLED: bool = Field(default=True, description="Enable metrics collection")
    TRACING_ENABLED: bool = Field(
        default=True, description="Enable distributed tracing"
    )

    # Rate Limiting
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = Field(
        default=60, description="Rate limit requests per minute"
    )
    RATE_LIMIT_BURST_SIZE: int = Field(default=10, description="Rate limit burst size")

    # SIEM Integration
    SIEM_ENDPOINT: Optional[str] = Field(default=None, description="SIEM endpoint URL")
    SIEM_API_KEY: Optional[str] = Field(default=None, description="SIEM API key")
    SIEM_FORMAT: str = Field(default="cef", description="SIEM log format")

    # SOAR Integration
    SOAR_ENDPOINT: Optional[str] = Field(default=None, description="SOAR endpoint URL")
    SOAR_API_KEY: Optional[str] = Field(default=None, description="SOAR API key")
    SOAR_PLAYBOOK_ID: Optional[str] = Field(
        default=None, description="SOAR playbook ID"
    )

    # Compliance and Audit
    AUDIT_LOG_ENABLED: bool = Field(default=True, description="Enable audit logging")
    AUDIT_LOG_RETENTION_DAYS: int = Field(
        default=365, description="Audit log retention in days"
    )
    COMPLIANCE_REPORTING_ENABLED: bool = Field(
        default=True, description="Enable compliance reporting"
    )

    # Performance Tuning
    MAX_WORKERS: int = Field(default=4, description="Maximum worker processes")
    WORKER_TIMEOUT: int = Field(default=30, description="Worker timeout in seconds")
    KEEPALIVE_TIMEOUT: int = Field(
        default=5, description="Keep-alive timeout in seconds"
    )
    MAX_REQUESTS: int = Field(default=1000, description="Maximum requests per worker")
    MAX_REQUESTS_JITTER: int = Field(default=50, description="Max requests jitter")

    # Development Settings
    DEV_RELOAD: bool = Field(
        default=False, description="Enable auto-reload in development"
    )
    DEV_MOCK_AI: bool = Field(
        default=False, description="Mock AI responses in development"
    )
    DEV_MOCK_INTEGRATIONS: bool = Field(
        default=False, description="Mock integrations in development"
    )

    # Health Check Configuration
    HEALTH_CHECK_INTERVAL_SECONDS: int = Field(
        default=60, description="Health check interval"
    )
    HEALTH_CHECK_TIMEOUT_SECONDS: int = Field(
        default=10, description="Health check timeout"
    )

    # Backup and Recovery
    BACKUP_ENABLED: bool = Field(default=True, description="Enable automated backups")
    BACKUP_SCHEDULE: str = Field(
        default="0 2 * * *", description="Backup schedule (cron format)"
    )
    BACKUP_RETENTION_DAYS: int = Field(
        default=30, description="Backup retention in days"
    )

    # Feature Flags
    FEATURE_ADVANCED_ANALYTICS: bool = Field(
        default=True, description="Enable advanced analytics"
    )
    FEATURE_REAL_TIME_SCANNING: bool = Field(
        default=True, description="Enable real-time scanning"
    )
    FEATURE_AUTOMATED_RESPONSE: bool = Field(
        default=True, description="Enable automated response"
    )
    FEATURE_THREAT_INTELLIGENCE: bool = Field(
        default=True, description="Enable threat intelligence"
    )

    class Config:
        """Pydantic configuration."""

        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True

    @validator("ENVIRONMENT")
    def validate_environment(cls, v):
        """Validate environment setting."""
        valid_environments = ["development", "staging", "production"]
        if v not in valid_environments:
            raise ValueError(f"Environment must be one of {valid_environments}")
        return v

    @validator("LOG_LEVEL")
    def validate_log_level(cls, v):
        """Validate log level setting."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of {valid_levels}")
        return v.upper()

    @validator("ML_CONFIDENCE_THRESHOLD")
    def validate_confidence_threshold(cls, v):
        """Validate ML confidence threshold."""
        if not 0 <= v <= 1:
            raise ValueError("ML confidence threshold must be between 0 and 1")
        return v

    @validator("DATABASE_URL")
    def validate_database_url(cls, v):
        """Validate database URL format."""
        if not v.startswith(("postgresql://", "postgresql+asyncpg://", "sqlite://")):
            raise ValueError("Database URL must start with postgresql:// or sqlite://")
        return v

    @validator("REDIS_URL")
    def validate_redis_url(cls, v):
        """Validate Redis URL format."""
        if not v.startswith("redis://"):
            raise ValueError("Redis URL must start with redis://")
        return v

    def get_database_url_sync(self) -> str:
        """Get synchronous database URL for migrations."""
        return self.DATABASE_URL.replace("+asyncpg", "")

    def create_directories(self) -> None:
        """Create necessary directories for the application."""
        directories = [
            self.QUARANTINE_STORAGE_PATH,
            self.ATTACHMENT_STORAGE_PATH,
            self.LOG_STORAGE_PATH,
            Path(self.ML_MODEL_PATH).parent,
        ]

        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)

    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.ENVIRONMENT == "development"

    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.ENVIRONMENT == "production"

    def get_cors_origins(self) -> List[str]:
        """Get CORS origins as a list."""
        if isinstance(self.ALLOWED_ORIGINS, str):
            return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",")]
        return self.ALLOWED_ORIGINS


# Create settings instance
try:
    settings = Settings()
    # Create necessary directories
    settings.create_directories()
except Exception as e:
    # Fallback settings for import-time errors
    print(f"Warning: Failed to load settings from environment: {e}")
    settings = Settings(
        APP_NAME="PhishGuard",
        ENVIRONMENT="development",
        DEBUG=True,
    )


# Configuration validation
def validate_configuration() -> List[str]:
    """
    Validate the current configuration and return any issues.

    Returns:
        List[str]: List of configuration issues
    """
    issues = []

    # Check critical settings
    if (
        settings.SECRET_KEY == "change-this-secret-key-in-production"
        and settings.is_production()
    ):
        issues.append("SECRET_KEY must be changed in production")

    if (
        settings.JWT_SECRET_KEY == "change-this-jwt-secret-in-production"
        and settings.is_production()
    ):
        issues.append("JWT_SECRET_KEY must be changed in production")

    # Check database configuration
    try:
        from sqlalchemy import create_engine

        engine = create_engine(settings.get_database_url_sync())
        engine.connect()
    except Exception as e:
        issues.append(f"Database connection failed: {e}")

    # Check Redis configuration
    try:
        import redis

        r = redis.from_url(settings.REDIS_URL)
        r.ping()
    except Exception as e:
        issues.append(f"Redis connection failed: {e}")

    # Check required directories
    required_dirs = [
        settings.QUARANTINE_STORAGE_PATH,
        settings.ATTACHMENT_STORAGE_PATH,
        settings.LOG_STORAGE_PATH,
    ]

    for directory in required_dirs:
        if not Path(directory).exists():
            issues.append(f"Required directory does not exist: {directory}")

    return issues


# Export commonly used objects
__all__ = [
    "settings",
    "Settings",
    "validate_configuration",
]

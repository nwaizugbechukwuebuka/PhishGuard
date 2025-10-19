"""
PhishGuard Logging Configuration

This module provides comprehensive logging capabilities with structured logging,
performance monitoring, and enterprise-grade audit trail functionality.
"""

import logging
import sys
import json
import traceback
from datetime import datetime
from typing import Any, Dict, Optional
from pathlib import Path
import threading
from contextvars import ContextVar

try:
    from loguru import logger as loguru_logger
    LOGURU_AVAILABLE = True
except ImportError:
    LOGURU_AVAILABLE = False

try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False

from .config import settings


# Context variables for request tracking
request_id_context: ContextVar[str] = ContextVar('request_id', default='')
user_id_context: ContextVar[str] = ContextVar('user_id', default='')


class PhishGuardLogger:
    """
    Enterprise-grade logger with structured logging, audit trails, and performance monitoring.
    
    Features:
    - Structured JSON logging
    - Request correlation IDs
    - Performance metrics
    - Security audit logging
    - Multi-level log filtering
    - Log aggregation support
    """
    
    def __init__(self):
        """Initialize the PhishGuard logger."""
        self.logger = self._setup_logger()
        self._setup_audit_logger()
        
        # Performance tracking
        self._request_times = {}
        self._lock = threading.Lock()
    
    def _setup_logger(self) -> logging.Logger:
        """Set up the main application logger."""
        logger = logging.getLogger("phishguard")
        logger.setLevel(getattr(logging, settings.LOG_LEVEL))
        
        # Remove existing handlers
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        
        # Create formatter based on configuration
        if settings.LOG_FORMAT == "json":
            formatter = self._get_json_formatter()
        else:
            formatter = self._get_text_formatter()
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # File handler for persistent logging
        if settings.LOG_STORAGE_PATH:
            log_file = Path(settings.LOG_STORAGE_PATH) / "phishguard.log"
            log_file.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=10 * 1024 * 1024,  # 10MB
                backupCount=5
            )
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        
        # Error handler for critical logs
        error_file = Path(settings.LOG_STORAGE_PATH) / "errors.log"
        error_handler = logging.handlers.RotatingFileHandler(
            error_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=10
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(formatter)
        logger.addHandler(error_handler)
        
        return logger
    
    def _setup_audit_logger(self):
        """Set up audit logging for security events."""
        if not settings.AUDIT_LOG_ENABLED:
            self.audit_logger = None
            return
        
        self.audit_logger = logging.getLogger("phishguard.audit")
        self.audit_logger.setLevel(logging.INFO)
        
        # Audit log file
        audit_file = Path(settings.LOG_STORAGE_PATH) / "audit.log"
        audit_handler = logging.handlers.RotatingFileHandler(
            audit_file,
            maxBytes=50 * 1024 * 1024,  # 50MB
            backupCount=20
        )
        
        audit_formatter = logging.Formatter(
            '%(asctime)s - AUDIT - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        audit_handler.setFormatter(audit_formatter)
        
        self.audit_logger.addHandler(audit_handler)
    
    def _get_json_formatter(self) -> logging.Formatter:
        """Get JSON formatter for structured logging."""
        class JSONFormatter(logging.Formatter):
            def format(self, record):
                log_entry = {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "level": record.levelname,
                    "logger": record.name,
                    "message": record.getMessage(),
                    "module": record.module,
                    "function": record.funcName,
                    "line": record.lineno,
                    "request_id": request_id_context.get(),
                    "user_id": user_id_context.get(),
                    "environment": settings.ENVIRONMENT,
                    "service": settings.APP_NAME,
                    "version": settings.APP_VERSION,
                }
                
                # Add exception info if present
                if record.exc_info:
                    log_entry["exception"] = {
                        "type": record.exc_info[0].__name__,
                        "message": str(record.exc_info[1]),
                        "traceback": traceback.format_exception(*record.exc_info),
                    }
                
                # Add extra fields
                if hasattr(record, 'extra_fields'):
                    log_entry.update(record.extra_fields)
                
                return json.dumps(log_entry)
        
        return JSONFormatter()
    
    def _get_text_formatter(self) -> logging.Formatter:
        """Get text formatter for human-readable logs."""
        return logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    def debug(self, message: str, **kwargs):
        """Log debug message with context."""
        self._log(logging.DEBUG, message, **kwargs)
    
    def info(self, message: str, **kwargs):
        """Log info message with context."""
        self._log(logging.INFO, message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message with context."""
        self._log(logging.WARNING, message, **kwargs)
    
    def error(self, message: str, exc_info: bool = False, **kwargs):
        """Log error message with optional exception info."""
        self._log(logging.ERROR, message, exc_info=exc_info, **kwargs)
    
    def critical(self, message: str, exc_info: bool = True, **kwargs):
        """Log critical message with exception info."""
        self._log(logging.CRITICAL, message, exc_info=exc_info, **kwargs)
    
    def _log(self, level: int, message: str, exc_info: bool = False, **kwargs):
        """Internal logging method with context enrichment."""
        if kwargs:
            # Create a log record with extra fields
            record = self.logger.makeRecord(
                self.logger.name, level, "", 0, message, (), exc_info
            )
            record.extra_fields = kwargs
            self.logger.handle(record)
        else:
            self.logger.log(level, message, exc_info=exc_info)
    
    def audit(self, event: str, details: Dict[str, Any], user_id: str = None):
        """Log security audit event."""
        if not self.audit_logger:
            return
        
        audit_entry = {
            "event": event,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "user_id": user_id or user_id_context.get(),
            "request_id": request_id_context.get(),
            "details": details,
            "source_ip": details.get("source_ip"),
            "user_agent": details.get("user_agent"),
        }
        
        self.audit_logger.info(json.dumps(audit_entry))
    
    def performance(self, operation: str, duration_ms: float, **kwargs):
        """Log performance metrics."""
        perf_data = {
            "operation": operation,
            "duration_ms": duration_ms,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            **kwargs
        }
        
        self.info(f"Performance: {operation}", **perf_data)
    
    def start_request_timer(self, request_id: str):
        """Start timing a request."""
        with self._lock:
            self._request_times[request_id] = datetime.utcnow()
    
    def end_request_timer(self, request_id: str, operation: str = "request"):
        """End timing a request and log performance."""
        with self._lock:
            start_time = self._request_times.pop(request_id, None)
        
        if start_time:
            duration = (datetime.utcnow() - start_time).total_seconds() * 1000
            self.performance(operation, duration, request_id=request_id)
    
    def get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        return datetime.utcnow().isoformat() + "Z"
    
    def set_request_context(self, request_id: str, user_id: str = None):
        """Set request context for correlation."""
        request_id_context.set(request_id)
        if user_id:
            user_id_context.set(user_id)
    
    def clear_request_context(self):
        """Clear request context."""
        request_id_context.set('')
        user_id_context.set('')


# Security audit event types
class AuditEvents:
    """Predefined audit event types for consistency."""
    
    # Authentication events
    LOGIN_SUCCESS = "auth.login.success"
    LOGIN_FAILURE = "auth.login.failure"
    LOGOUT = "auth.logout"
    TOKEN_REFRESH = "auth.token.refresh"
    PASSWORD_CHANGE = "auth.password.change"
    
    # Email processing events
    EMAIL_SCANNED = "email.scanned"
    EMAIL_QUARANTINED = "email.quarantined"
    EMAIL_RELEASED = "email.released"
    EMAIL_DELETED = "email.deleted"
    
    # System events
    SYSTEM_STARTUP = "system.startup"
    SYSTEM_SHUTDOWN = "system.shutdown"
    CONFIG_CHANGE = "system.config.change"
    MODEL_UPDATE = "system.model.update"
    
    # Security events
    SUSPICIOUS_ACTIVITY = "security.suspicious_activity"
    ACCESS_DENIED = "security.access_denied"
    RATE_LIMIT_EXCEEDED = "security.rate_limit_exceeded"
    
    # Admin events
    USER_CREATED = "admin.user.created"
    USER_DELETED = "admin.user.deleted"
    PERMISSION_GRANTED = "admin.permission.granted"
    PERMISSION_REVOKED = "admin.permission.revoked"


# Performance monitoring decorators
def log_performance(operation_name: str = None):
    """Decorator to log function performance."""
    def decorator(func):
        import functools
        import time
        
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                return result
            finally:
                duration = (time.time() - start_time) * 1000
                op_name = operation_name or f"{func.__module__}.{func.__name__}"
                logger.performance(op_name, duration)
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                duration = (time.time() - start_time) * 1000
                op_name = operation_name or f"{func.__module__}.{func.__name__}"
                logger.performance(op_name, duration)
        
        # Return appropriate wrapper based on function type
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def log_audit(event_type: str, include_args: bool = False):
    """Decorator to log audit events."""
    def decorator(func):
        import functools
        
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            details = {"function": func.__name__}
            if include_args:
                details["args"] = str(args)
                details["kwargs"] = str(kwargs)
            
            try:
                result = await func(*args, **kwargs)
                details["status"] = "success"
                return result
            except Exception as e:
                details["status"] = "error"
                details["error"] = str(e)
                raise
            finally:
                logger.audit(event_type, details)
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            details = {"function": func.__name__}
            if include_args:
                details["args"] = str(args)
                details["kwargs"] = str(kwargs)
            
            try:
                result = func(*args, **kwargs)
                details["status"] = "success"
                return result
            except Exception as e:
                details["status"] = "error"
                details["error"] = str(e)
                raise
            finally:
                logger.audit(event_type, details)
        
        # Return appropriate wrapper
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


# Setup logging configuration
def setup_logging():
    """Initialize logging configuration for the application."""
    global logger
    
    # Configure based on available libraries
    if LOGURU_AVAILABLE and settings.LOG_FORMAT == "json":
        # Use loguru for better performance if available
        loguru_logger.remove()  # Remove default handler
        
        # Add custom handler
        loguru_logger.add(
            sys.stdout,
            format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level} | {name}:{function}:{line} | {message}",
            level=settings.LOG_LEVEL,
            serialize=True if settings.LOG_FORMAT == "json" else False
        )
        
        # File handler
        if settings.LOG_STORAGE_PATH:
            log_file = Path(settings.LOG_STORAGE_PATH) / "phishguard.log"
            loguru_logger.add(
                log_file,
                rotation="10 MB",
                retention="30 days",
                level=settings.LOG_LEVEL,
                serialize=True if settings.LOG_FORMAT == "json" else False
            )
        
        logger = PhishGuardLogger()
    else:
        # Use standard logging
        logger = PhishGuardLogger()


# Create global logger instance
logger = PhishGuardLogger()


# Export commonly used objects
__all__ = [
    "logger",
    "PhishGuardLogger",
    "AuditEvents",
    "log_performance",
    "log_audit",
    "setup_logging",
    "request_id_context",
    "user_id_context",
]

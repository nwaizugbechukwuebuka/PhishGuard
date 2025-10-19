"""
Prometheus Metrics Collection for PhishGuard
Comprehensive monitoring and observability metrics
"""

import time
import os
from typing import Dict, Any, Optional, List
from datetime import datetime
from functools import wraps
import asyncio

from prometheus_client import (
    Counter, Histogram, Gauge, Summary, Info,
    CollectorRegistry, multiprocess, generate_latest,
    CONTENT_TYPE_LATEST, start_http_server
)
from prometheus_client.exposition import MetricsHandler
from fastapi import Request, Response
from fastapi.responses import PlainTextResponse

from src.api.utils.logger import get_logger

logger = get_logger(__name__)

# Create custom registry for PhishGuard metrics
REGISTRY = CollectorRegistry()

# Application Information
APP_INFO = Info(
    'phishguard_app_info',
    'PhishGuard application information',
    registry=REGISTRY
)

# Set application info
APP_INFO.info({
    'version': os.getenv('APP_VERSION', '1.0.0'),
    'environment': os.getenv('ENVIRONMENT', 'production'),
    'build_date': os.getenv('BUILD_DATE', datetime.now().isoformat()),
    'git_commit': os.getenv('GIT_COMMIT', 'unknown')
})

# Request Metrics
HTTP_REQUESTS_TOTAL = Counter(
    'phishguard_http_requests_total',
    'Total number of HTTP requests',
    ['method', 'endpoint', 'status_code'],
    registry=REGISTRY
)

HTTP_REQUEST_DURATION = Histogram(
    'phishguard_http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint'],
    buckets=(0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0),
    registry=REGISTRY
)

HTTP_REQUEST_SIZE = Histogram(
    'phishguard_http_request_size_bytes',
    'HTTP request size in bytes',
    ['method', 'endpoint'],
    buckets=(100, 1000, 10000, 100000, 1000000, 10000000),
    registry=REGISTRY
)

HTTP_RESPONSE_SIZE = Histogram(
    'phishguard_http_response_size_bytes',
    'HTTP response size in bytes',
    ['method', 'endpoint'],
    buckets=(100, 1000, 10000, 100000, 1000000, 10000000),
    registry=REGISTRY
)

# Email Processing Metrics
EMAILS_PROCESSED_TOTAL = Counter(
    'phishguard_emails_processed_total',
    'Total number of emails processed',
    ['platform', 'status'],
    registry=REGISTRY
)

EMAILS_DETECTED_PHISHING = Counter(
    'phishguard_emails_detected_phishing_total',
    'Total number of phishing emails detected',
    ['platform', 'threat_level'],
    registry=REGISTRY
)

EMAILS_QUARANTINED_TOTAL = Counter(
    'phishguard_emails_quarantined_total',
    'Total number of emails quarantined',
    ['platform', 'reason'],
    registry=REGISTRY
)

EMAIL_PROCESSING_DURATION = Histogram(
    'phishguard_email_processing_duration_seconds',
    'Email processing duration in seconds',
    ['platform', 'processing_stage'],
    buckets=(0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0),
    registry=REGISTRY
)

EMAIL_RISK_SCORE = Histogram(
    'phishguard_email_risk_score',
    'Distribution of email risk scores',
    ['platform'],
    buckets=(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0),
    registry=REGISTRY
)

# AI Model Metrics
MODEL_PREDICTIONS_TOTAL = Counter(
    'phishguard_model_predictions_total',
    'Total number of model predictions',
    ['model_type', 'prediction'],
    registry=REGISTRY
)

MODEL_PREDICTION_DURATION = Histogram(
    'phishguard_model_prediction_duration_seconds',
    'Model prediction duration in seconds',
    ['model_type'],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0),
    registry=REGISTRY
)

MODEL_CONFIDENCE_SCORE = Histogram(
    'phishguard_model_confidence_score',
    'Distribution of model confidence scores',
    ['model_type'],
    buckets=(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0),
    registry=REGISTRY
)

MODEL_ACCURACY = Gauge(
    'phishguard_model_accuracy',
    'Current model accuracy',
    ['model_type'],
    registry=REGISTRY
)

# System Metrics
ACTIVE_CONNECTIONS = Gauge(
    'phishguard_active_connections',
    'Number of active connections',
    registry=REGISTRY
)

DATABASE_CONNECTIONS_POOL = Gauge(
    'phishguard_database_connections_pool',
    'Database connection pool status',
    ['status'],
    registry=REGISTRY
)

REDIS_CONNECTIONS_POOL = Gauge(
    'phishguard_redis_connections_pool',
    'Redis connection pool status',
    ['status'],
    registry=REGISTRY
)

BACKGROUND_TASKS_ACTIVE = Gauge(
    'phishguard_background_tasks_active',
    'Number of active background tasks',
    ['task_type'],
    registry=REGISTRY
)

BACKGROUND_TASKS_COMPLETED = Counter(
    'phishguard_background_tasks_completed_total',
    'Total number of completed background tasks',
    ['task_type', 'status'],
    registry=REGISTRY
)

# Authentication Metrics
AUTH_ATTEMPTS_TOTAL = Counter(
    'phishguard_auth_attempts_total',
    'Total number of authentication attempts',
    ['method', 'status'],
    registry=REGISTRY
)

ACTIVE_SESSIONS = Gauge(
    'phishguard_active_sessions',
    'Number of active user sessions',
    registry=REGISTRY
)

TOKEN_OPERATIONS_TOTAL = Counter(
    'phishguard_token_operations_total',
    'Total number of token operations',
    ['operation', 'status'],
    registry=REGISTRY
)

# Integration Metrics
INTEGRATION_REQUESTS_TOTAL = Counter(
    'phishguard_integration_requests_total',
    'Total number of integration requests',
    ['integration', 'operation', 'status'],
    registry=REGISTRY
)

INTEGRATION_REQUEST_DURATION = Histogram(
    'phishguard_integration_request_duration_seconds',
    'Integration request duration in seconds',
    ['integration', 'operation'],
    buckets=(0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0),
    registry=REGISTRY
)

# Quarantine Metrics
QUARANTINE_ACTIONS_TOTAL = Counter(
    'phishguard_quarantine_actions_total',
    'Total number of quarantine actions',
    ['action', 'platform'],
    registry=REGISTRY
)

QUARANTINE_QUEUE_SIZE = Gauge(
    'phishguard_quarantine_queue_size',
    'Current quarantine queue size',
    registry=REGISTRY
)

# Alert and Notification Metrics
ALERTS_SENT_TOTAL = Counter(
    'phishguard_alerts_sent_total',
    'Total number of alerts sent',
    ['type', 'channel', 'status'],
    registry=REGISTRY
)

NOTIFICATIONS_SENT_TOTAL = Counter(
    'phishguard_notifications_sent_total',
    'Total number of notifications sent',
    ['type', 'status'],
    registry=REGISTRY
)

# Performance and Health Metrics
MEMORY_USAGE_BYTES = Gauge(
    'phishguard_memory_usage_bytes',
    'Memory usage in bytes',
    registry=REGISTRY
)

CPU_USAGE_PERCENT = Gauge(
    'phishguard_cpu_usage_percent',
    'CPU usage percentage',
    registry=REGISTRY
)

DISK_USAGE_BYTES = Gauge(
    'phishguard_disk_usage_bytes',
    'Disk usage in bytes',
    ['path'],
    registry=REGISTRY
)

HEALTH_CHECK_STATUS = Gauge(
    'phishguard_health_check_status',
    'Health check status (1 = healthy, 0 = unhealthy)',
    ['component'],
    registry=REGISTRY
)

class MetricsCollector:
    """Centralized metrics collection and management"""
    
    def __init__(self):
        self.start_time = time.time()
        self._metrics_enabled = os.getenv('METRICS_ENABLED', 'true').lower() == 'true'
        self._metrics_port = int(os.getenv('METRICS_PORT', '8090'))
        self._metrics_path = os.getenv('METRICS_PATH', '/metrics')
    
    def is_enabled(self) -> bool:
        """Check if metrics collection is enabled"""
        return self._metrics_enabled
    
    async def start_metrics_server(self):
        """Start Prometheus metrics HTTP server"""
        if not self._metrics_enabled:
            logger.info("Metrics collection is disabled")
            return
        
        try:
            start_http_server(self._metrics_port, registry=REGISTRY)
            logger.info(f"Metrics server started on port {self._metrics_port}")
        except Exception as e:
            logger.error(f"Failed to start metrics server: {e}")
    
    def record_http_request(
        self,
        method: str,
        endpoint: str,
        status_code: int,
        duration: float,
        request_size: int = 0,
        response_size: int = 0
    ):
        """Record HTTP request metrics"""
        if not self._metrics_enabled:
            return
        
        try:
            HTTP_REQUESTS_TOTAL.labels(
                method=method,
                endpoint=endpoint,
                status_code=status_code
            ).inc()
            
            HTTP_REQUEST_DURATION.labels(
                method=method,
                endpoint=endpoint
            ).observe(duration)
            
            if request_size > 0:
                HTTP_REQUEST_SIZE.labels(
                    method=method,
                    endpoint=endpoint
                ).observe(request_size)
            
            if response_size > 0:
                HTTP_RESPONSE_SIZE.labels(
                    method=method,
                    endpoint=endpoint
                ).observe(response_size)
        except Exception as e:
            logger.error(f"Error recording HTTP metrics: {e}")
    
    def record_email_processing(
        self,
        platform: str,
        status: str,
        duration: float,
        processing_stage: str = "total",
        is_phishing: bool = False,
        threat_level: str = None,
        risk_score: float = None
    ):
        """Record email processing metrics"""
        if not self._metrics_enabled:
            return
        
        try:
            EMAILS_PROCESSED_TOTAL.labels(
                platform=platform,
                status=status
            ).inc()
            
            EMAIL_PROCESSING_DURATION.labels(
                platform=platform,
                processing_stage=processing_stage
            ).observe(duration)
            
            if is_phishing and threat_level:
                EMAILS_DETECTED_PHISHING.labels(
                    platform=platform,
                    threat_level=threat_level
                ).inc()
            
            if risk_score is not None:
                EMAIL_RISK_SCORE.labels(platform=platform).observe(risk_score)
        except Exception as e:
            logger.error(f"Error recording email processing metrics: {e}")
    
    def record_model_prediction(
        self,
        model_type: str,
        prediction: str,
        duration: float,
        confidence: float = None
    ):
        """Record AI model prediction metrics"""
        if not self._metrics_enabled:
            return
        
        try:
            MODEL_PREDICTIONS_TOTAL.labels(
                model_type=model_type,
                prediction=prediction
            ).inc()
            
            MODEL_PREDICTION_DURATION.labels(
                model_type=model_type
            ).observe(duration)
            
            if confidence is not None:
                MODEL_CONFIDENCE_SCORE.labels(
                    model_type=model_type
                ).observe(confidence)
        except Exception as e:
            logger.error(f"Error recording model metrics: {e}")
    
    def record_auth_attempt(self, method: str, status: str):
        """Record authentication attempt"""
        if not self._metrics_enabled:
            return
        
        try:
            AUTH_ATTEMPTS_TOTAL.labels(
                method=method,
                status=status
            ).inc()
        except Exception as e:
            logger.error(f"Error recording auth metrics: {e}")
    
    def record_integration_request(
        self,
        integration: str,
        operation: str,
        status: str,
        duration: float
    ):
        """Record integration request metrics"""
        if not self._metrics_enabled:
            return
        
        try:
            INTEGRATION_REQUESTS_TOTAL.labels(
                integration=integration,
                operation=operation,
                status=status
            ).inc()
            
            INTEGRATION_REQUEST_DURATION.labels(
                integration=integration,
                operation=operation
            ).observe(duration)
        except Exception as e:
            logger.error(f"Error recording integration metrics: {e}")
    
    def record_quarantine_action(self, action: str, platform: str):
        """Record quarantine action"""
        if not self._metrics_enabled:
            return
        
        try:
            QUARANTINE_ACTIONS_TOTAL.labels(
                action=action,
                platform=platform
            ).inc()
        except Exception as e:
            logger.error(f"Error recording quarantine metrics: {e}")
    
    def record_alert_sent(self, alert_type: str, channel: str, status: str):
        """Record alert sent"""
        if not self._metrics_enabled:
            return
        
        try:
            ALERTS_SENT_TOTAL.labels(
                type=alert_type,
                channel=channel,
                status=status
            ).inc()
        except Exception as e:
            logger.error(f"Error recording alert metrics: {e}")
    
    def update_system_metrics(
        self,
        memory_usage: int = None,
        cpu_usage: float = None,
        active_connections: int = None
    ):
        """Update system performance metrics"""
        if not self._metrics_enabled:
            return
        
        try:
            if memory_usage is not None:
                MEMORY_USAGE_BYTES.set(memory_usage)
            
            if cpu_usage is not None:
                CPU_USAGE_PERCENT.set(cpu_usage)
            
            if active_connections is not None:
                ACTIVE_CONNECTIONS.set(active_connections)
        except Exception as e:
            logger.error(f"Error updating system metrics: {e}")
    
    def update_health_status(self, component: str, is_healthy: bool):
        """Update component health status"""
        if not self._metrics_enabled:
            return
        
        try:
            HEALTH_CHECK_STATUS.labels(component=component).set(1 if is_healthy else 0)
        except Exception as e:
            logger.error(f"Error updating health metrics: {e}")
    
    def get_metrics(self) -> str:
        """Get Prometheus metrics in text format"""
        if not self._metrics_enabled:
            return ""
        
        try:
            return generate_latest(REGISTRY).decode('utf-8')
        except Exception as e:
            logger.error(f"Error generating metrics: {e}")
            return ""

# Global metrics collector instance
metrics = MetricsCollector()

def metrics_middleware():
    """FastAPI middleware for automatic metrics collection"""
    async def middleware(request: Request, call_next):
        if not metrics.is_enabled():
            return await call_next(request)
        
        start_time = time.time()
        
        # Get request size
        request_size = 0
        if hasattr(request, 'headers') and 'content-length' in request.headers:
            try:
                request_size = int(request.headers['content-length'])
            except (ValueError, TypeError):
                pass
        
        try:
            response = await call_next(request)
        except Exception as e:
            # Record failed request
            duration = time.time() - start_time
            metrics.record_http_request(
                method=request.method,
                endpoint=request.url.path,
                status_code=500,
                duration=duration,
                request_size=request_size
            )
            raise
        
        # Calculate response time
        duration = time.time() - start_time
        
        # Get response size
        response_size = 0
        if hasattr(response, 'headers') and 'content-length' in response.headers:
            try:
                response_size = int(response.headers['content-length'])
            except (ValueError, TypeError):
                pass
        
        # Record metrics
        metrics.record_http_request(
            method=request.method,
            endpoint=request.url.path,
            status_code=response.status_code,
            duration=duration,
            request_size=request_size,
            response_size=response_size
        )
        
        return response
    
    return middleware

def monitor_function(
    metric_name: str = None,
    labels: Dict[str, str] = None,
    duration_metric: bool = True
):
    """Decorator to monitor function execution"""
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            if not metrics.is_enabled():
                return await func(*args, **kwargs)
            
            start_time = time.time()
            function_name = metric_name or f"{func.__module__}.{func.__name__}"
            
            try:
                result = await func(*args, **kwargs)
                status = "success"
            except Exception as e:
                status = "error"
                raise
            finally:
                if duration_metric:
                    duration = time.time() - start_time
                    # You could create a generic function duration metric here
                    logger.debug(f"Function {function_name} took {duration:.3f}s")
            
            return result
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            if not metrics.is_enabled():
                return func(*args, **kwargs)
            
            start_time = time.time()
            function_name = metric_name or f"{func.__module__}.{func.__name__}"
            
            try:
                result = func(*args, **kwargs)
                status = "success"
            except Exception as e:
                status = "error"
                raise
            finally:
                if duration_metric:
                    duration = time.time() - start_time
                    logger.debug(f"Function {function_name} took {duration:.3f}s")
            
            return result
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    
    return decorator

# FastAPI endpoint for metrics
async def metrics_endpoint():
    """FastAPI endpoint to serve Prometheus metrics"""
    return PlainTextResponse(
        content=metrics.get_metrics(),
        media_type=CONTENT_TYPE_LATEST
    )

# Export main components
__all__ = [
    'metrics', 'MetricsCollector', 'metrics_middleware', 
    'monitor_function', 'metrics_endpoint', 'REGISTRY'
]
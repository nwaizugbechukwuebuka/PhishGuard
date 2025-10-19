"""
Request Logger Middleware for PhishGuard API

Comprehensive request/response logging, audit trail, and security monitoring
for all API interactions.
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from ..database import SessionLocal
from ..models.audit_log import AuditLog
from ..utils.logger import get_logger

logger = get_logger(__name__)


class RequestLoggerMiddleware(BaseHTTPMiddleware):
    """
    Middleware for comprehensive request/response logging and audit trails.
    """

    def __init__(self, app, exclude_paths: Optional[list] = None):
        super().__init__(app)
        self.exclude_paths = exclude_paths or [
            "/docs",
            "/redoc",
            "/openapi.json",
            "/favicon.ico",
            "/health",
            "/metrics",
            "/static",
        ]

    async def dispatch(self, request: Request, call_next):
        """
        Process and log each request/response.

        Args:
            request: FastAPI request object
            call_next: Next middleware/route handler

        Returns:
            Response object
        """
        # Skip logging for excluded paths
        if any(request.url.path.startswith(path) for path in self.exclude_paths):
            return await call_next(request)

        # Generate unique request ID
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id

        # Start timing
        start_time = time.time()

        # Extract request information
        request_info = await self._extract_request_info(request)

        # Log request start
        logger.info(
            f"REQUEST_START",
            extra={
                "request_id": request_id,
                "method": request.method,
                "url": str(request.url),
                "client_ip": request.client.host,
                "user_agent": request.headers.get("user-agent"),
                "user_id": getattr(request.state, "user_id", None),
            },
        )

        try:
            # Process request
            response = await call_next(request)

            # Calculate processing time
            process_time = time.time() - start_time

            # Extract response information
            response_info = self._extract_response_info(response, process_time)

            # Log successful request
            await self._log_request_success(request_info, response_info, request_id)

            # Add response headers
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Process-Time"] = str(process_time)

            return response

        except Exception as e:
            # Calculate processing time for failed request
            process_time = time.time() - start_time

            # Log failed request
            await self._log_request_error(
                request_info, str(e), process_time, request_id
            )

            # Re-raise the exception
            raise

    async def _extract_request_info(self, request: Request) -> Dict[str, Any]:
        """
        Extract comprehensive request information.

        Args:
            request: FastAPI request object

        Returns:
            Dictionary containing request information
        """
        try:
            # Get request body for POST/PUT requests
            body = None
            if request.method in ["POST", "PUT", "PATCH"]:
                try:
                    body_bytes = await request.body()
                    if body_bytes:
                        # Try to parse as JSON, fallback to string
                        try:
                            body = json.loads(body_bytes.decode())
                            # Sanitize sensitive fields
                            body = self._sanitize_sensitive_data(body)
                        except (json.JSONDecodeError, UnicodeDecodeError):
                            body = f"<binary_data:{len(body_bytes)}_bytes>"
                except Exception:
                    body = "<could_not_read_body>"

            return {
                "request_id": getattr(request.state, "request_id", None),
                "timestamp": datetime.utcnow().isoformat(),
                "method": request.method,
                "url": str(request.url),
                "path": request.url.path,
                "query_params": dict(request.query_params),
                "headers": dict(request.headers),
                "client_ip": request.client.host,
                "client_port": request.client.port,
                "user_agent": request.headers.get("user-agent"),
                "content_type": request.headers.get("content-type"),
                "content_length": request.headers.get("content-length"),
                "body": body,
                "user_id": getattr(request.state, "user_id", None),
                "user_email": getattr(request.state, "user_email", None),
                "user_roles": getattr(request.state, "user_roles", []),
            }

        except Exception as e:
            logger.error(f"Error extracting request info: {str(e)}")
            return {
                "error": f"Failed to extract request info: {str(e)}",
                "timestamp": datetime.utcnow().isoformat(),
            }

    def _extract_response_info(
        self, response: Response, process_time: float
    ) -> Dict[str, Any]:
        """
        Extract response information.

        Args:
            response: FastAPI response object
            process_time: Request processing time in seconds

        Returns:
            Dictionary containing response information
        """
        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "process_time_seconds": round(process_time, 4),
            "content_type": response.headers.get("content-type"),
            "content_length": response.headers.get("content-length"),
        }

    async def _log_request_success(
        self,
        request_info: Dict[str, Any],
        response_info: Dict[str, Any],
        request_id: str,
    ):
        """
        Log successful request to database and file.

        Args:
            request_info: Request information dictionary
            response_info: Response information dictionary
            request_id: Unique request identifier
        """
        try:
            # Log to file
            logger.info(
                f"REQUEST_SUCCESS",
                extra={
                    "request_id": request_id,
                    "method": request_info.get("method"),
                    "path": request_info.get("path"),
                    "status_code": response_info.get("status_code"),
                    "process_time": response_info.get("process_time_seconds"),
                    "user_id": request_info.get("user_id"),
                    "client_ip": request_info.get("client_ip"),
                },
            )

            # Log to database (async)
            asyncio.create_task(
                self._save_audit_log(request_info, response_info, "SUCCESS")
            )

        except Exception as e:
            logger.error(f"Error logging successful request: {str(e)}")

    async def _log_request_error(
        self,
        request_info: Dict[str, Any],
        error_message: str,
        process_time: float,
        request_id: str,
    ):
        """
        Log failed request to database and file.

        Args:
            request_info: Request information dictionary
            error_message: Error message
            process_time: Request processing time
            request_id: Unique request identifier
        """
        try:
            # Log to file
            logger.error(
                f"REQUEST_ERROR",
                extra={
                    "request_id": request_id,
                    "method": request_info.get("method"),
                    "path": request_info.get("path"),
                    "error": error_message,
                    "process_time": round(process_time, 4),
                    "user_id": request_info.get("user_id"),
                    "client_ip": request_info.get("client_ip"),
                },
            )

            # Log to database (async)
            response_info = {
                "status_code": 500,
                "error_message": error_message,
                "process_time_seconds": round(process_time, 4),
            }

            asyncio.create_task(
                self._save_audit_log(request_info, response_info, "ERROR")
            )

        except Exception as e:
            logger.error(f"Error logging failed request: {str(e)}")

    async def _save_audit_log(
        self, request_info: Dict[str, Any], response_info: Dict[str, Any], status: str
    ):
        """
        Save audit log to database.

        Args:
            request_info: Request information dictionary
            response_info: Response information dictionary
            status: Request status (SUCCESS/ERROR)
        """
        try:
            db = SessionLocal()

            audit_log = AuditLog(
                request_id=request_info.get("request_id"),
                user_id=request_info.get("user_id"),
                action=f"{request_info.get('method')} {request_info.get('path')}",
                resource_type="API_ENDPOINT",
                resource_id=request_info.get("path"),
                status=status,
                ip_address=request_info.get("client_ip"),
                user_agent=request_info.get("user_agent"),
                metadata={
                    "request": {
                        "method": request_info.get("method"),
                        "url": request_info.get("url"),
                        "query_params": request_info.get("query_params"),
                        "headers": self._sanitize_headers(
                            request_info.get("headers", {})
                        ),
                        "body": request_info.get("body"),
                    },
                    "response": response_info,
                    "performance": {
                        "process_time_seconds": response_info.get(
                            "process_time_seconds"
                        )
                    },
                },
            )

            db.add(audit_log)
            db.commit()
            db.close()

        except Exception as e:
            logger.error(f"Error saving audit log to database: {str(e)}")
            try:
                db.close()
            except:
                pass

    def _sanitize_sensitive_data(self, data: Any) -> Any:
        """
        Remove or mask sensitive data from request body.

        Args:
            data: Data to sanitize

        Returns:
            Sanitized data
        """
        if not isinstance(data, dict):
            return data

        sensitive_fields = [
            "password",
            "token",
            "secret",
            "key",
            "auth",
            "authorization",
            "api_key",
            "access_token",
            "refresh_token",
            "credit_card",
            "ssn",
            "social",
        ]

        sanitized = {}
        for key, value in data.items():
            if any(field in key.lower() for field in sensitive_fields):
                sanitized[key] = "***REDACTED***"
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_sensitive_data(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    (
                        self._sanitize_sensitive_data(item)
                        if isinstance(item, dict)
                        else item
                    )
                    for item in value
                ]
            else:
                sanitized[key] = value

        return sanitized

    def _sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Remove or mask sensitive headers.

        Args:
            headers: Headers dictionary

        Returns:
            Sanitized headers
        """
        sensitive_headers = ["authorization", "cookie", "x-api-key", "x-auth-token"]

        sanitized = {}
        for key, value in headers.items():
            if key.lower() in sensitive_headers:
                sanitized[key] = "***REDACTED***"
            else:
                sanitized[key] = value

        return sanitized


class SecurityMonitor:
    """
    Security monitoring for suspicious request patterns.
    """

    def __init__(self):
        self.suspicious_patterns = {
            "sql_injection": [
                "union select",
                "drop table",
                "delete from",
                "insert into",
                "update set",
                "--",
                "/*",
                "*/",
            ],
            "xss": [
                "<script",
                "javascript:",
                "onload=",
                "onerror=",
                "alert(",
                "document.cookie",
            ],
            "path_traversal": ["../", "..\\", "/etc/passwd", "\\windows\\system32"],
            "command_injection": ["; cat ", "| cat ", "$(", "`", "&& cat"],
        }

    def analyze_request(self, request_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze request for security threats.

        Args:
            request_info: Request information dictionary

        Returns:
            Security analysis results
        """
        threats_detected = []
        risk_score = 0

        # Check URL and parameters
        url_text = request_info.get("url", "").lower()
        query_params = request_info.get("query_params", {})
        body = request_info.get("body", {})

        # Convert all text to analyze
        text_to_analyze = [url_text]

        if isinstance(query_params, dict):
            text_to_analyze.extend(str(v).lower() for v in query_params.values())

        if isinstance(body, dict):
            text_to_analyze.extend(
                str(v).lower()
                for v in body.values()
                if isinstance(v, (str, int, float))
            )
        elif isinstance(body, str):
            text_to_analyze.append(body.lower())

        # Check for suspicious patterns
        for category, patterns in self.suspicious_patterns.items():
            for text in text_to_analyze:
                for pattern in patterns:
                    if pattern in text:
                        threats_detected.append(
                            {
                                "type": category,
                                "pattern": pattern,
                                "location": (
                                    "url" if text == url_text else "parameters/body"
                                ),
                            }
                        )
                        risk_score += 10

        # Check for unusual request characteristics
        if len(url_text) > 1000:  # Unusually long URL
            threats_detected.append(
                {
                    "type": "suspicious_request_size",
                    "pattern": "long_url",
                    "location": "url",
                }
            )
            risk_score += 5

        # Rate limiting check (simplified)
        client_ip = request_info.get("client_ip")
        if self._is_suspicious_ip(client_ip):
            threats_detected.append(
                {
                    "type": "suspicious_ip",
                    "pattern": "known_threat_ip",
                    "location": "client",
                }
            )
            risk_score += 20

        return {
            "threats_detected": threats_detected,
            "risk_score": min(risk_score, 100),  # Cap at 100
            "is_suspicious": risk_score > 15,
            "analysis_timestamp": datetime.utcnow().isoformat(),
        }

    def _is_suspicious_ip(self, ip_address: str) -> bool:
        """
        Check if IP address is in threat database.

        Args:
            ip_address: Client IP address

        Returns:
            True if IP is suspicious
        """
        # In production, this would check against threat intelligence feeds
        suspicious_ips = [
            "127.0.0.1",  # Example - remove in production
        ]

        return ip_address in suspicious_ips


# Performance monitoring
class PerformanceMonitor:
    """
    Monitor API performance and generate alerts for slow endpoints.
    """

    def __init__(self):
        self.slow_request_threshold = 5.0  # seconds
        self.performance_data = {}  # In production, use Redis/database

    def record_performance(
        self, endpoint: str, method: str, process_time: float, status_code: int
    ):
        """
        Record endpoint performance metrics.

        Args:
            endpoint: API endpoint path
            method: HTTP method
            process_time: Processing time in seconds
            status_code: Response status code
        """
        key = f"{method}:{endpoint}"

        if key not in self.performance_data:
            self.performance_data[key] = {
                "request_count": 0,
                "total_time": 0.0,
                "max_time": 0.0,
                "min_time": float("inf"),
                "error_count": 0,
                "slow_request_count": 0,
            }

        stats = self.performance_data[key]
        stats["request_count"] += 1
        stats["total_time"] += process_time
        stats["max_time"] = max(stats["max_time"], process_time)
        stats["min_time"] = min(stats["min_time"], process_time)

        if status_code >= 400:
            stats["error_count"] += 1

        if process_time > self.slow_request_threshold:
            stats["slow_request_count"] += 1
            logger.warning(
                f"SLOW_REQUEST: {method} {endpoint} took {process_time:.2f}s"
            )

    def get_performance_summary(self) -> Dict[str, Any]:
        """
        Get performance summary for all endpoints.

        Returns:
            Performance summary dictionary
        """
        summary = {}

        for endpoint, stats in self.performance_data.items():
            if stats["request_count"] > 0:
                summary[endpoint] = {
                    "request_count": stats["request_count"],
                    "average_time": stats["total_time"] / stats["request_count"],
                    "max_time": stats["max_time"],
                    "min_time": stats["min_time"],
                    "error_rate": stats["error_count"] / stats["request_count"],
                    "slow_request_rate": stats["slow_request_count"]
                    / stats["request_count"],
                }

        return summary


# Initialize monitoring components
security_monitor = SecurityMonitor()
performance_monitor = PerformanceMonitor()

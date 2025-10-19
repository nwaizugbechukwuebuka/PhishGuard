"""
Health Check System for PhishGuard
Comprehensive health monitoring for all system components
"""

import asyncio
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

import aiohttp
import psutil
import redis.asyncio as redis
import sqlalchemy
from sqlalchemy import text

from src.api.utils.logger import get_logger
from src.api.utils.monitoring import metrics

logger = get_logger(__name__)


class HealthStatus(Enum):
    """Health check status enumeration"""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class HealthCheckResult:
    """Health check result data structure"""

    component: str
    status: HealthStatus
    message: str
    details: Dict[str, Any] = None
    timestamp: datetime = None
    response_time: float = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()
        if self.details is None:
            self.details = {}


class BaseHealthCheck:
    """Base class for health checks"""

    def __init__(self, name: str, timeout: float = 10.0):
        self.name = name
        self.timeout = timeout

    async def check(self) -> HealthCheckResult:
        """Execute health check - to be implemented by subclasses"""
        raise NotImplementedError

    async def execute_with_timeout(self) -> HealthCheckResult:
        """Execute health check with timeout"""
        start_time = time.time()

        try:
            result = await asyncio.wait_for(self.check(), timeout=self.timeout)
            result.response_time = time.time() - start_time
            return result
        except asyncio.TimeoutError:
            return HealthCheckResult(
                component=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"Health check timed out after {self.timeout}s",
                response_time=time.time() - start_time,
            )
        except Exception as e:
            return HealthCheckResult(
                component=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"Health check failed: {str(e)}",
                response_time=time.time() - start_time,
            )


class DatabaseHealthCheck(BaseHealthCheck):
    """Database connectivity health check"""

    def __init__(self, engine, timeout: float = 5.0):
        super().__init__("database", timeout)
        self.engine = engine

    async def check(self) -> HealthCheckResult:
        """Check database connectivity and performance"""
        try:
            # Test basic connectivity
            async with self.engine.begin() as conn:
                result = await conn.execute(text("SELECT 1"))
                row = result.fetchone()

                if row and row[0] == 1:
                    # Get additional database info
                    pool_info = (
                        self.engine.pool.status()
                        if hasattr(self.engine.pool, "status")
                        else {}
                    )

                    details = {
                        "pool_size": getattr(self.engine.pool, "size", lambda: None)(),
                        "checked_out": getattr(
                            self.engine.pool, "checkedout", lambda: None
                        )(),
                        "overflow": getattr(
                            self.engine.pool, "overflow", lambda: None
                        )(),
                    }

                    # Remove None values
                    details = {k: v for k, v in details.items() if v is not None}

                    return HealthCheckResult(
                        component=self.name,
                        status=HealthStatus.HEALTHY,
                        message="Database connection successful",
                        details=details,
                    )
                else:
                    return HealthCheckResult(
                        component=self.name,
                        status=HealthStatus.UNHEALTHY,
                        message="Database query returned unexpected result",
                    )

        except Exception as e:
            return HealthCheckResult(
                component=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"Database connection failed: {str(e)}",
            )


class RedisHealthCheck(BaseHealthCheck):
    """Redis connectivity health check"""

    def __init__(self, redis_url: str = "redis://localhost:6379", timeout: float = 5.0):
        super().__init__("redis", timeout)
        self.redis_url = redis_url

    async def check(self) -> HealthCheckResult:
        """Check Redis connectivity and performance"""
        try:
            redis_client = redis.from_url(self.redis_url)

            # Test basic connectivity
            ping_result = await redis_client.ping()

            if ping_result:
                # Get Redis info
                info = await redis_client.info()

                details = {
                    "connected_clients": info.get("connected_clients"),
                    "used_memory_human": info.get("used_memory_human"),
                    "redis_version": info.get("redis_version"),
                    "uptime_in_seconds": info.get("uptime_in_seconds"),
                }

                await redis_client.close()

                return HealthCheckResult(
                    component=self.name,
                    status=HealthStatus.HEALTHY,
                    message="Redis connection successful",
                    details=details,
                )
            else:
                await redis_client.close()
                return HealthCheckResult(
                    component=self.name,
                    status=HealthStatus.UNHEALTHY,
                    message="Redis ping failed",
                )

        except Exception as e:
            return HealthCheckResult(
                component=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"Redis connection failed: {str(e)}",
            )


class ExternalServiceHealthCheck(BaseHealthCheck):
    """External service HTTP health check"""

    def __init__(
        self, name: str, url: str, timeout: float = 10.0, expected_status: int = 200
    ):
        super().__init__(name, timeout)
        self.url = url
        self.expected_status = expected_status

    async def check(self) -> HealthCheckResult:
        """Check external service availability"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.url, timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    if response.status == self.expected_status:
                        details = {
                            "status_code": response.status,
                            "headers": dict(response.headers),
                            "url": self.url,
                        }

                        return HealthCheckResult(
                            component=self.name,
                            status=HealthStatus.HEALTHY,
                            message=f"Service responding with status {response.status}",
                            details=details,
                        )
                    else:
                        return HealthCheckResult(
                            component=self.name,
                            status=HealthStatus.DEGRADED,
                            message=f"Service returned status {response.status}, expected {self.expected_status}",
                            details={"status_code": response.status, "url": self.url},
                        )

        except asyncio.TimeoutError:
            return HealthCheckResult(
                component=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"Service timeout after {self.timeout}s",
                details={"url": self.url},
            )
        except Exception as e:
            return HealthCheckResult(
                component=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"Service check failed: {str(e)}",
                details={"url": self.url},
            )


class SystemResourcesHealthCheck(BaseHealthCheck):
    """System resources health check"""

    def __init__(self, timeout: float = 5.0):
        super().__init__("system_resources", timeout)
        self.cpu_threshold = 90.0  # CPU usage threshold
        self.memory_threshold = 90.0  # Memory usage threshold
        self.disk_threshold = 90.0  # Disk usage threshold

    async def check(self) -> HealthCheckResult:
        """Check system resource usage"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)

            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent

            # Disk usage (root partition)
            disk = psutil.disk_usage("/")
            disk_percent = (disk.used / disk.total) * 100

            # Network statistics
            network = psutil.net_io_counters()

            details = {
                "cpu_percent": cpu_percent,
                "memory_percent": memory_percent,
                "memory_total_gb": round(memory.total / (1024**3), 2),
                "memory_available_gb": round(memory.available / (1024**3), 2),
                "disk_percent": disk_percent,
                "disk_total_gb": round(disk.total / (1024**3), 2),
                "disk_free_gb": round(disk.free / (1024**3), 2),
                "network_bytes_sent": network.bytes_sent,
                "network_bytes_recv": network.bytes_recv,
            }

            # Determine status based on thresholds
            if (
                cpu_percent > self.cpu_threshold
                or memory_percent > self.memory_threshold
                or disk_percent > self.disk_threshold
            ):
                status = HealthStatus.DEGRADED
                message = "System resources under high load"
            else:
                status = HealthStatus.HEALTHY
                message = "System resources normal"

            # Update monitoring metrics
            metrics.update_system_metrics(
                memory_usage=int(memory.used), cpu_usage=cpu_percent
            )

            return HealthCheckResult(
                component=self.name, status=status, message=message, details=details
            )

        except Exception as e:
            return HealthCheckResult(
                component=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"System resource check failed: {str(e)}",
            )


class AIModelHealthCheck(BaseHealthCheck):
    """AI model health check"""

    def __init__(self, model_path: str = None, timeout: float = 10.0):
        super().__init__("ai_model", timeout)
        self.model_path = model_path

    async def check(self) -> HealthCheckResult:
        """Check AI model availability and performance"""
        try:
            # Import here to avoid circular imports
            from src.ai_engine.inference import ThreatAnalyzer

            analyzer = ThreatAnalyzer()

            # Test model loading and basic functionality
            start_time = time.time()

            # Create a test email object for model testing
            test_result = await analyzer._test_model_functionality()

            model_load_time = time.time() - start_time

            if test_result.get("success", False):
                details = {
                    "model_loaded": True,
                    "model_load_time": model_load_time,
                    "model_version": test_result.get("model_version", "unknown"),
                    "features_count": test_result.get("features_count", 0),
                }

                return HealthCheckResult(
                    component=self.name,
                    status=HealthStatus.HEALTHY,
                    message="AI model functioning normally",
                    details=details,
                )
            else:
                return HealthCheckResult(
                    component=self.name,
                    status=HealthStatus.DEGRADED,
                    message="AI model partially functional",
                    details={"error": test_result.get("error", "Unknown error")},
                )

        except Exception as e:
            return HealthCheckResult(
                component=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"AI model check failed: {str(e)}",
            )


class IntegrationHealthCheck(BaseHealthCheck):
    """Integration services health check"""

    def __init__(self, timeout: float = 15.0):
        super().__init__("integrations", timeout)

    async def check(self) -> HealthCheckResult:
        """Check integration services status"""
        try:
            integration_status = {}
            overall_status = HealthStatus.HEALTHY

            # Check Gmail integration
            try:
                from src.integrations.gmail_api import GmailIntegration

                gmail = GmailIntegration()
                # Basic configuration check
                integration_status["gmail"] = {
                    "configured": bool(gmail.credentials_path),
                    "status": (
                        "configured" if gmail.credentials_path else "not_configured"
                    ),
                }
            except Exception as e:
                integration_status["gmail"] = {"status": "error", "error": str(e)}
                overall_status = HealthStatus.DEGRADED

            # Check Microsoft 365 integration
            try:
                from src.integrations.microsoft365 import Microsoft365Integration

                ms365 = Microsoft365Integration()
                integration_status["microsoft365"] = {
                    "configured": bool(ms365.client_id),
                    "status": "configured" if ms365.client_id else "not_configured",
                }
            except Exception as e:
                integration_status["microsoft365"] = {
                    "status": "error",
                    "error": str(e),
                }
                overall_status = HealthStatus.DEGRADED

            # Check Slack integration
            try:
                from src.integrations.slack_webhook import SlackIntegration

                slack = SlackIntegration()
                integration_status["slack"] = {
                    "configured": slack.is_configured(),
                    "status": (
                        "configured" if slack.is_configured() else "not_configured"
                    ),
                }
            except Exception as e:
                integration_status["slack"] = {"status": "error", "error": str(e)}
                overall_status = HealthStatus.DEGRADED

            return HealthCheckResult(
                component=self.name,
                status=overall_status,
                message="Integration services checked",
                details=integration_status,
            )

        except Exception as e:
            return HealthCheckResult(
                component=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"Integration check failed: {str(e)}",
            )


class HealthChecker:
    """Main health checker orchestrator"""

    def __init__(self):
        self.checks: List[BaseHealthCheck] = []
        self.last_check_time: Optional[datetime] = None
        self.last_results: List[HealthCheckResult] = []
        self.check_interval = 30  # seconds

    def add_check(self, health_check: BaseHealthCheck):
        """Add a health check to the system"""
        self.checks.append(health_check)
        logger.info(f"Added health check: {health_check.name}")

    async def run_checks(self) -> Dict[str, Any]:
        """Run all health checks and return results"""
        start_time = time.time()

        # Run all checks concurrently
        tasks = [check.execute_with_timeout() for check in self.checks]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        check_results = []
        overall_status = HealthStatus.HEALTHY

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                # Handle check that threw an exception
                result = HealthCheckResult(
                    component=self.checks[i].name,
                    status=HealthStatus.UNHEALTHY,
                    message=f"Health check exception: {str(result)}",
                )

            check_results.append(result)

            # Update overall status
            if result.status == HealthStatus.UNHEALTHY:
                overall_status = HealthStatus.UNHEALTHY
            elif (
                result.status == HealthStatus.DEGRADED
                and overall_status == HealthStatus.HEALTHY
            ):
                overall_status = HealthStatus.DEGRADED

        total_time = time.time() - start_time
        self.last_check_time = datetime.utcnow()
        self.last_results = check_results

        # Update metrics
        for result in check_results:
            metrics.update_health_status(
                result.component, result.status == HealthStatus.HEALTHY
            )

        # Build response
        response = {
            "status": overall_status.value,
            "timestamp": self.last_check_time.isoformat(),
            "total_duration": round(total_time, 3),
            "checks": {
                result.component: {
                    "status": result.status.value,
                    "message": result.message,
                    "response_time": round(result.response_time or 0, 3),
                    "details": result.details,
                    "timestamp": result.timestamp.isoformat(),
                }
                for result in check_results
            },
            "summary": {
                "total_checks": len(check_results),
                "healthy": sum(
                    1 for r in check_results if r.status == HealthStatus.HEALTHY
                ),
                "degraded": sum(
                    1 for r in check_results if r.status == HealthStatus.DEGRADED
                ),
                "unhealthy": sum(
                    1 for r in check_results if r.status == HealthStatus.UNHEALTHY
                ),
            },
        }

        return response

    async def run_check(self, component_name: str) -> Optional[Dict[str, Any]]:
        """Run a specific health check"""
        for check in self.checks:
            if check.name == component_name:
                result = await check.execute_with_timeout()

                # Update metrics
                metrics.update_health_status(
                    result.component, result.status == HealthStatus.HEALTHY
                )

                return {
                    "status": result.status.value,
                    "message": result.message,
                    "response_time": round(result.response_time or 0, 3),
                    "details": result.details,
                    "timestamp": result.timestamp.isoformat(),
                }

        return None

    def get_last_results(self) -> Dict[str, Any]:
        """Get last health check results"""
        if not self.last_results:
            return {"message": "No health checks have been run yet"}

        overall_status = HealthStatus.HEALTHY
        for result in self.last_results:
            if result.status == HealthStatus.UNHEALTHY:
                overall_status = HealthStatus.UNHEALTHY
                break
            elif result.status == HealthStatus.DEGRADED:
                overall_status = HealthStatus.DEGRADED

        return {
            "status": overall_status.value,
            "last_check": (
                self.last_check_time.isoformat() if self.last_check_time else None
            ),
            "checks": {
                result.component: {
                    "status": result.status.value,
                    "message": result.message,
                    "timestamp": result.timestamp.isoformat(),
                }
                for result in self.last_results
            },
        }


# Global health checker instance
health_checker = HealthChecker()


# Initialize default health checks
def initialize_health_checks(database_engine=None, redis_url: str = None):
    """Initialize default health checks"""

    # System resources check
    health_checker.add_check(SystemResourcesHealthCheck())

    # Database check
    if database_engine:
        health_checker.add_check(DatabaseHealthCheck(database_engine))

    # Redis check
    if redis_url:
        health_checker.add_check(RedisHealthCheck(redis_url))

    # AI model check
    health_checker.add_check(AIModelHealthCheck())

    # Integration check
    health_checker.add_check(IntegrationHealthCheck())

    logger.info("Health checks initialized")


# FastAPI endpoints
async def health_endpoint():
    """Simple health endpoint"""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


async def health_detailed_endpoint():
    """Detailed health check endpoint"""
    return await health_checker.run_checks()


async def health_component_endpoint(component: str):
    """Component-specific health check endpoint"""
    result = await health_checker.run_check(component)
    if result:
        return result
    else:
        return {"error": f"Health check '{component}' not found"}, 404


# Export main components
__all__ = [
    "HealthChecker",
    "HealthStatus",
    "HealthCheckResult",
    "BaseHealthCheck",
    "DatabaseHealthCheck",
    "RedisHealthCheck",
    "ExternalServiceHealthCheck",
    "SystemResourcesHealthCheck",
    "AIModelHealthCheck",
    "IntegrationHealthCheck",
    "health_checker",
    "initialize_health_checks",
    "health_endpoint",
    "health_detailed_endpoint",
    "health_component_endpoint",
]

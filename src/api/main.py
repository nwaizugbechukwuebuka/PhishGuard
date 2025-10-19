"""
PhishGuard Enterprise Security Platform
Main FastAPI Application

This module initializes the PhishGuard API server with all routes, middleware,
and enterprise security features for advanced email threat detection and response.
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Any, Dict

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import start_http_server

from .database import create_tables, engine, metadata
from .middleware.auth_middleware import AuthMiddleware
from .middleware.rate_limit import RateLimitMiddleware
from .middleware.request_logger import RequestLoggerMiddleware
from .routes import auth, notify, quarantine, reports, simulation, users
from .utils.config import settings
from .utils.logger import logger, setup_logging
from .utils.security import SecurityHeaders

# Initialize logging
setup_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events for startup and shutdown."""
    # Startup
    logger.info("🚀 Starting PhishGuard Enterprise Security Platform...")

    try:
        # Create database tables
        await create_tables()
        logger.info("✅ Database tables initialized")

        # Start Prometheus metrics server
        if settings.METRICS_ENABLED:
            start_http_server(settings.PROMETHEUS_METRICS_PORT)
            logger.info(
                f"📊 Prometheus metrics server started on port {settings.PROMETHEUS_METRICS_PORT}"
            )

        # Warm up AI models
        from .ai_engine.inference import PhishingDetector

        detector = PhishingDetector()
        await detector.load_model()
        logger.info("🤖 AI models loaded successfully")

        logger.info("🛡️ PhishGuard is ready for enterprise email security!")

    except Exception as e:
        logger.error(f"❌ Failed to start PhishGuard: {str(e)}")
        raise

    yield

    # Shutdown
    logger.info("🔄 Shutting down PhishGuard...")
    logger.info("👋 PhishGuard shutdown complete")


# Create FastAPI application
app = FastAPI(
    title="PhishGuard Enterprise API",
    description="""
    🛡️ **PhishGuard Enterprise Security Platform**
    
    Advanced email threat detection and automated response system providing:
    
    ## 🎯 Core Features
    * **AI-Powered Phishing Detection** - Machine learning models for advanced threat identification
    * **Real-time Email Scanning** - Continuous monitoring of email traffic
    * **Automated Quarantine** - Intelligent threat isolation and management
    * **Enterprise Integrations** - Gmail, Microsoft 365, Slack, SIEM/SOAR connectivity
    * **Compliance Reporting** - SOC 2, ISO 27001, and regulatory compliance automation
    * **Executive Analytics** - Real-time dashboards and threat intelligence
    
    ## 🚀 Enterprise Scale
    * **High Performance** - 10,000+ emails/minute processing capability
    * **Zero Downtime** - Microservices architecture with health monitoring
    * **Security First** - JWT authentication, rate limiting, and audit logging
    * **Cloud Native** - Kubernetes-ready with Docker containerization
    
    ## 📊 API Capabilities
    * RESTful API design with OpenAPI 3.0 specification
    * WebSocket support for real-time notifications
    * Comprehensive error handling and validation
    * Prometheus metrics and observability
    """,
    version=settings.APP_VERSION,
    openapi_url=f"{settings.API_PREFIX}/openapi.json",
    docs_url=f"{settings.API_PREFIX}/docs",
    redoc_url=f"{settings.API_PREFIX}/redoc",
    lifespan=lifespan,
)


# Security Middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=(
        ["*"]
        if settings.DEBUG
        else ["localhost", "127.0.0.1", settings.ALLOWED_ORIGINS]
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=settings.ALLOWED_METHODS,
    allow_headers=settings.ALLOWED_HEADERS,
)

# Custom Middleware
app.add_middleware(SecurityHeaders)
app.add_middleware(RequestLoggerMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(AuthMiddleware)


# Exception Handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Handle HTTP exceptions with structured error responses."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "type": "http_error",
                "message": exc.detail,
                "status_code": exc.status_code,
                "path": str(request.url),
                "timestamp": logger.get_timestamp(),
            }
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle unexpected exceptions with secure error responses."""
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)

    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "type": "internal_error",
                "message": (
                    "An internal server error occurred"
                    if not settings.DEBUG
                    else str(exc)
                ),
                "status_code": 500,
                "path": str(request.url),
                "timestamp": logger.get_timestamp(),
            }
        },
    )


# Health Check Endpoints
@app.get("/health", tags=["Health"], summary="Health Check")
async def health_check() -> Dict[str, Any]:
    """
    Comprehensive health check endpoint for monitoring and load balancers.

    Returns system status, database connectivity, and service health metrics.
    """
    from .services.health_service import HealthService

    health_service = HealthService()
    health_status = await health_service.get_system_health()

    return {
        "status": "healthy" if health_status["overall_health"] else "unhealthy",
        "timestamp": logger.get_timestamp(),
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "checks": health_status,
    }


@app.get("/health/live", tags=["Health"], summary="Liveness Probe")
async def liveness_probe() -> Dict[str, str]:
    """Kubernetes liveness probe endpoint."""
    return {"status": "alive", "timestamp": logger.get_timestamp()}


@app.get("/health/ready", tags=["Health"], summary="Readiness Probe")
async def readiness_probe() -> Dict[str, Any]:
    """Kubernetes readiness probe endpoint."""
    from .services.health_service import HealthService

    health_service = HealthService()
    is_ready = await health_service.check_readiness()

    return {
        "status": "ready" if is_ready else "not_ready",
        "timestamp": logger.get_timestamp(),
    }


# API Routes
app.include_router(
    auth.router,
    prefix=f"{settings.API_PREFIX}/auth",
    tags=["Authentication"],
)

app.include_router(
    users.router,
    prefix=f"{settings.API_PREFIX}/users",
    tags=["User Management"],
)

app.include_router(
    quarantine.router,
    prefix=f"{settings.API_PREFIX}/quarantine",
    tags=["Email Quarantine"],
)

app.include_router(
    reports.router,
    prefix=f"{settings.API_PREFIX}/reports",
    tags=["Reporting & Analytics"],
)

app.include_router(
    simulation.router,
    prefix=f"{settings.API_PREFIX}/simulations",
    tags=["Phishing Simulations"],
)

app.include_router(
    notify.router,
    prefix=f"{settings.API_PREFIX}/notifications",
    tags=["Notifications & Alerts"],
)


# Root endpoint
@app.get("/", tags=["Root"])
async def root() -> Dict[str, Any]:
    """
    PhishGuard API root endpoint with system information.
    """
    return {
        "message": "🛡️ PhishGuard Enterprise Security Platform",
        "description": "Advanced email threat detection and automated response system",
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "api_docs": f"{settings.API_PREFIX}/docs",
        "health_check": "/health",
        "timestamp": logger.get_timestamp(),
        "features": [
            "AI-Powered Phishing Detection",
            "Real-time Email Scanning",
            "Automated Quarantine Management",
            "Enterprise Integrations",
            "Compliance Reporting",
            "Executive Analytics Dashboard",
        ],
    }


# WebSocket endpoint for real-time notifications
@app.websocket(f"{settings.API_PREFIX}/ws")
async def websocket_endpoint(websocket):
    """WebSocket endpoint for real-time notifications and updates."""
    from .services.notification_service import NotificationService

    notification_service = NotificationService()
    await notification_service.handle_websocket(websocket)


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
        workers=1 if settings.DEBUG else settings.MAX_WORKERS,
    )

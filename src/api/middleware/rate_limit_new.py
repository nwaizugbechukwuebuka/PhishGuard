"""
Rate Limiting Middleware for PhishGuard API

Advanced rate limiting with multiple strategies, user-based limits,
and DDoS protection capabilities.
"""

import asyncio
import hashlib
import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, Optional, Tuple

import redis
from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from ..utils.config import settings
from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class RateLimitRule:
    """Rate limit rule configuration"""

    requests: int  # Number of requests allowed
    window: int  # Time window in seconds
    burst: int = None  # Burst allowance (optional)
    key_func: str = "ip"  # Key function: ip, user, endpoint


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Advanced rate limiting middleware with multiple strategies.
    """

    def __init__(
        self,
        app,
        redis_client: Optional[redis.Redis] = None,
        default_rate_limit: int = 100,
        default_window: int = 60,
        burst_limit: int = 20,
        burst_window: int = 1,
    ):
        super().__init__(app)
        self.redis_client = redis_client
        self.default_rate_limit = default_rate_limit
        self.default_window = default_window
        self.burst_limit = burst_limit
        self.burst_window = burst_window

        # In-memory fallback if Redis is not available
        self.memory_store = {}
        self.cleanup_interval = 300  # 5 minutes
        self.last_cleanup = time.time()

        # Rate limit configurations per endpoint
        self.endpoint_limits = {
            "POST:/auth/login": {"rate": 5, "window": 300},  # 5 attempts per 5 minutes
            "POST:/auth/register": {"rate": 3, "window": 3600},  # 3 per hour
            "POST:/auth/forgot-password": {"rate": 3, "window": 3600},  # 3 per hour
            "GET:/emails": {"rate": 1000, "window": 60},  # 1000 per minute
            "POST:/emails/scan": {"rate": 50, "window": 60},  # 50 scans per minute
            "POST:/quarantine": {"rate": 100, "window": 60},  # 100 per minute
            "POST:/reports": {"rate": 10, "window": 60},  # 10 reports per minute
        }

        # User tier limits
        self.user_tier_limits = {
            "free": {"daily": 1000, "hourly": 100, "minute": 10},
            "premium": {"daily": 10000, "hourly": 1000, "minute": 100},
            "enterprise": {"daily": 100000, "hourly": 10000, "minute": 1000},
            "admin": {
                "daily": float("inf"),
                "hourly": float("inf"),
                "minute": float("inf"),
            },
        }

    async def dispatch(self, request: Request, call_next):
        """
        Process rate limiting for each request.

        Args:
            request: FastAPI request object
            call_next: Next middleware/route handler

        Returns:
            Response object or HTTPException if rate limited
        """
        # Skip rate limiting for health checks and static files
        skip_paths = [
            "/health",
            "/metrics",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/static",
        ]
        if any(request.url.path.startswith(path) for path in skip_paths):
            return await call_next(request)

        try:
            # Get client identifier and user info
            client_id = self._get_client_id(request)
            user_id = getattr(request.state, "user_id", None)
            user_tier = self._get_user_tier(request)

            # Check rate limits
            rate_limit_result = await self._check_rate_limits(
                request, client_id, user_id, user_tier
            )

            if not rate_limit_result["allowed"]:
                # Log rate limit violation
                logger.warning(
                    f"RATE_LIMIT_EXCEEDED",
                    extra={
                        "client_id": client_id,
                        "user_id": user_id,
                        "endpoint": f"{request.method}:{request.url.path}",
                        "limit_type": rate_limit_result["limit_type"],
                        "retry_after": rate_limit_result["retry_after"],
                    },
                )

                # Return rate limit error
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "error": "Rate limit exceeded",
                        "limit_type": rate_limit_result["limit_type"],
                        "retry_after": rate_limit_result["retry_after"],
                        "current_usage": rate_limit_result["current_usage"],
                        "limit": rate_limit_result["limit"],
                    },
                    headers={
                        "Retry-After": str(rate_limit_result["retry_after"]),
                        "X-RateLimit-Limit": str(rate_limit_result["limit"]),
                        "X-RateLimit-Remaining": str(
                            max(
                                0,
                                rate_limit_result["limit"]
                                - rate_limit_result["current_usage"],
                            )
                        ),
                        "X-RateLimit-Reset": str(
                            int(time.time()) + rate_limit_result["retry_after"]
                        ),
                    },
                )

            # Process request
            response = await call_next(request)

            # Add rate limit headers to response
            response.headers.update(
                {
                    "X-RateLimit-Limit": str(rate_limit_result["limit"]),
                    "X-RateLimit-Remaining": str(
                        max(
                            0,
                            rate_limit_result["limit"]
                            - rate_limit_result["current_usage"]
                            - 1,
                        )
                    ),
                    "X-RateLimit-Reset": str(
                        int(time.time()) + rate_limit_result["window"]
                    ),
                }
            )

            return response

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Rate limiting error: {str(e)}")
            # Allow request to proceed if rate limiting fails
            return await call_next(request)

    def _get_client_id(self, request: Request) -> str:
        """
        Generate unique client identifier.

        Args:
            request: FastAPI request object

        Returns:
            Unique client identifier
        """
        # Try to get real IP from headers (behind proxy)
        real_ip = (
            request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.headers.get("X-Real-IP")
            or request.client.host
        )

        # Include user agent for more specific identification
        user_agent = request.headers.get("User-Agent", "")

        # Create hash of IP + User-Agent for privacy
        client_string = f"{real_ip}:{user_agent}"
        client_id = hashlib.sha256(client_string.encode()).hexdigest()[:16]

        return client_id

    def _get_user_tier(self, request: Request) -> str:
        """
        Get user tier from request state.

        Args:
            request: FastAPI request object

        Returns:
            User tier string
        """
        user_roles = getattr(request.state, "user_roles", [])

        if "admin" in user_roles:
            return "admin"
        elif "enterprise" in user_roles:
            return "enterprise"
        elif "premium" in user_roles:
            return "premium"
        else:
            return "free"

    async def _check_rate_limits(
        self, request: Request, client_id: str, user_id: Optional[str], user_tier: str
    ) -> Dict[str, Any]:
        """
        Check all applicable rate limits.

        Args:
            request: FastAPI request object
            client_id: Client identifier
            user_id: User ID if authenticated
            user_tier: User tier for limits

        Returns:
            Rate limit check result
        """
        endpoint = f"{request.method}:{request.url.path}"

        # Check endpoint-specific limits
        endpoint_result = await self._check_endpoint_limit(endpoint, client_id)
        if not endpoint_result["allowed"]:
            return endpoint_result

        # Check burst limits
        burst_result = await self._check_burst_limit(client_id)
        if not burst_result["allowed"]:
            return burst_result

        # Check user tier limits (if authenticated)
        if user_id:
            tier_result = await self._check_user_tier_limits(user_id, user_tier)
            if not tier_result["allowed"]:
                return tier_result

        # Check DDoS protection
        ddos_result = await self._check_ddos_protection(client_id, request)
        if not ddos_result["allowed"]:
            return ddos_result

        # All limits passed
        return {
            "allowed": True,
            "limit_type": "general",
            "current_usage": 0,
            "limit": self.default_rate_limit,
            "retry_after": 0,
            "window": self.default_window,
        }

    async def _check_endpoint_limit(
        self, endpoint: str, client_id: str
    ) -> Dict[str, Any]:
        """
        Check endpoint-specific rate limits.

        Args:
            endpoint: Endpoint identifier
            client_id: Client identifier

        Returns:
            Rate limit check result
        """
        if endpoint not in self.endpoint_limits:
            return {"allowed": True}

        limit_config = self.endpoint_limits[endpoint]
        key = f"endpoint:{endpoint}:{client_id}"

        current_usage = await self._get_current_usage(key, limit_config["window"])

        if current_usage >= limit_config["rate"]:
            return {
                "allowed": False,
                "limit_type": "endpoint",
                "current_usage": current_usage,
                "limit": limit_config["rate"],
                "retry_after": limit_config["window"],
                "window": limit_config["window"],
            }

        # Increment usage
        await self._increment_usage(key, limit_config["window"])

        return {
            "allowed": True,
            "limit_type": "endpoint",
            "current_usage": current_usage + 1,
            "limit": limit_config["rate"],
            "retry_after": 0,
            "window": limit_config["window"],
        }

    async def _check_burst_limit(self, client_id: str) -> Dict[str, Any]:
        """
        Check burst rate limits (short-term high frequency).

        Args:
            client_id: Client identifier

        Returns:
            Rate limit check result
        """
        key = f"burst:{client_id}"
        current_usage = await self._get_current_usage(key, self.burst_window)

        if current_usage >= self.burst_limit:
            return {
                "allowed": False,
                "limit_type": "burst",
                "current_usage": current_usage,
                "limit": self.burst_limit,
                "retry_after": self.burst_window,
                "window": self.burst_window,
            }

        # Increment usage
        await self._increment_usage(key, self.burst_window)

        return {"allowed": True}

    async def _check_user_tier_limits(
        self, user_id: str, user_tier: str
    ) -> Dict[str, Any]:
        """
        Check user tier-based limits.

        Args:
            user_id: User identifier
            user_tier: User tier

        Returns:
            Rate limit check result
        """
        tier_limits = self.user_tier_limits.get(
            user_tier, self.user_tier_limits["free"]
        )

        # Check minute limit
        minute_key = f"user_minute:{user_id}"
        minute_usage = await self._get_current_usage(minute_key, 60)
        if minute_usage >= tier_limits["minute"]:
            return {
                "allowed": False,
                "limit_type": "user_tier_minute",
                "current_usage": minute_usage,
                "limit": tier_limits["minute"],
                "retry_after": 60,
                "window": 60,
            }

        # Check hourly limit
        hourly_key = f"user_hourly:{user_id}"
        hourly_usage = await self._get_current_usage(hourly_key, 3600)
        if hourly_usage >= tier_limits["hourly"]:
            return {
                "allowed": False,
                "limit_type": "user_tier_hourly",
                "current_usage": hourly_usage,
                "limit": tier_limits["hourly"],
                "retry_after": 3600,
                "window": 3600,
            }

        # Check daily limit
        daily_key = f"user_daily:{user_id}"
        daily_usage = await self._get_current_usage(daily_key, 86400)
        if daily_usage >= tier_limits["daily"]:
            return {
                "allowed": False,
                "limit_type": "user_tier_daily",
                "current_usage": daily_usage,
                "limit": tier_limits["daily"],
                "retry_after": 86400,
                "window": 86400,
            }

        # Increment all tier usage counters
        await self._increment_usage(minute_key, 60)
        await self._increment_usage(hourly_key, 3600)
        await self._increment_usage(daily_key, 86400)

        return {"allowed": True}

    async def _check_ddos_protection(
        self, client_id: str, request: Request
    ) -> Dict[str, Any]:
        """
        Check for DDoS attack patterns.

        Args:
            client_id: Client identifier
            request: FastAPI request object

        Returns:
            Rate limit check result
        """
        # Check for suspicious patterns
        suspicious_patterns = [
            len(request.url.path) > 1000,  # Very long URLs
            len(dict(request.query_params)) > 50,  # Too many parameters
            request.headers.get("User-Agent", "").lower()
            in ["", "curl", "wget", "python-requests"],  # Bot-like agents
        ]

        if any(suspicious_patterns):
            # Apply stricter limits for suspicious requests
            key = f"suspicious:{client_id}"
            current_usage = await self._get_current_usage(key, 60)

            if current_usage >= 10:  # Much stricter limit
                return {
                    "allowed": False,
                    "limit_type": "ddos_protection",
                    "current_usage": current_usage,
                    "limit": 10,
                    "retry_after": 300,  # 5 minute cooldown
                    "window": 60,
                }

            await self._increment_usage(key, 60)

        return {"allowed": True}

    async def _get_current_usage(self, key: str, window: int) -> int:
        """
        Get current usage count for a key within time window.

        Args:
            key: Rate limit key
            window: Time window in seconds

        Returns:
            Current usage count
        """
        if self.redis_client:
            try:
                # Use Redis sliding window
                current_time = time.time()
                pipe = self.redis_client.pipeline()

                # Remove expired entries
                pipe.zremrangebyscore(key, 0, current_time - window)

                # Count current entries
                pipe.zcard(key)

                results = pipe.execute()
                return results[1] if len(results) > 1 else 0

            except Exception as e:
                logger.error(f"Redis error in get_current_usage: {str(e)}")
                # Fall back to memory store

        # Memory store fallback
        self._cleanup_memory_store()

        if key not in self.memory_store:
            return 0

        current_time = time.time()
        # Remove expired timestamps
        self.memory_store[key] = [
            timestamp
            for timestamp in self.memory_store[key]
            if timestamp > current_time - window
        ]

        return len(self.memory_store[key])

    async def _increment_usage(self, key: str, window: int):
        """
        Increment usage count for a key.

        Args:
            key: Rate limit key
            window: Time window in seconds
        """
        if self.redis_client:
            try:
                current_time = time.time()
                pipe = self.redis_client.pipeline()

                # Add current timestamp
                pipe.zadd(key, {str(current_time): current_time})

                # Set expiry
                pipe.expire(key, window)

                pipe.execute()
                return

            except Exception as e:
                logger.error(f"Redis error in increment_usage: {str(e)}")
                # Fall back to memory store

        # Memory store fallback
        current_time = time.time()

        if key not in self.memory_store:
            self.memory_store[key] = []

        self.memory_store[key].append(current_time)

    def _cleanup_memory_store(self):
        """Clean up expired entries from memory store."""
        current_time = time.time()

        if current_time - self.last_cleanup < self.cleanup_interval:
            return

        self.last_cleanup = current_time

        keys_to_delete = []
        for key, timestamps in self.memory_store.items():
            # Keep only recent timestamps (within 1 day)
            recent_timestamps = [ts for ts in timestamps if ts > current_time - 86400]

            if recent_timestamps:
                self.memory_store[key] = recent_timestamps
            else:
                keys_to_delete.append(key)

        for key in keys_to_delete:
            del self.memory_store[key]


class RedisRateLimiter:
    """Redis-based rate limiter with sliding window"""

    def __init__(self, redis_url: str = "redis://localhost:6379"):
        """
        Initialize rate limiter

        Args:
            redis_url: Redis connection URL
        """
        self.redis_pool = None
        self.redis_url = redis_url

        # Default rate limit rules
        self.rules = {
            "default": RateLimitRule(
                requests=100, window=60
            ),  # 100 requests per minute
            "auth": RateLimitRule(
                requests=10, window=60
            ),  # 10 auth attempts per minute
            "api": RateLimitRule(requests=1000, window=60),  # 1000 API calls per minute
            "upload": RateLimitRule(requests=20, window=60),  # 20 uploads per minute
            "strict": RateLimitRule(requests=30, window=60),  # Strict limit
        }

    async def init_redis(self):
        """Initialize Redis connection pool"""
        try:
            self.redis_pool = redis.ConnectionPool.from_url(self.redis_url)
            logger.info("Redis rate limiter initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Redis for rate limiting: {e}")
            # Fallback to in-memory rate limiting
            self.redis_pool = None

    def add_rule(self, name: str, rule: RateLimitRule):
        """
        Add custom rate limit rule

        Args:
            name: Rule name
            rule: Rate limit rule configuration
        """
        self.rules[name] = rule
        logger.info(f"Added rate limit rule: {name}")


def create_rate_limit_middleware(
    rule_name: str = "default", identifier_func: Optional[Callable] = None
):
    """
    Create rate limiting middleware

    Args:
        rule_name: Name of the rate limit rule to use
        identifier_func: Function to generate custom identifier

    Returns:
        Rate limiting middleware function
    """

    async def rate_limit_middleware(request: Request, call_next):
        """Rate limiting middleware function"""
        try:
            # Get rate limit rule
            rule = rate_limiter.rules.get(rule_name, rate_limiter.rules["default"])

            # Get custom identifier if function provided
            identifier = None
            if identifier_func:
                try:
                    identifier = await identifier_func(request)
                except Exception as e:
                    logger.warning(f"Error getting rate limit identifier: {e}")

            # Check rate limit
            result = await rate_limiter.is_allowed(request, rule, identifier)

            if not result["allowed"]:
                # Rate limit exceeded
                headers = {
                    "X-RateLimit-Limit": str(rule.requests),
                    "X-RateLimit-Window": str(rule.window),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(
                        int(result.get("reset_time", time.time()))
                    ),
                }

                error_response = {
                    "error": "Rate limit exceeded",
                    "message": f"Too many requests. Limit: {rule.requests} per {rule.window} seconds",
                    "retry_after": int(
                        result.get("reset_time", time.time()) - time.time()
                    ),
                }

                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content=error_response,
                    headers=headers,
                )

            # Proceed with request
            response = await call_next(request)

            # Add rate limit headers to response
            response.headers["X-RateLimit-Limit"] = str(rule.requests)
            response.headers["X-RateLimit-Window"] = str(rule.window)
            response.headers["X-RateLimit-Remaining"] = str(result.get("remaining", 0))
            response.headers["X-RateLimit-Reset"] = str(
                int(result.get("reset_time", time.time()))
            )

            return response

        except Exception as e:
            logger.error(f"Rate limiting middleware error: {e}")
            # Continue without rate limiting on error
            return await call_next(request)

    return rate_limit_middleware


# Decorator for route-specific rate limiting
def rate_limit(rule_name: str = "default", identifier_func: Optional[Callable] = None):
    """
    Decorator for applying rate limiting to specific routes

    Args:
        rule_name: Name of the rate limit rule
        identifier_func: Function to generate custom identifier
    """

    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Get request from function arguments
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break

            if not request:
                # If no request found, proceed without rate limiting
                return await func(*args, **kwargs)

            # Apply rate limiting
            rule = rate_limiter.rules.get(rule_name, rate_limiter.rules["default"])

            identifier = None
            if identifier_func:
                try:
                    identifier = await identifier_func(request)
                except Exception as e:
                    logger.warning(f"Error getting rate limit identifier: {e}")

            result = await rate_limiter.is_allowed(request, rule, identifier)

            if not result["allowed"]:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "error": "Rate limit exceeded",
                        "limit": rule.requests,
                        "window": rule.window,
                        "retry_after": int(
                            result.get("reset_time", time.time()) - time.time()
                        ),
                    },
                )

            return await func(*args, **kwargs)

        return wrapper

    return decorator


# Global rate limiter instance
rate_limiter = RedisRateLimiter()


# Common rate limiting functions
async def get_user_identifier(request: Request) -> str:
    """Get user ID for user-based rate limiting"""
    return getattr(request.state, "user_id", "anonymous")


async def get_endpoint_identifier(request: Request) -> str:
    """Get endpoint identifier for endpoint-based rate limiting"""
    return f"{request.method}:{request.url.path}"


# Export main components
__all__ = [
    "RateLimitMiddleware",
    "RedisRateLimiter",
    "RateLimitRule",
    "create_rate_limit_middleware",
    "rate_limit",
    "rate_limiter",
    "get_user_identifier",
    "get_endpoint_identifier",
]

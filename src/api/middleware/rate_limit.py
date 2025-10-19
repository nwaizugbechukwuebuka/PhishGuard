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
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

import redis
from fastapi import HTTPException, Request, status
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


class RateLimiterError(Exception):
    """Rate limiter error"""

    pass


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

    async def get_redis(self) -> Optional[redis.Redis]:
        """Get Redis connection"""
        if not self.redis_pool:
            await self.init_redis()

        if self.redis_pool:
            return redis.Redis(connection_pool=self.redis_pool)
        return None

    def get_key(
        self, request: Request, rule: RateLimitRule, identifier: str = None
    ) -> str:
        """
        Generate rate limit key based on rule configuration

        Args:
            request: FastAPI request object
            rule: Rate limit rule
            identifier: Custom identifier

        Returns:
            Rate limit key
        """
        if identifier:
            return f"ratelimit:{identifier}"

        if rule.key_func == "ip":
            client_ip = self.get_client_ip(request)
            return f"ratelimit:ip:{client_ip}"
        elif rule.key_func == "user":
            # Extract user ID from token or session
            user_id = getattr(request.state, "user_id", "anonymous")
            return f"ratelimit:user:{user_id}"
        elif rule.key_func == "endpoint":
            endpoint = f"{request.method}:{request.url.path}"
            client_ip = self.get_client_ip(request)
            return f"ratelimit:endpoint:{endpoint}:{client_ip}"
        else:
            # Default to IP-based
            client_ip = self.get_client_ip(request)
            return f"ratelimit:default:{client_ip}"

    def get_client_ip(self, request: Request) -> str:
        """
        Extract client IP address from request

        Args:
            request: FastAPI request object

        Returns:
            Client IP address
        """
        # Check for X-Forwarded-For header (load balancer/proxy)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        # Check for X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        # Fallback to client host
        return request.client.host if request.client else "unknown"

    async def is_allowed(
        self, request: Request, rule: RateLimitRule, identifier: str = None
    ) -> Dict[str, Any]:
        """
        Check if request is allowed based on rate limit rules

        Args:
            request: FastAPI request object
            rule: Rate limit rule to apply
            identifier: Custom identifier for rate limiting

        Returns:
            Dictionary with rate limit status and metadata
        """
        redis_client = await self.get_redis()
        key = self.get_key(request, rule, identifier)

        if not redis_client:
            # Fallback to in-memory rate limiting (basic implementation)
            return await self._in_memory_rate_limit(key, rule)

        try:
            current_time = time.time()
            window_start = current_time - rule.window

            # Use Redis sorted set for sliding window
            async with redis_client.pipeline() as pipe:
                # Remove expired entries
                await pipe.zremrangebyscore(key, 0, window_start)

                # Count current requests in window
                await pipe.zcard(key)

                # Add current request
                await pipe.zadd(key, {str(current_time): current_time})

                # Set expiration
                await pipe.expire(key, rule.window)

                results = await pipe.execute()

            current_requests = results[1]  # Count from zcard

            # Check burst allowance if configured
            if rule.burst and current_requests > rule.burst:
                return {
                    "allowed": False,
                    "requests": current_requests,
                    "limit": rule.requests,
                    "window": rule.window,
                    "reset_time": current_time + rule.window,
                    "reason": "burst_limit_exceeded",
                }

            # Check regular limit
            if current_requests > rule.requests:
                return {
                    "allowed": False,
                    "requests": current_requests,
                    "limit": rule.requests,
                    "window": rule.window,
                    "reset_time": current_time + rule.window,
                    "reason": "rate_limit_exceeded",
                }

            return {
                "allowed": True,
                "requests": current_requests,
                "limit": rule.requests,
                "window": rule.window,
                "remaining": rule.requests - current_requests,
                "reset_time": current_time + rule.window,
            }

        except Exception as e:
            logger.error(f"Rate limiting error: {e}")
            # Allow request on error (fail open)
            return {"allowed": True, "error": str(e), "fallback": True}

    async def _in_memory_rate_limit(
        self, key: str, rule: RateLimitRule
    ) -> Dict[str, Any]:
        """
        Fallback in-memory rate limiting

        Args:
            key: Rate limit key
            rule: Rate limit rule

        Returns:
            Rate limit status
        """
        # This is a basic implementation - in production you'd want a more sophisticated
        # in-memory store with TTL and proper cleanup
        if not hasattr(self, "_memory_store"):
            self._memory_store = {}

        current_time = time.time()
        window_start = current_time - rule.window

        # Clean up expired entries
        if key in self._memory_store:
            self._memory_store[key] = [
                timestamp
                for timestamp in self._memory_store[key]
                if timestamp > window_start
            ]
        else:
            self._memory_store[key] = []

        # Add current request
        self._memory_store[key].append(current_time)

        current_requests = len(self._memory_store[key])

        if current_requests > rule.requests:
            return {
                "allowed": False,
                "requests": current_requests,
                "limit": rule.requests,
                "window": rule.window,
                "reset_time": current_time + rule.window,
                "reason": "rate_limit_exceeded",
                "fallback": True,
            }

        return {
            "allowed": True,
            "requests": current_requests,
            "limit": rule.requests,
            "window": rule.window,
            "remaining": rule.requests - current_requests,
            "reset_time": current_time + rule.window,
            "fallback": True,
        }

    async def reset_limit(
        self, request: Request, rule: RateLimitRule, identifier: str = None
    ):
        """
        Reset rate limit for a specific key

        Args:
            request: FastAPI request object
            rule: Rate limit rule
            identifier: Custom identifier
        """
        redis_client = await self.get_redis()
        if not redis_client:
            return

        key = self.get_key(request, rule, identifier)
        try:
            await redis_client.delete(key)
            logger.info(f"Rate limit reset for key: {key}")
        except Exception as e:
            logger.error(f"Error resetting rate limit: {e}")

    def add_rule(self, name: str, rule: RateLimitRule):
        """
        Add custom rate limit rule

        Args:
            name: Rule name
            rule: Rate limit rule configuration
        """
        self.rules[name] = rule
        logger.info(f"Added rate limit rule: {name}")


# Global rate limiter instance
rate_limiter = RedisRateLimiter()


def create_rate_limit_middleware(
    rule_name: str = "default", identifier_func: Callable = None
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
def rate_limit(rule_name: str = "default", identifier_func: Callable = None):
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


# Common rate limiting functions
async def get_user_identifier(request: Request) -> str:
    """Get user ID for user-based rate limiting"""
    return getattr(request.state, "user_id", "anonymous")


async def get_endpoint_identifier(request: Request) -> str:
    """Get endpoint identifier for endpoint-based rate limiting"""
    return f"{request.method}:{request.url.path}"


# Export main components
__all__ = [
    "RedisRateLimiter",
    "RateLimitRule",
    "RateLimiterError",
    "create_rate_limit_middleware",
    "rate_limit",
    "rate_limiter",
    "get_user_identifier",
    "get_endpoint_identifier",
]

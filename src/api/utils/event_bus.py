"""
Event Bus System for PhishGuard

Provides event-driven architecture for decoupled communication
between services, enabling real-time notifications and system integration.
"""

import asyncio
import json
import uuid
from datetime import datetime
from typing import Dict, List, Any, Callable, Optional, Set
from enum import Enum
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict

from .logger import get_logger
from .config import get_settings

logger = get_logger(__name__)
settings = get_settings()

class EventPriority(Enum):
    """Event priority levels."""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class Event:
    """Event data structure."""
    id: str
    type: str
    data: Dict[str, Any]
    timestamp: datetime
    source: str
    priority: EventPriority = EventPriority.NORMAL
    correlation_id: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3

class EventBus:
    """
    Centralized event bus for application-wide event handling.
    
    Provides pub/sub messaging, event routing, and handler management
    with support for async operations and error handling.
    """
    
    def __init__(self):
        """Initialize the event bus."""
        self._handlers: Dict[str, List[Callable]] = {}
        self._middleware: List[Callable] = []
        self._event_history: List[Event] = []
        self._max_history = 1000
        self._running = False
        self._event_queue = asyncio.Queue() if hasattr(asyncio, 'Queue') else None
        self._executor = ThreadPoolExecutor(max_workers=4)
        self._lock = threading.Lock()
        
    async def emit(
        self,
        event_type: str,
        data: Dict[str, Any],
        source: str = "unknown",
        priority: EventPriority = EventPriority.NORMAL,
        correlation_id: Optional[str] = None
    ) -> str:
        """
        Emit an event to all registered handlers.
        
        Args:
            event_type: Type/name of the event
            data: Event payload data
            source: Source component/service
            priority: Event priority level
            correlation_id: Optional correlation ID for tracking
            
        Returns:
            Event ID
        """
        try:
            event = Event(
                id=str(uuid.uuid4()),
                type=event_type,
                data=data,
                timestamp=datetime.utcnow(),
                source=source,
                priority=priority,
                correlation_id=correlation_id
            )
            
            # Apply middleware
            for middleware in self._middleware:
                try:
                    event = await self._run_middleware(middleware, event)
                    if not event:  # Middleware can filter out events
                        return ""
                except Exception as e:
                    logger.error(f"Middleware error for event {event.id}: {str(e)}")
            
            # Add to history
            self._add_to_history(event)
            
            # Emit to handlers
            await self._emit_to_handlers(event)
            
            logger.debug(f"Event emitted: {event_type} ({event.id})")
            return event.id
            
        except Exception as e:
            logger.error(f"Error emitting event {event_type}: {str(e)}")
            return ""
    
    def subscribe(
        self,
        event_type: str,
        handler: Callable,
        priority: bool = False
    ) -> str:
        """
        Subscribe to events of a specific type.
        
        Args:
            event_type: Event type to subscribe to
            handler: Handler function to call
            priority: Whether to add handler at the beginning
            
        Returns:
            Subscription ID
        """
        try:
            with self._lock:
                if event_type not in self._handlers:
                    self._handlers[event_type] = []
                
                if priority:
                    self._handlers[event_type].insert(0, handler)
                else:
                    self._handlers[event_type].append(handler)
            
            subscription_id = str(uuid.uuid4())
            logger.debug(f"Handler subscribed to {event_type}: {subscription_id}")
            return subscription_id
            
        except Exception as e:
            logger.error(f"Error subscribing to {event_type}: {str(e)}")
            return ""
    
    def unsubscribe(self, event_type: str, handler: Callable) -> bool:
        """
        Unsubscribe a handler from an event type.
        
        Args:
            event_type: Event type
            handler: Handler to remove
            
        Returns:
            Success status
        """
        try:
            with self._lock:
                if event_type in self._handlers and handler in self._handlers[event_type]:
                    self._handlers[event_type].remove(handler)
                    return True
            return False
            
        except Exception as e:
            logger.error(f"Error unsubscribing from {event_type}: {str(e)}")
            return False
    
    def add_middleware(self, middleware: Callable):
        """
        Add middleware for event processing.
        
        Args:
            middleware: Middleware function
        """
        try:
            self._middleware.append(middleware)
            logger.debug("Middleware added to event bus")
            
        except Exception as e:
            logger.error(f"Error adding middleware: {str(e)}")
    
    async def _emit_to_handlers(self, event: Event):
        """Emit event to all registered handlers."""
        try:
            handlers = self._handlers.get(event.type, [])
            wildcard_handlers = self._handlers.get("*", [])
            all_handlers = handlers + wildcard_handlers
            
            if not all_handlers:
                logger.debug(f"No handlers for event type: {event.type}")
                return
            
            # Execute handlers concurrently
            tasks = []
            for handler in all_handlers:
                task = asyncio.create_task(self._execute_handler(handler, event))
                tasks.append(task)
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            
        except Exception as e:
            logger.error(f"Error emitting to handlers for event {event.id}: {str(e)}")
    
    async def _execute_handler(self, handler: Callable, event: Event):
        """Execute a single event handler."""
        try:
            if asyncio.iscoroutinefunction(handler):
                await handler(event)
            else:
                # Run sync handler in thread pool
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(self._executor, handler, event)
                
        except Exception as e:
            logger.error(f"Handler error for event {event.id}: {str(e)}")
            
            # Retry for critical events
            if event.priority == EventPriority.CRITICAL and event.retry_count < event.max_retries:
                event.retry_count += 1
                await asyncio.sleep(2 ** event.retry_count)  # Exponential backoff
                await self._execute_handler(handler, event)
    
    async def _run_middleware(self, middleware: Callable, event: Event) -> Optional[Event]:
        """Run middleware on an event."""
        try:
            if asyncio.iscoroutinefunction(middleware):
                return await middleware(event)
            else:
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(self._executor, middleware, event)
                
        except Exception as e:
            logger.error(f"Middleware execution error: {str(e)}")
            return event  # Return original event on error
    
    def _add_to_history(self, event: Event):
        """Add event to history with size management."""
        try:
            with self._lock:
                self._event_history.append(event)
                
                # Maintain history size
                if len(self._event_history) > self._max_history:
                    self._event_history = self._event_history[-self._max_history:]
                    
        except Exception as e:
            logger.error(f"Error adding event to history: {str(e)}")
    
    def get_event_history(
        self,
        event_type: Optional[str] = None,
        limit: Optional[int] = None,
        since: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Get event history with optional filtering.
        
        Args:
            event_type: Filter by event type
            limit: Maximum events to return
            since: Only events after this timestamp
            
        Returns:
            List of event data
        """
        try:
            with self._lock:
                events = self._event_history.copy()
            
            # Apply filters
            if event_type:
                events = [e for e in events if e.type == event_type]
            
            if since:
                events = [e for e in events if e.timestamp > since]
            
            # Sort by timestamp (newest first)
            events.sort(key=lambda e: e.timestamp, reverse=True)
            
            # Apply limit
            if limit:
                events = events[:limit]
            
            # Convert to dict format
            return [
                {
                    "id": event.id,
                    "type": event.type,
                    "data": event.data,
                    "timestamp": event.timestamp.isoformat(),
                    "source": event.source,
                    "priority": event.priority.name,
                    "correlation_id": event.correlation_id,
                    "retry_count": event.retry_count
                }
                for event in events
            ]
            
        except Exception as e:
            logger.error(f"Error getting event history: {str(e)}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get event bus statistics.
        
        Returns:
            Statistics data
        """
        try:
            with self._lock:
                total_events = len(self._event_history)
                event_types = {}
                sources = {}
                priorities = {}
                
                for event in self._event_history:
                    # Count by type
                    event_types[event.type] = event_types.get(event.type, 0) + 1
                    
                    # Count by source
                    sources[event.source] = sources.get(event.source, 0) + 1
                    
                    # Count by priority
                    priority_name = event.priority.name
                    priorities[priority_name] = priorities.get(priority_name, 0) + 1
                
                return {
                    "total_events": total_events,
                    "total_handlers": sum(len(handlers) for handlers in self._handlers.values()),
                    "event_types": event_types,
                    "sources": sources,
                    "priorities": priorities,
                    "middleware_count": len(self._middleware),
                    "subscription_types": list(self._handlers.keys())
                }
                
        except Exception as e:
            logger.error(f"Error getting statistics: {str(e)}")
            return {}
    
    def clear_history(self):
        """Clear event history."""
        try:
            with self._lock:
                self._event_history.clear()
            logger.info("Event history cleared")
            
        except Exception as e:
            logger.error(f"Error clearing history: {str(e)}")

# Global event bus instance
_event_bus = None

def get_event_bus() -> EventBus:
    """Get the global event bus instance."""
    global _event_bus
    if _event_bus is None:
        _event_bus = EventBus()
    return _event_bus

# Common event type constants
class EventTypes:
    """Common event type definitions."""
    
    # Security events
    THREAT_DETECTED = "threat_detected"
    EMAIL_QUARANTINED = "email_quarantined"
    EMAIL_RELEASED = "email_released"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    
    # User events
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    
    # System events
    SYSTEM_START = "system_start"
    SYSTEM_SHUTDOWN = "system_shutdown"
    SYSTEM_ERROR = "system_error"
    BACKUP_COMPLETED = "backup_completed"
    
    # Notification events
    NOTIFICATION_SENT = "notification_sent"
    NOTIFICATION_FAILED = "notification_failed"
    ALERT_TRIGGERED = "alert_triggered"
    
    # Simulation events
    SIMULATION_STARTED = "simulation_started"
    SIMULATION_COMPLETED = "simulation_completed"
    SIMULATION_USER_ACTION = "simulation_user_action"
    
    # Compliance events
    COMPLIANCE_VIOLATION = "compliance_violation"
    AUDIT_LOG_CREATED = "audit_log_created"
    REPORT_GENERATED = "report_generated"

# Convenience functions for common operations
async def emit_threat_detected(threat_data: Dict[str, Any], source: str = "detection_engine"):
    """Emit threat detected event."""
    event_bus = get_event_bus()
    return await event_bus.emit(
        EventTypes.THREAT_DETECTED,
        threat_data,
        source=source,
        priority=EventPriority.HIGH
    )

async def emit_user_action(action_type: str, user_id: str, details: Dict[str, Any]):
    """Emit user action event."""
    event_bus = get_event_bus()
    return await event_bus.emit(
        f"user_{action_type}",
        {
            "user_id": user_id,
            "action": action_type,
            "details": details
        },
        source="user_service"
    )

async def emit_system_event(event_type: str, details: Dict[str, Any], priority: EventPriority = EventPriority.NORMAL):
    """Emit system event."""
    event_bus = get_event_bus()
    return await event_bus.emit(
        event_type,
        details,
        source="system",
        priority=priority
    )

# Middleware functions
async def logging_middleware(event: Event) -> Event:
    """Middleware to log all events."""
    try:
        logger.info(f"Event: {event.type} from {event.source} at {event.timestamp}")
        return event
    except Exception as e:
        logger.error(f"Logging middleware error: {str(e)}")
        return event

async def audit_middleware(event: Event) -> Event:
    """Middleware to create audit logs for important events."""
    try:
        # In production, this would create actual audit logs
        if event.priority in [EventPriority.HIGH, EventPriority.CRITICAL]:
            logger.info(f"Audit: High priority event {event.type} logged")
        return event
    except Exception as e:
        logger.error(f"Audit middleware error: {str(e)}")
        return event

def setup_default_event_bus() -> EventBus:
    """Setup event bus with default middleware and handlers."""
    try:
        event_bus = get_event_bus()
        
        # Add default middleware
        event_bus.add_middleware(logging_middleware)
        event_bus.add_middleware(audit_middleware)
        
        # Subscribe to system events
        event_bus.subscribe("system_error", _handle_system_error)
        event_bus.subscribe("compliance_violation", _handle_compliance_violation)
        
        logger.info("Default event bus configured")
        return event_bus
        
    except Exception as e:
        logger.error(f"Error setting up default event bus: {str(e)}")
        return get_event_bus()

def _handle_system_error(event: Event):
    """Handle system error events."""
    try:
        logger.error(f"System error event: {event.data}")
        # In production, this might trigger alerts, notifications, etc.
    except Exception as e:
        logger.error(f"Error handling system error event: {str(e)}")

def _handle_compliance_violation(event: Event):
    """Handle compliance violation events."""
    try:
        logger.warning(f"Compliance violation: {event.data}")
        # In production, this might trigger compliance workflows
    except Exception as e:
        logger.error(f"Error handling compliance violation event: {str(e)}")

# Initialize default event bus when module is loaded
try:
    setup_default_event_bus()
except Exception as e:
    logger.error(f"Failed to initialize default event bus: {str(e)}")

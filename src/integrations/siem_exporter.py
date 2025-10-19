"""
SIEM Export Integration for PhishGuard
Exports threat data to Security Information and Event Management (SIEM) systems
"""

import asyncio
import json
import os
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Union

import aiohttp

from src.api.models.audit_log import AuditLog
from src.api.models.email import Email
from src.api.utils.logger import get_logger

logger = get_logger(__name__)


class SIEMFormat(Enum):
    """Supported SIEM export formats"""

    CEF = "cef"  # Common Event Format
    LEEF = "leef"  # Log Event Extended Format
    JSON = "json"  # JSON format
    SYSLOG = "syslog"  # Syslog format
    SPLUNK = "splunk"  # Splunk format


class SIEMExportError(Exception):
    """Custom exception for SIEM export errors"""

    pass


class SIEMExporter:
    """SIEM integration for exporting threat intelligence and logs"""

    def __init__(
        self,
        siem_url: str = None,
        api_key: str = None,
        format_type: SIEMFormat = SIEMFormat.JSON,
        verify_ssl: bool = True,
    ):
        """
        Initialize SIEM exporter

        Args:
            siem_url: SIEM system endpoint URL
            api_key: API key for authentication
            format_type: Export format
            verify_ssl: Whether to verify SSL certificates
        """
        self.siem_url = siem_url or os.getenv("SIEM_URL")
        self.api_key = api_key or os.getenv("SIEM_API_KEY")
        self.format_type = format_type
        self.verify_ssl = verify_ssl

        # SIEM-specific configurations
        self.vendor = os.getenv("SIEM_VENDOR", "PhishGuard")
        self.product = os.getenv("SIEM_PRODUCT", "Email Threat Detection")
        self.version = os.getenv("SIEM_VERSION", "1.0")

        if not self.siem_url:
            logger.warning("SIEM URL not configured")

    def format_threat_event_cef(
        self, email: Email, threat_details: Dict[str, Any]
    ) -> str:
        """
        Format threat event in CEF (Common Event Format)

        Args:
            email: Email object
            threat_details: Threat analysis details

        Returns:
            CEF formatted string
        """
        try:
            # CEF Header
            cef_version = "CEF:0"
            device_vendor = self.vendor
            device_product = self.product
            device_version = self.version
            signature_id = "PHISH001"
            name = "Phishing Email Detected"
            severity = self._map_threat_level_to_cef_severity(
                threat_details.get("threat_level", "low")
            )

            # CEF Extensions
            extensions = []

            # Basic email information
            extensions.append(f"src={email.sender_email}")
            extensions.append(f"dst={email.recipient_email}")
            extensions.append(f"msg={email.subject or 'No Subject'}")
            extensions.append(f"act=detected")

            # Threat-specific information
            risk_score = threat_details.get("risk_score", 0.0)
            extensions.append(f"cs1={risk_score:.3f}")
            extensions.append("cs1Label=Risk Score")

            threat_level = threat_details.get("threat_level", "low")
            extensions.append(f"cs2={threat_level}")
            extensions.append("cs2Label=Threat Level")

            # Email metadata
            extensions.append(f"cs3={email.source_platform}")
            extensions.append("cs3Label=Email Platform")

            extensions.append(f"cs4={email.platform_message_id}")
            extensions.append("cs4Label=Message ID")

            # Timestamps
            received_time = int(email.received_date.timestamp() * 1000)
            extensions.append(f"rt={received_time}")

            # Additional threat indicators
            indicators = threat_details.get("indicators", [])
            if indicators:
                extensions.append(f"cs5={', '.join(indicators[:3])}")
                extensions.append("cs5Label=Threat Indicators")

            # Build full CEF string
            cef_header = f"{cef_version}|{device_vendor}|{device_product}|{device_version}|{signature_id}|{name}|{severity}"
            cef_extensions = "|" + " ".join(extensions) if extensions else ""

            return cef_header + cef_extensions

        except Exception as e:
            logger.error(f"Error formatting CEF event: {e}")
            return ""

    def format_threat_event_leef(
        self, email: Email, threat_details: Dict[str, Any]
    ) -> str:
        """
        Format threat event in LEEF (Log Event Extended Format)

        Args:
            email: Email object
            threat_details: Threat analysis details

        Returns:
            LEEF formatted string
        """
        try:
            # LEEF Header
            leef_version = "LEEF:2.0"
            vendor = self.vendor
            product = self.product
            version = self.version
            event_id = "PHISH001"
            delimiter = "|"

            # LEEF Attributes
            attributes = []

            # Basic information
            attributes.append(f"devTime={email.received_date.isoformat()}")
            attributes.append(f"src={email.sender_email}")
            attributes.append(f"dst={email.recipient_email}")
            attributes.append(f"usrName={email.recipient_email}")

            # Threat information
            attributes.append(f"cat=Phishing")
            attributes.append(
                f"sev={self._map_threat_level_to_leef_severity(threat_details.get('threat_level', 'low'))}"
            )
            attributes.append(f"msg={email.subject or 'No Subject'}")

            # Custom attributes
            risk_score = threat_details.get("risk_score", 0.0)
            attributes.append(f"riskScore={risk_score:.3f}")
            attributes.append(
                f"threatLevel={threat_details.get('threat_level', 'low')}"
            )
            attributes.append(f"platform={email.source_platform}")
            attributes.append(f"messageId={email.platform_message_id}")
            attributes.append(f"quarantined={str(email.is_quarantined).lower()}")

            # Threat indicators
            indicators = threat_details.get("indicators", [])
            if indicators:
                attributes.append(f"indicators={','.join(indicators)}")

            # Build LEEF string
            leef_header = f"{leef_version}{delimiter}{vendor}{delimiter}{product}{delimiter}{version}{delimiter}{event_id}{delimiter}"
            leef_attributes = "\t".join(attributes)

            return leef_header + leef_attributes

        except Exception as e:
            logger.error(f"Error formatting LEEF event: {e}")
            return ""

    def format_threat_event_json(
        self, email: Email, threat_details: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Format threat event in JSON format

        Args:
            email: Email object
            threat_details: Threat analysis details

        Returns:
            JSON formatted dictionary
        """
        try:
            return {
                "timestamp": email.received_date.isoformat(),
                "event_type": "phishing_detection",
                "severity": threat_details.get("threat_level", "low"),
                "source": {
                    "vendor": self.vendor,
                    "product": self.product,
                    "version": self.version,
                },
                "email": {
                    "id": email.id,
                    "sender": email.sender_email,
                    "recipient": email.recipient_email,
                    "subject": email.subject,
                    "platform": email.source_platform,
                    "platform_message_id": email.platform_message_id,
                    "received_date": email.received_date.isoformat(),
                    "has_attachments": email.has_attachments,
                    "attachment_count": email.attachment_count,
                },
                "threat_analysis": {
                    "is_phishing": threat_details.get("is_phishing", False),
                    "risk_score": threat_details.get("risk_score", 0.0),
                    "threat_level": threat_details.get("threat_level", "low"),
                    "confidence": threat_details.get("confidence", 0.0),
                    "indicators": threat_details.get("indicators", []),
                    "detection_methods": threat_details.get("detection_methods", []),
                },
                "actions": {
                    "quarantined": email.is_quarantined,
                    "status": email.status,
                },
                "metadata": {
                    "organization": os.getenv("ORGANIZATION_NAME", "PhishGuard"),
                    "environment": os.getenv("ENVIRONMENT", "production"),
                    "event_id": f"phish_{email.id}_{int(datetime.now().timestamp())}",
                },
            }

        except Exception as e:
            logger.error(f"Error formatting JSON event: {e}")
            return {}

    def format_threat_event_syslog(
        self, email: Email, threat_details: Dict[str, Any]
    ) -> str:
        """
        Format threat event in Syslog format (RFC 5424)

        Args:
            email: Email object
            threat_details: Threat analysis details

        Returns:
            Syslog formatted string
        """
        try:
            # Syslog priority (facility 16 = local0, severity based on threat level)
            facility = 16  # local0
            severity_map = {"low": 6, "medium": 4, "high": 3, "critical": 2}
            severity = severity_map.get(threat_details.get("threat_level", "low"), 6)
            priority = facility * 8 + severity

            # Timestamp in RFC 3339 format
            timestamp = email.received_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            # Hostname
            hostname = os.getenv("HOSTNAME", "phishguard")

            # App name and process ID
            app_name = "phishguard"
            procid = os.getpid()

            # Message ID
            msgid = "PHISH001"

            # Structured data
            structured_data = (
                f"[phishguard@32473 "
                f'riskScore="{threat_details.get("risk_score", 0.0):.3f}" '
                f'threatLevel="{threat_details.get("threat_level", "low")}" '
                f'sender="{email.sender_email}" '
                f'recipient="{email.recipient_email}" '
                f'platform="{email.source_platform}" '
                f'quarantined="{str(email.is_quarantined).lower()}"]'
            )

            # Message
            message = f"Phishing email detected: {email.subject or 'No Subject'}"

            # Build syslog message
            syslog_msg = f"<{priority}>1 {timestamp} {hostname} {app_name} {procid} {msgid} {structured_data} {message}"

            return syslog_msg

        except Exception as e:
            logger.error(f"Error formatting Syslog event: {e}")
            return ""

    def _map_threat_level_to_cef_severity(self, threat_level: str) -> int:
        """Map threat level to CEF severity (0-10)"""
        mapping = {"low": 3, "medium": 6, "high": 8, "critical": 10}
        return mapping.get(threat_level.lower(), 3)

    def _map_threat_level_to_leef_severity(self, threat_level: str) -> int:
        """Map threat level to LEEF severity (1-10)"""
        mapping = {"low": 3, "medium": 6, "high": 8, "critical": 10}
        return mapping.get(threat_level.lower(), 3)

    async def export_threat_event(
        self, email: Email, threat_details: Dict[str, Any]
    ) -> bool:
        """
        Export threat event to SIEM system

        Args:
            email: Email object
            threat_details: Threat analysis details

        Returns:
            bool: True if exported successfully
        """
        if not self.siem_url:
            logger.warning("SIEM URL not configured, skipping export")
            return False

        try:
            # Format event based on configured format
            if self.format_type == SIEMFormat.CEF:
                event_data = self.format_threat_event_cef(email, threat_details)
                content_type = "text/plain"
            elif self.format_type == SIEMFormat.LEEF:
                event_data = self.format_threat_event_leef(email, threat_details)
                content_type = "text/plain"
            elif self.format_type == SIEMFormat.JSON:
                event_data = self.format_threat_event_json(email, threat_details)
                content_type = "application/json"
            elif self.format_type == SIEMFormat.SYSLOG:
                event_data = self.format_threat_event_syslog(email, threat_details)
                content_type = "text/plain"
            else:
                # Default to JSON
                event_data = self.format_threat_event_json(email, threat_details)
                content_type = "application/json"

            if not event_data:
                logger.error("Failed to format SIEM event data")
                return False

            # Prepare headers
            headers = {
                "Content-Type": content_type,
                "User-Agent": f"PhishGuard/{self.version}",
            }

            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            # Send to SIEM
            connector = aiohttp.TCPConnector(verify_ssl=self.verify_ssl)
            async with aiohttp.ClientSession(connector=connector) as session:
                if self.format_type == SIEMFormat.JSON:
                    async with session.post(
                        self.siem_url, json=event_data, headers=headers
                    ) as response:
                        if response.status in [200, 201, 202]:
                            logger.info(f"Threat event exported to SIEM: {email.id}")
                            return True
                        else:
                            error_text = await response.text()
                            logger.error(
                                f"SIEM export failed: {response.status} - {error_text}"
                            )
                            return False
                else:
                    async with session.post(
                        self.siem_url, data=event_data, headers=headers
                    ) as response:
                        if response.status in [200, 201, 202]:
                            logger.info(f"Threat event exported to SIEM: {email.id}")
                            return True
                        else:
                            error_text = await response.text()
                            logger.error(
                                f"SIEM export failed: {response.status} - {error_text}"
                            )
                            return False

        except aiohttp.ClientError as e:
            logger.error(f"SIEM export client error: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error in SIEM export: {e}")
            return False

    async def export_audit_log(self, audit_log: AuditLog) -> bool:
        """
        Export audit log event to SIEM

        Args:
            audit_log: Audit log entry

        Returns:
            bool: True if exported successfully
        """
        if not self.siem_url:
            logger.warning("SIEM URL not configured, skipping audit log export")
            return False

        try:
            # Format audit log as JSON
            audit_data = {
                "timestamp": audit_log.timestamp.isoformat(),
                "event_type": "audit_log",
                "severity": "info",
                "source": {
                    "vendor": self.vendor,
                    "product": self.product,
                    "version": self.version,
                },
                "audit": {
                    "id": audit_log.id,
                    "user_id": audit_log.user_id,
                    "action": audit_log.action,
                    "resource_type": audit_log.resource_type,
                    "resource_id": audit_log.resource_id,
                    "ip_address": audit_log.ip_address,
                    "user_agent": audit_log.user_agent,
                    "details": audit_log.details,
                },
                "metadata": {
                    "organization": os.getenv("ORGANIZATION_NAME", "PhishGuard"),
                    "environment": os.getenv("ENVIRONMENT", "production"),
                    "event_id": f"audit_{audit_log.id}_{int(datetime.now().timestamp())}",
                },
            }

            # Export to SIEM
            headers = {
                "Content-Type": "application/json",
                "User-Agent": f"PhishGuard/{self.version}",
            }

            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            connector = aiohttp.TCPConnector(verify_ssl=self.verify_ssl)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.post(
                    self.siem_url, json=audit_data, headers=headers
                ) as response:
                    if response.status in [200, 201, 202]:
                        logger.info(f"Audit log exported to SIEM: {audit_log.id}")
                        return True
                    else:
                        error_text = await response.text()
                        logger.error(
                            f"SIEM audit export failed: {response.status} - {error_text}"
                        )
                        return False

        except Exception as e:
            logger.error(f"Error exporting audit log to SIEM: {e}")
            return False

    async def export_batch_events(self, events: List[Dict[str, Any]]) -> bool:
        """
        Export multiple events in batch

        Args:
            events: List of event dictionaries

        Returns:
            bool: True if exported successfully
        """
        if not self.siem_url or not events:
            return False

        try:
            # Prepare batch data
            batch_data = {
                "events": events,
                "metadata": {
                    "batch_size": len(events),
                    "timestamp": datetime.now().isoformat(),
                    "source": {
                        "vendor": self.vendor,
                        "product": self.product,
                        "version": self.version,
                    },
                },
            }

            headers = {
                "Content-Type": "application/json",
                "User-Agent": f"PhishGuard/{self.version}",
            }

            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            connector = aiohttp.TCPConnector(verify_ssl=self.verify_ssl)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.post(
                    f"{self.siem_url}/batch", json=batch_data, headers=headers
                ) as response:
                    if response.status in [200, 201, 202]:
                        logger.info(f"Batch of {len(events)} events exported to SIEM")
                        return True
                    else:
                        error_text = await response.text()
                        logger.error(
                            f"SIEM batch export failed: {response.status} - {error_text}"
                        )
                        return False

        except Exception as e:
            logger.error(f"Error in SIEM batch export: {e}")
            return False

    def is_configured(self) -> bool:
        """
        Check if SIEM integration is properly configured

        Returns:
            bool: True if configured
        """
        return bool(self.siem_url)


# Utility functions for SIEM integration
async def create_siem_exporter(
    format_type: SIEMFormat = SIEMFormat.JSON,
) -> SIEMExporter:
    """Create SIEM exporter with specified format"""
    return SIEMExporter(format_type=format_type)


async def export_threat_to_siem(email: Email, threat_details: Dict[str, Any]) -> bool:
    """Convenience function to export threat to SIEM"""
    exporter = await create_siem_exporter()
    if exporter.is_configured():
        return await exporter.export_threat_event(email, threat_details)
    return False

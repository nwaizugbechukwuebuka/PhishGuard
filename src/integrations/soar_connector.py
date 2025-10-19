"""
SOAR (Security Orchestration, Automation and Response) Connector for PhishGuard
Integrates with SOAR platforms for automated incident response and orchestration
"""

import asyncio
import json
import os
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Union

import aiohttp

from src.api.models.email import Email
from src.api.models.user import User
from src.api.utils.logger import get_logger

logger = get_logger(__name__)


class SOARPlatform(Enum):
    """Supported SOAR platforms"""

    PHANTOM = "phantom"
    DEMISTO = "demisto"
    SIEMPLIFY = "siemplify"
    RESILIENT = "resilient"
    GENERIC = "generic"


class IncidentSeverity(Enum):
    """Incident severity levels"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SOARConnectorError(Exception):
    """Custom exception for SOAR connector errors"""

    pass


class SOARConnector:
    """SOAR platform integration for automated incident response"""

    def __init__(
        self,
        platform: SOARPlatform = SOARPlatform.GENERIC,
        base_url: str = None,
        api_key: str = None,
        username: str = None,
        password: str = None,
        verify_ssl: bool = True,
    ):
        """
        Initialize SOAR connector

        Args:
            platform: SOAR platform type
            base_url: SOAR platform base URL
            api_key: API key for authentication
            username: Username for authentication
            password: Password for authentication
            verify_ssl: Whether to verify SSL certificates
        """
        self.platform = platform
        self.base_url = base_url or os.getenv("SOAR_BASE_URL")
        self.api_key = api_key or os.getenv("SOAR_API_KEY")
        self.username = username or os.getenv("SOAR_USERNAME")
        self.password = password or os.getenv("SOAR_PASSWORD")
        self.verify_ssl = verify_ssl

        # Platform-specific settings
        self.tenant_id = os.getenv("SOAR_TENANT_ID")
        self.organization = os.getenv("ORGANIZATION_NAME", "PhishGuard")

        if not self.base_url:
            logger.warning("SOAR base URL not configured")

    def _get_auth_headers(self) -> Dict[str, str]:
        """
        Get authentication headers based on platform

        Returns:
            Authentication headers
        """
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "PhishGuard-SOAR-Connector/1.0",
        }

        if self.api_key:
            if self.platform == SOARPlatform.PHANTOM:
                headers["ph-auth-token"] = self.api_key
            elif self.platform == SOARPlatform.DEMISTO:
                headers["Authorization"] = self.api_key
            elif self.platform == SOARPlatform.SIEMPLIFY:
                headers["AppKey"] = self.api_key
            else:
                headers["Authorization"] = f"Bearer {self.api_key}"

        return headers

    async def create_incident(
        self,
        email: Email,
        threat_details: Dict[str, Any],
        severity: IncidentSeverity = IncidentSeverity.MEDIUM,
        assignee: str = None,
    ) -> Optional[str]:
        """
        Create incident in SOAR platform

        Args:
            email: Email object that triggered the incident
            threat_details: Threat analysis details
            severity: Incident severity
            assignee: User to assign the incident to

        Returns:
            Incident ID if created successfully
        """
        if not self.base_url:
            logger.warning("SOAR base URL not configured, skipping incident creation")
            return None

        try:
            # Prepare incident data based on platform
            if self.platform == SOARPlatform.PHANTOM:
                incident_data = await self._create_phantom_incident(
                    email, threat_details, severity, assignee
                )
                endpoint = "/rest/container"
            elif self.platform == SOARPlatform.DEMISTO:
                incident_data = await self._create_demisto_incident(
                    email, threat_details, severity, assignee
                )
                endpoint = "/incident"
            elif self.platform == SOARPlatform.SIEMPLIFY:
                incident_data = await self._create_siemplify_incident(
                    email, threat_details, severity, assignee
                )
                endpoint = "/external/v1/cases"
            elif self.platform == SOARPlatform.RESILIENT:
                incident_data = await self._create_resilient_incident(
                    email, threat_details, severity, assignee
                )
                endpoint = "/incidents"
            else:
                # Generic format
                incident_data = await self._create_generic_incident(
                    email, threat_details, severity, assignee
                )
                endpoint = "/incidents"

            # Send request to SOAR platform
            headers = self._get_auth_headers()
            connector = aiohttp.TCPConnector(verify_ssl=self.verify_ssl)

            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.post(
                    f"{self.base_url}{endpoint}", json=incident_data, headers=headers
                ) as response:
                    if response.status in [200, 201]:
                        result = await response.json()
                        incident_id = self._extract_incident_id(result)

                        if incident_id:
                            logger.info(
                                f"SOAR incident created: {incident_id} for email {email.id}"
                            )
                            # Create artifacts/evidence for the incident
                            await self._create_incident_artifacts(
                                incident_id, email, threat_details
                            )
                            return incident_id
                        else:
                            logger.error(
                                "Could not extract incident ID from SOAR response"
                            )
                            return None
                    else:
                        error_text = await response.text()
                        logger.error(
                            f"SOAR incident creation failed: {response.status} - {error_text}"
                        )
                        return None

        except aiohttp.ClientError as e:
            logger.error(f"SOAR client error: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error creating SOAR incident: {e}")
            return None

    async def _create_phantom_incident(
        self,
        email: Email,
        threat_details: Dict[str, Any],
        severity: IncidentSeverity,
        assignee: str = None,
    ) -> Dict[str, Any]:
        """Create incident data for Phantom SOAR"""
        severity_map = {
            IncidentSeverity.LOW: "low",
            IncidentSeverity.MEDIUM: "medium",
            IncidentSeverity.HIGH: "high",
            IncidentSeverity.CRITICAL: "high",
        }

        return {
            "name": f"Phishing Email Detected - {email.sender_email}",
            "description": f"Phishing email detected from {email.sender_email} to {email.recipient_email}",
            "label": "events",
            "severity": severity_map.get(severity, "medium"),
            "sensitivity": "amber",
            "status": "new",
            "source_data_identifier": email.platform_message_id,
            "data": {
                "email_id": email.id,
                "sender": email.sender_email,
                "recipient": email.recipient_email,
                "subject": email.subject,
                "risk_score": threat_details.get("risk_score", 0.0),
                "threat_level": threat_details.get("threat_level", "low"),
                "platform": email.source_platform,
                "received_date": email.received_date.isoformat(),
                "indicators": threat_details.get("indicators", []),
            },
        }

    async def _create_demisto_incident(
        self,
        email: Email,
        threat_details: Dict[str, Any],
        severity: IncidentSeverity,
        assignee: str = None,
    ) -> Dict[str, Any]:
        """Create incident data for Demisto SOAR"""
        severity_map = {
            IncidentSeverity.LOW: 1,
            IncidentSeverity.MEDIUM: 2,
            IncidentSeverity.HIGH: 3,
            IncidentSeverity.CRITICAL: 4,
        }

        incident_data = {
            "name": f"Phishing Email - {email.sender_email}",
            "type": "Phishing",
            "severity": severity_map.get(severity, 2),
            "details": f"Phishing email detected from {email.sender_email}",
            "labels": [
                {"type": "Email", "value": email.sender_email},
                {"type": "Subject", "value": email.subject or "No Subject"},
                {"type": "Recipient", "value": email.recipient_email},
                {"type": "Platform", "value": email.source_platform},
                {
                    "type": "RiskScore",
                    "value": str(threat_details.get("risk_score", 0.0)),
                },
            ],
            "customFields": {
                "emailid": email.id,
                "emailplatform": email.source_platform,
                "threatlevel": threat_details.get("threat_level", "low"),
                "phishguardrisk": threat_details.get("risk_score", 0.0),
                "quarantined": email.is_quarantined,
            },
        }

        if assignee:
            incident_data["owner"] = assignee

        return incident_data

    async def _create_siemplify_incident(
        self,
        email: Email,
        threat_details: Dict[str, Any],
        severity: IncidentSeverity,
        assignee: str = None,
    ) -> Dict[str, Any]:
        """Create incident data for Siemplify SOAR"""
        severity_map = {
            IncidentSeverity.LOW: 40,
            IncidentSeverity.MEDIUM: 60,
            IncidentSeverity.HIGH: 80,
            IncidentSeverity.CRITICAL: 100,
        }

        return {
            "name": f"Phishing Email Detection - {email.sender_email}",
            "description": f"Suspicious email detected from {email.sender_email} to {email.recipient_email}",
            "ticketType": "Phishing",
            "priority": severity_map.get(severity, 60),
            "ruleGenerator": "PhishGuard",
            "sourceGroupIdentifier": "PhishGuard",
            "events": [
                {
                    "eventType": "Email",
                    "deviceProduct": "PhishGuard",
                    "deviceVendor": "PhishGuard",
                    "eventName": "Phishing Email Detected",
                    "startTime": int(email.received_date.timestamp() * 1000),
                    "endTime": int(datetime.now().timestamp() * 1000),
                    "extensions": {
                        "email_id": email.id,
                        "sender": email.sender_email,
                        "recipient": email.recipient_email,
                        "subject": email.subject,
                        "risk_score": threat_details.get("risk_score", 0.0),
                        "threat_level": threat_details.get("threat_level", "low"),
                        "platform": email.source_platform,
                    },
                }
            ],
        }

    async def _create_resilient_incident(
        self,
        email: Email,
        threat_details: Dict[str, Any],
        severity: IncidentSeverity,
        assignee: str = None,
    ) -> Dict[str, Any]:
        """Create incident data for IBM Resilient SOAR"""
        severity_map = {
            IncidentSeverity.LOW: "Low",
            IncidentSeverity.MEDIUM: "Medium",
            IncidentSeverity.HIGH: "High",
            IncidentSeverity.CRITICAL: "High",
        }

        return {
            "name": f"Phishing Email - {email.sender_email}",
            "description": {
                "format": "text",
                "content": f"Phishing email detected from {email.sender_email} to {email.recipient_email}. Risk Score: {threat_details.get('risk_score', 0.0):.2%}",
            },
            "discovered_date": int(email.received_date.timestamp() * 1000),
            "incident_type_ids": [1],  # Phishing incident type
            "severity_code": severity_map.get(severity, "Medium"),
            "properties": {
                "email_sender": email.sender_email,
                "email_recipient": email.recipient_email,
                "email_subject": email.subject,
                "email_platform": email.source_platform,
                "phishguard_risk_score": threat_details.get("risk_score", 0.0),
                "threat_level": threat_details.get("threat_level", "low"),
                "quarantined": email.is_quarantined,
            },
        }

    async def _create_generic_incident(
        self,
        email: Email,
        threat_details: Dict[str, Any],
        severity: IncidentSeverity,
        assignee: str = None,
    ) -> Dict[str, Any]:
        """Create incident data for generic SOAR platform"""
        return {
            "title": f"Phishing Email Detected - {email.sender_email}",
            "description": f"Suspicious email detected from {email.sender_email} to {email.recipient_email}",
            "severity": severity.value,
            "type": "phishing",
            "status": "open",
            "source": "PhishGuard",
            "created_time": datetime.now().isoformat(),
            "discovered_time": email.received_date.isoformat(),
            "assignee": assignee,
            "artifacts": {
                "email": {
                    "id": email.id,
                    "sender": email.sender_email,
                    "recipient": email.recipient_email,
                    "subject": email.subject,
                    "platform": email.source_platform,
                    "platform_message_id": email.platform_message_id,
                    "has_attachments": email.has_attachments,
                    "quarantined": email.is_quarantined,
                },
                "threat_analysis": threat_details,
                "indicators": threat_details.get("indicators", []),
            },
        }

    def _extract_incident_id(self, response_data: Dict[str, Any]) -> Optional[str]:
        """Extract incident ID from SOAR platform response"""
        if self.platform == SOARPlatform.PHANTOM:
            return response_data.get("id")
        elif self.platform == SOARPlatform.DEMISTO:
            return response_data.get("id")
        elif self.platform == SOARPlatform.SIEMPLIFY:
            return response_data.get("case_id")
        elif self.platform == SOARPlatform.RESILIENT:
            return str(response_data.get("id"))
        else:
            return response_data.get("id") or response_data.get("incident_id")

    async def _create_incident_artifacts(
        self, incident_id: str, email: Email, threat_details: Dict[str, Any]
    ) -> bool:
        """
        Create artifacts/evidence for the incident

        Args:
            incident_id: SOAR incident ID
            email: Email object
            threat_details: Threat analysis details

        Returns:
            bool: True if artifacts created successfully
        """
        try:
            artifacts = []

            # Email artifacts
            artifacts.append(
                {
                    "type": "email",
                    "value": email.sender_email,
                    "description": "Sender email address",
                    "tags": ["phishing", "sender"],
                }
            )

            artifacts.append(
                {
                    "type": "email",
                    "value": email.recipient_email,
                    "description": "Recipient email address",
                    "tags": ["phishing", "recipient"],
                }
            )

            # URL artifacts from threat indicators
            indicators = threat_details.get("indicators", [])
            for indicator in indicators:
                if "url" in indicator.lower() or "link" in indicator.lower():
                    artifacts.append(
                        {
                            "type": "url",
                            "value": indicator,
                            "description": "Suspicious URL found in email",
                            "tags": ["phishing", "url", "suspicious"],
                        }
                    )
                elif "domain" in indicator.lower():
                    artifacts.append(
                        {
                            "type": "domain",
                            "value": indicator,
                            "description": "Suspicious domain found in email",
                            "tags": ["phishing", "domain", "suspicious"],
                        }
                    )

            # Create artifacts in SOAR platform
            for artifact in artifacts:
                await self._create_single_artifact(incident_id, artifact)

            logger.info(
                f"Created {len(artifacts)} artifacts for incident {incident_id}"
            )
            return True

        except Exception as e:
            logger.error(f"Error creating incident artifacts: {e}")
            return False

    async def _create_single_artifact(
        self, incident_id: str, artifact: Dict[str, Any]
    ) -> bool:
        """Create a single artifact in the SOAR platform"""
        try:
            if self.platform == SOARPlatform.PHANTOM:
                endpoint = "/rest/artifact"
                artifact_data = {
                    "container_id": incident_id,
                    "name": artifact["type"],
                    "cef": {artifact["type"]: artifact["value"]},
                    "description": artifact["description"],
                    "tags": artifact.get("tags", []),
                }
            elif self.platform == SOARPlatform.DEMISTO:
                # Demisto uses evidence instead of artifacts
                return True  # Skip for now, would need specific implementation
            else:
                # Generic artifact creation
                endpoint = f"/incidents/{incident_id}/artifacts"
                artifact_data = artifact

            headers = self._get_auth_headers()
            connector = aiohttp.TCPConnector(verify_ssl=self.verify_ssl)

            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.post(
                    f"{self.base_url}{endpoint}", json=artifact_data, headers=headers
                ) as response:
                    return response.status in [200, 201]

        except Exception as e:
            logger.error(f"Error creating artifact: {e}")
            return False

    async def update_incident_status(
        self, incident_id: str, status: str, resolution: str = None, notes: str = None
    ) -> bool:
        """
        Update incident status in SOAR platform

        Args:
            incident_id: SOAR incident ID
            status: New status
            resolution: Resolution if closing
            notes: Additional notes

        Returns:
            bool: True if updated successfully
        """
        if not self.base_url:
            return False

        try:
            # Prepare update data based on platform
            if self.platform == SOARPlatform.PHANTOM:
                endpoint = f"/rest/container/{incident_id}"
                update_data = {"status": status}
            elif self.platform == SOARPlatform.DEMISTO:
                endpoint = f"/incident/{incident_id}"
                update_data = {"status": status}
            else:
                endpoint = f"/incidents/{incident_id}"
                update_data = {"status": status}

            if resolution:
                update_data["resolution"] = resolution

            if notes:
                update_data["notes"] = notes

            headers = self._get_auth_headers()
            connector = aiohttp.TCPConnector(verify_ssl=self.verify_ssl)

            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.patch(
                    f"{self.base_url}{endpoint}", json=update_data, headers=headers
                ) as response:
                    if response.status == 200:
                        logger.info(
                            f"SOAR incident {incident_id} status updated to {status}"
                        )
                        return True
                    else:
                        error_text = await response.text()
                        logger.error(
                            f"SOAR incident update failed: {response.status} - {error_text}"
                        )
                        return False

        except Exception as e:
            logger.error(f"Error updating SOAR incident: {e}")
            return False

    async def add_incident_comment(
        self, incident_id: str, comment: str, author: str = None
    ) -> bool:
        """
        Add comment to SOAR incident

        Args:
            incident_id: SOAR incident ID
            comment: Comment text
            author: Comment author

        Returns:
            bool: True if comment added successfully
        """
        if not self.base_url:
            return False

        try:
            # Platform-specific comment creation
            if self.platform == SOARPlatform.PHANTOM:
                endpoint = "/rest/note"
                comment_data = {
                    "container_id": incident_id,
                    "title": "PhishGuard Update",
                    "content": comment,
                    "author": author or "PhishGuard",
                }
            elif self.platform == SOARPlatform.DEMISTO:
                endpoint = f"/incident/{incident_id}/entries"
                comment_data = {"contents": comment, "type": 1}  # Note type
            else:
                endpoint = f"/incidents/{incident_id}/comments"
                comment_data = {"text": comment, "author": author or "PhishGuard"}

            headers = self._get_auth_headers()
            connector = aiohttp.TCPConnector(verify_ssl=self.verify_ssl)

            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.post(
                    f"{self.base_url}{endpoint}", json=comment_data, headers=headers
                ) as response:
                    if response.status in [200, 201]:
                        logger.info(f"Comment added to SOAR incident {incident_id}")
                        return True
                    else:
                        error_text = await response.text()
                        logger.error(
                            f"SOAR comment creation failed: {response.status} - {error_text}"
                        )
                        return False

        except Exception as e:
            logger.error(f"Error adding SOAR incident comment: {e}")
            return False

    def is_configured(self) -> bool:
        """
        Check if SOAR integration is properly configured

        Returns:
            bool: True if configured
        """
        return bool(
            self.base_url and (self.api_key or (self.username and self.password))
        )


# Utility functions for SOAR integration
async def create_soar_connector(
    platform: SOARPlatform = SOARPlatform.GENERIC,
) -> SOARConnector:
    """Create SOAR connector for specified platform"""
    return SOARConnector(platform=platform)


async def create_soar_incident(
    email: Email,
    threat_details: Dict[str, Any],
    platform: SOARPlatform = SOARPlatform.GENERIC,
) -> Optional[str]:
    """Convenience function to create SOAR incident"""
    connector = await create_soar_connector(platform)
    if connector.is_configured():
        return await connector.create_incident(email, threat_details)
    return None

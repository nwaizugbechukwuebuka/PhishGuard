"""
Mail Client for PhishGuard

Provides email sending capabilities for notifications, alerts, and
phishing simulations with support for multiple providers and templates.
"""

import asyncio
import base64
import json
import smtplib
import ssl
from dataclasses import dataclass
from datetime import datetime
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional, Union

import requests

from .config import get_settings
from .event_bus import EventPriority, get_event_bus
from .logger import get_logger

logger = get_logger(__name__)
settings = get_settings()


@dataclass
class EmailAttachment:
    """Email attachment data structure."""

    filename: str
    content: bytes
    content_type: str = "application/octet-stream"


@dataclass
class EmailTemplate:
    """Email template data structure."""

    name: str
    subject: str
    html_body: str
    text_body: Optional[str] = None
    variables: List[str] = None


class MailProvider:
    """Base class for email providers."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config

    async def send_email(
        self,
        to_addresses: Union[str, List[str]],
        subject: str,
        body: str,
        html_body: Optional[str] = None,
        from_address: Optional[str] = None,
        attachments: Optional[List[EmailAttachment]] = None,
    ) -> Dict[str, Any]:
        """Send email. Must be implemented by subclasses."""
        raise NotImplementedError


class SMTPProvider(MailProvider):
    """SMTP email provider."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.smtp_server = config.get("smtp_server", "localhost")
        self.smtp_port = config.get("smtp_port", 587)
        self.username = config.get("username")
        self.password = config.get("password")
        self.use_tls = config.get("use_tls", True)
        self.default_from = config.get("default_from", "noreply@phishguard.com")

    async def send_email(
        self,
        to_addresses: Union[str, List[str]],
        subject: str,
        body: str,
        html_body: Optional[str] = None,
        from_address: Optional[str] = None,
        attachments: Optional[List[EmailAttachment]] = None,
    ) -> Dict[str, Any]:
        """Send email via SMTP."""
        try:
            # Normalize recipients
            if isinstance(to_addresses, str):
                to_addresses = [to_addresses]

            from_addr = from_address or self.default_from

            # Create message
            msg = MIMEMultipart("alternative")
            msg["From"] = from_addr
            msg["To"] = ", ".join(to_addresses)
            msg["Subject"] = subject

            # Add text body
            text_part = MIMEText(body, "plain", "utf-8")
            msg.attach(text_part)

            # Add HTML body if provided
            if html_body:
                html_part = MIMEText(html_body, "html", "utf-8")
                msg.attach(html_part)

            # Add attachments
            if attachments:
                for attachment in attachments:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(attachment.content)
                    encoders.encode_base64(part)
                    part.add_header(
                        "Content-Disposition",
                        f"attachment; filename= {attachment.filename}",
                    )
                    msg.attach(part)

            # Send email
            await self._send_smtp_message(msg, from_addr, to_addresses)

            return {
                "success": True,
                "message_id": msg.get("Message-ID"),
                "recipients": to_addresses,
                "provider": "smtp",
            }

        except Exception as e:
            logger.error(f"SMTP send error: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "recipients": to_addresses,
                "provider": "smtp",
            }

    async def _send_smtp_message(
        self, msg: MIMEMultipart, from_addr: str, to_addresses: List[str]
    ):
        """Send message via SMTP server."""

        def _send():
            context = ssl.create_default_context()

            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls(context=context)

                if self.username and self.password:
                    server.login(self.username, self.password)

                server.send_message(msg, from_addr, to_addresses)

        # Run in thread to avoid blocking
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _send)


class SendGridProvider(MailProvider):
    """SendGrid email provider."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.api_key = config.get("api_key")
        self.default_from = config.get("default_from", "noreply@phishguard.com")
        self.api_url = "https://api.sendgrid.com/v3/mail/send"

    async def send_email(
        self,
        to_addresses: Union[str, List[str]],
        subject: str,
        body: str,
        html_body: Optional[str] = None,
        from_address: Optional[str] = None,
        attachments: Optional[List[EmailAttachment]] = None,
    ) -> Dict[str, Any]:
        """Send email via SendGrid API."""
        try:
            if isinstance(to_addresses, str):
                to_addresses = [to_addresses]

            from_addr = from_address or self.default_from

            # Build SendGrid payload
            payload = {
                "personalizations": [
                    {
                        "to": [{"email": addr} for addr in to_addresses],
                        "subject": subject,
                    }
                ],
                "from": {"email": from_addr},
                "content": [{"type": "text/plain", "value": body}],
            }

            # Add HTML content
            if html_body:
                payload["content"].append({"type": "text/html", "value": html_body})

            # Add attachments
            if attachments:
                payload["attachments"] = []
                for attachment in attachments:
                    payload["attachments"].append(
                        {
                            "content": base64.b64encode(attachment.content).decode(),
                            "filename": attachment.filename,
                            "type": attachment.content_type,
                        }
                    )

            # Send request
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }

            response = requests.post(
                self.api_url, headers=headers, json=payload, timeout=30
            )

            if response.status_code == 202:
                return {
                    "success": True,
                    "message_id": response.headers.get("X-Message-Id"),
                    "recipients": to_addresses,
                    "provider": "sendgrid",
                }
            else:
                raise Exception(
                    f"SendGrid API error: {response.status_code} - {response.text}"
                )

        except Exception as e:
            logger.error(f"SendGrid send error: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "recipients": to_addresses,
                "provider": "sendgrid",
            }


class MailClient:
    """
    Main mail client that manages multiple providers and templates.
    """

    def __init__(self):
        """Initialize mail client with configuration."""
        self.providers = {}
        self.templates = {}
        self.default_provider = None
        self.event_bus = get_event_bus()

        self._load_configuration()
        self._load_templates()

    def _load_configuration(self):
        """Load email provider configuration."""
        try:
            # SMTP Provider (default)
            smtp_config = {
                "smtp_server": getattr(settings, "SMTP_SERVER", "localhost"),
                "smtp_port": getattr(settings, "SMTP_PORT", 587),
                "username": getattr(settings, "SMTP_USERNAME", ""),
                "password": getattr(settings, "SMTP_PASSWORD", ""),
                "use_tls": getattr(settings, "SMTP_USE_TLS", True),
                "default_from": getattr(
                    settings, "DEFAULT_FROM_EMAIL", "noreply@phishguard.com"
                ),
            }
            self.providers["smtp"] = SMTPProvider(smtp_config)
            self.default_provider = "smtp"

            # SendGrid Provider (if configured)
            sendgrid_api_key = getattr(settings, "SENDGRID_API_KEY", None)
            if sendgrid_api_key:
                sendgrid_config = {
                    "api_key": sendgrid_api_key,
                    "default_from": getattr(
                        settings, "DEFAULT_FROM_EMAIL", "noreply@phishguard.com"
                    ),
                }
                self.providers["sendgrid"] = SendGridProvider(sendgrid_config)
                self.default_provider = "sendgrid"  # Prefer SendGrid if available

            logger.info(
                f"Mail client initialized with providers: {list(self.providers.keys())}"
            )

        except Exception as e:
            logger.error(f"Error loading mail configuration: {str(e)}")

    def _load_templates(self):
        """Load email templates."""
        try:
            # Default templates
            self.templates = {
                "threat_alert": EmailTemplate(
                    name="threat_alert",
                    subject="🚨 Security Alert: Threat Detected",
                    html_body="""
                    <html>
                    <body>
                        <h2>Security Threat Detected</h2>
                        <p>A potential security threat has been detected in your email system:</p>
                        <ul>
                            <li><strong>Threat Type:</strong> {threat_type}</li>
                            <li><strong>Sender:</strong> {sender}</li>
                            <li><strong>Subject:</strong> {subject}</li>
                            <li><strong>Detection Time:</strong> {detection_time}</li>
                            <li><strong>Confidence:</strong> {confidence}%</li>
                        </ul>
                        <p>The email has been automatically quarantined for your protection.</p>
                        <p>Best regards,<br>PhishGuard Security Team</p>
                    </body>
                    </html>
                    """,
                    text_body="Security Alert: A threat has been detected and quarantined. Threat: {threat_type}, Sender: {sender}, Subject: {subject}",
                    variables=[
                        "threat_type",
                        "sender",
                        "subject",
                        "detection_time",
                        "confidence",
                    ],
                ),
                "quarantine_notification": EmailTemplate(
                    name="quarantine_notification",
                    subject="Email Quarantined - Action Required",
                    html_body="""
                    <html>
                    <body>
                        <h2>Email Quarantined</h2>
                        <p>An email has been quarantined by our security system:</p>
                        <ul>
                            <li><strong>From:</strong> {sender}</li>
                            <li><strong>Subject:</strong> {subject}</li>
                            <li><strong>Quarantine Reason:</strong> {reason}</li>
                            <li><strong>Date:</strong> {quarantine_date}</li>
                        </ul>
                        <p>If you believe this email is legitimate, please contact your IT administrator.</p>
                        <p>Best regards,<br>PhishGuard Security Team</p>
                    </body>
                    </html>
                    """,
                    variables=["sender", "subject", "reason", "quarantine_date"],
                ),
                "simulation_training": EmailTemplate(
                    name="simulation_training",
                    subject="Security Training Recommended",
                    html_body="""
                    <html>
                    <body>
                        <h2>Security Awareness Training</h2>
                        <p>Hello {user_name},</p>
                        <p>Based on your recent phishing simulation results, we recommend additional security awareness training.</p>
                        <p><strong>Simulation Results:</strong></p>
                        <ul>
                            <li>Campaign: {campaign_name}</li>
                            <li>Date: {simulation_date}</li>
                            <li>Result: {result}</li>
                        </ul>
                        <p>Please complete the recommended training modules to improve your security awareness.</p>
                        <p>Thank you for helping keep our organization secure!</p>
                    </body>
                    </html>
                    """,
                    variables=[
                        "user_name",
                        "campaign_name",
                        "simulation_date",
                        "result",
                    ],
                ),
                "compliance_report": EmailTemplate(
                    name="compliance_report",
                    subject="Compliance Report - {report_period}",
                    html_body="""
                    <html>
                    <body>
                        <h2>Compliance Report</h2>
                        <p>Your compliance report for {report_period} is ready:</p>
                        <ul>
                            <li><strong>Overall Compliance Score:</strong> {compliance_score}%</li>
                            <li><strong>Total Threats Detected:</strong> {total_threats}</li>
                            <li><strong>Violations Found:</strong> {violations_count}</li>
                            <li><strong>Report Generated:</strong> {generation_date}</li>
                        </ul>
                        <p>Please review the attached detailed report.</p>
                        <p>Best regards,<br>PhishGuard Compliance Team</p>
                    </body>
                    </html>
                    """,
                    variables=[
                        "report_period",
                        "compliance_score",
                        "total_threats",
                        "violations_count",
                        "generation_date",
                    ],
                ),
            }

            logger.info(f"Loaded {len(self.templates)} email templates")

        except Exception as e:
            logger.error(f"Error loading email templates: {str(e)}")

    async def send_email(
        self,
        to_addresses: Union[str, List[str]],
        subject: str,
        body: str,
        html_body: Optional[str] = None,
        from_address: Optional[str] = None,
        attachments: Optional[List[EmailAttachment]] = None,
        provider: Optional[str] = None,
        priority: str = "normal",
    ) -> Dict[str, Any]:
        """
        Send email using specified or default provider.

        Args:
            to_addresses: Recipient email address(es)
            subject: Email subject
            body: Plain text body
            html_body: HTML body (optional)
            from_address: Sender address (optional)
            attachments: Email attachments (optional)
            provider: Email provider to use (optional)
            priority: Email priority level

        Returns:
            Send result data
        """
        try:
            # Select provider
            provider_name = provider or self.default_provider
            if provider_name not in self.providers:
                raise ValueError(f"Provider not available: {provider_name}")

            mail_provider = self.providers[provider_name]

            # Send email
            result = await mail_provider.send_email(
                to_addresses=to_addresses,
                subject=subject,
                body=body,
                html_body=html_body,
                from_address=from_address,
                attachments=attachments,
            )

            # Log result
            if result["success"]:
                logger.info(
                    f"Email sent successfully via {provider_name}: {result.get('message_id')}"
                )

                # Emit success event
                await self.event_bus.emit(
                    "notification_sent",
                    {
                        "recipients": result["recipients"],
                        "subject": subject,
                        "provider": provider_name,
                        "message_id": result.get("message_id"),
                    },
                    source="mail_client",
                    priority=(
                        EventPriority.HIGH
                        if priority == "high"
                        else EventPriority.NORMAL
                    ),
                )
            else:
                logger.error(
                    f"Email send failed via {provider_name}: {result.get('error')}"
                )

                # Emit failure event
                await self.event_bus.emit(
                    "notification_failed",
                    {
                        "recipients": result["recipients"],
                        "subject": subject,
                        "provider": provider_name,
                        "error": result.get("error"),
                    },
                    source="mail_client",
                    priority=EventPriority.HIGH,
                )

            return result

        except Exception as e:
            logger.error(f"Error sending email: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "recipients": to_addresses,
                "provider": provider_name if "provider_name" in locals() else "unknown",
            }

    async def send_template_email(
        self,
        template_name: str,
        to_addresses: Union[str, List[str]],
        variables: Dict[str, str],
        from_address: Optional[str] = None,
        attachments: Optional[List[EmailAttachment]] = None,
        provider: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Send email using a predefined template.

        Args:
            template_name: Name of the template to use
            to_addresses: Recipient email address(es)
            variables: Template variables to substitute
            from_address: Sender address (optional)
            attachments: Email attachments (optional)
            provider: Email provider to use (optional)

        Returns:
            Send result data
        """
        try:
            if template_name not in self.templates:
                raise ValueError(f"Template not found: {template_name}")

            template = self.templates[template_name]

            # Substitute variables in subject and body
            subject = template.subject.format(**variables)
            html_body = template.html_body.format(**variables)
            text_body = (
                template.text_body.format(**variables) if template.text_body else None
            )

            return await self.send_email(
                to_addresses=to_addresses,
                subject=subject,
                body=text_body or self._html_to_text(html_body),
                html_body=html_body,
                from_address=from_address,
                attachments=attachments,
                provider=provider,
            )

        except Exception as e:
            logger.error(f"Error sending template email: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "recipients": to_addresses,
                "template": template_name,
            }

    async def send_simulation_email(
        self,
        to_email: str,
        subject: str,
        body: str,
        sender_name: Optional[str] = None,
        sender_email: Optional[str] = None,
    ) -> bool:
        """
        Send phishing simulation email.

        Args:
            to_email: Target email address
            subject: Email subject
            body: Email body
            sender_name: Simulated sender name
            sender_email: Simulated sender email

        Returns:
            Success status
        """
        try:
            # Format sender address
            if sender_name and sender_email:
                from_address = f"{sender_name} <{sender_email}>"
            elif sender_email:
                from_address = sender_email
            else:
                from_address = None

            result = await self.send_email(
                to_addresses=[to_email],
                subject=subject,
                body=body,
                html_body=body,  # Assume body is HTML for simulations
                from_address=from_address,
                provider="smtp",  # Use SMTP for simulations
            )

            return result["success"]

        except Exception as e:
            logger.error(f"Error sending simulation email: {str(e)}")
            return False

    def _html_to_text(self, html_content: str) -> str:
        """Convert HTML content to plain text (basic implementation)."""
        try:
            # Simple HTML to text conversion
            import re

            # Remove HTML tags
            text = re.sub(r"<[^>]+>", "", html_content)

            # Convert common HTML entities
            text = text.replace("&nbsp;", " ")
            text = text.replace("&lt;", "<")
            text = text.replace("&gt;", ">")
            text = text.replace("&amp;", "&")

            # Clean up whitespace
            text = re.sub(r"\s+", " ", text).strip()

            return text

        except Exception:
            return html_content

    def add_template(self, template: EmailTemplate):
        """Add a new email template."""
        try:
            self.templates[template.name] = template
            logger.info(f"Email template added: {template.name}")

        except Exception as e:
            logger.error(f"Error adding template: {str(e)}")

    def get_template(self, template_name: str) -> Optional[EmailTemplate]:
        """Get an email template by name."""
        return self.templates.get(template_name)

    def list_templates(self) -> List[str]:
        """List available template names."""
        return list(self.templates.keys())

    def get_provider_status(self) -> Dict[str, Any]:
        """Get status of all email providers."""
        status = {
            "providers": list(self.providers.keys()),
            "default_provider": self.default_provider,
            "total_templates": len(self.templates),
        }

        return status


# Global mail client instance
_mail_client = None


def get_mail_client() -> MailClient:
    """Get the global mail client instance."""
    global _mail_client
    if _mail_client is None:
        _mail_client = MailClient()
    return _mail_client


# Convenience functions
async def send_threat_alert(
    recipient: str, threat_data: Dict[str, Any]
) -> Dict[str, Any]:
    """Send threat alert notification."""
    mail_client = get_mail_client()
    return await mail_client.send_template_email(
        template_name="threat_alert",
        to_addresses=[recipient],
        variables={
            "threat_type": threat_data.get("threat_type", "Unknown"),
            "sender": threat_data.get("sender", "Unknown"),
            "subject": threat_data.get("subject", "Unknown"),
            "detection_time": threat_data.get(
                "detection_time", datetime.utcnow().isoformat()
            ),
            "confidence": str(int(threat_data.get("confidence", 0) * 100)),
        },
    )


async def send_quarantine_notification(
    recipient: str, quarantine_data: Dict[str, Any]
) -> Dict[str, Any]:
    """Send quarantine notification."""
    mail_client = get_mail_client()
    return await mail_client.send_template_email(
        template_name="quarantine_notification",
        to_addresses=[recipient],
        variables={
            "sender": quarantine_data.get("sender", "Unknown"),
            "subject": quarantine_data.get("subject", "Unknown"),
            "reason": quarantine_data.get("reason", "Security threat detected"),
            "quarantine_date": quarantine_data.get(
                "quarantine_date", datetime.utcnow().isoformat()
            ),
        },
    )

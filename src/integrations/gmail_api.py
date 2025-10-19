"""
Gmail API Integration for PhishGuard
Handles Gmail email scanning, quarantine, and management
"""

import base64
import json
import os
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from src.ai_engine.inference import ThreatAnalyzer
from src.api.models.email import Email
from src.api.models.user import User
from src.api.utils.logger import get_logger

logger = get_logger(__name__)


class GmailAPIError(Exception):
    """Custom exception for Gmail API errors"""

    pass


class GmailIntegration:
    """Gmail API integration for email threat detection and management"""

    # Gmail API scopes
    SCOPES = [
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/gmail.compose",
    ]

    def __init__(self, credentials_path: str = None, token_path: str = None):
        """
        Initialize Gmail integration

        Args:
            credentials_path: Path to OAuth2 credentials file
            token_path: Path to store/load access tokens
        """
        self.credentials_path = credentials_path or os.getenv(
            "GMAIL_CREDENTIALS_PATH", "credentials.json"
        )
        self.token_path = token_path or os.getenv("GMAIL_TOKEN_PATH", "token.json")
        self.service = None
        self.threat_analyzer = ThreatAnalyzer()

    async def authenticate(self) -> bool:
        """
        Authenticate with Gmail API

        Returns:
            bool: True if authentication successful
        """
        try:
            creds = None

            # Load existing token
            if os.path.exists(self.token_path):
                creds = Credentials.from_authorized_user_file(
                    self.token_path, self.SCOPES
                )

            # Refresh or obtain new credentials
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                else:
                    if not os.path.exists(self.credentials_path):
                        logger.error(
                            f"Gmail credentials file not found: {self.credentials_path}"
                        )
                        return False

                    flow = InstalledAppFlow.from_client_secrets_file(
                        self.credentials_path, self.SCOPES
                    )
                    creds = flow.run_local_server(port=0)

                # Save credentials for next run
                with open(self.token_path, "w") as token:
                    token.write(creds.to_json())

            # Build Gmail service
            self.service = build("gmail", "v1", credentials=creds)
            logger.info("Gmail API authentication successful")
            return True

        except Exception as e:
            logger.error(f"Gmail authentication failed: {e}")
            return False

    async def get_messages(
        self,
        query: str = "is:unread",
        max_results: int = 100,
        label_ids: List[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve Gmail messages based on query

        Args:
            query: Gmail search query
            max_results: Maximum number of messages to retrieve
            label_ids: Specific label IDs to filter

        Returns:
            List of message metadata
        """
        try:
            if not self.service:
                await self.authenticate()

            results = (
                self.service.users()
                .messages()
                .list(userId="me", q=query, maxResults=max_results, labelIds=label_ids)
                .execute()
            )

            messages = results.get("messages", [])
            logger.info(f"Retrieved {len(messages)} Gmail messages")
            return messages

        except HttpError as e:
            logger.error(f"Gmail API error retrieving messages: {e}")
            raise GmailAPIError(f"Failed to retrieve messages: {e}")
        except Exception as e:
            logger.error(f"Unexpected error retrieving Gmail messages: {e}")
            raise GmailAPIError(f"Unexpected error: {e}")

    async def get_message_details(self, message_id: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific message

        Args:
            message_id: Gmail message ID

        Returns:
            Detailed message information
        """
        try:
            if not self.service:
                await self.authenticate()

            message = (
                self.service.users()
                .messages()
                .get(userId="me", id=message_id, format="full")
                .execute()
            )

            return message

        except HttpError as e:
            logger.error(f"Gmail API error getting message {message_id}: {e}")
            raise GmailAPIError(f"Failed to get message: {e}")
        except Exception as e:
            logger.error(f"Unexpected error getting Gmail message {message_id}: {e}")
            raise GmailAPIError(f"Unexpected error: {e}")

    def parse_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse Gmail message into structured format

        Args:
            message: Raw Gmail message

        Returns:
            Parsed message data
        """
        try:
            headers = {
                h["name"]: h["value"] for h in message["payload"].get("headers", [])
            }

            # Extract message body
            body_text = ""
            body_html = ""

            def extract_body(part):
                nonlocal body_text, body_html

                if part.get("mimeType") == "text/plain":
                    data = part["body"].get("data", "")
                    if data:
                        body_text += base64.urlsafe_b64decode(data).decode(
                            "utf-8", errors="ignore"
                        )
                elif part.get("mimeType") == "text/html":
                    data = part["body"].get("data", "")
                    if data:
                        body_html += base64.urlsafe_b64decode(data).decode(
                            "utf-8", errors="ignore"
                        )
                elif "parts" in part:
                    for subpart in part["parts"]:
                        extract_body(subpart)

            if "parts" in message["payload"]:
                for part in message["payload"]["parts"]:
                    extract_body(part)
            else:
                extract_body(message["payload"])

            # Extract attachments info
            attachments = []

            def extract_attachments(part):
                if part.get("filename"):
                    attachments.append(
                        {
                            "filename": part["filename"],
                            "mimeType": part.get("mimeType", ""),
                            "size": part["body"].get("size", 0),
                            "attachmentId": part["body"].get("attachmentId"),
                        }
                    )

                if "parts" in part:
                    for subpart in part["parts"]:
                        extract_attachments(subpart)

            if "parts" in message["payload"]:
                for part in message["payload"]["parts"]:
                    extract_attachments(part)

            return {
                "id": message["id"],
                "thread_id": message["threadId"],
                "label_ids": message.get("labelIds", []),
                "snippet": message.get("snippet", ""),
                "size_estimate": message.get("sizeEstimate", 0),
                "sender_email": headers.get("From", ""),
                "recipient_email": headers.get("To", ""),
                "cc_emails": headers.get("Cc", ""),
                "bcc_emails": headers.get("Bcc", ""),
                "subject": headers.get("Subject", ""),
                "date": headers.get("Date", ""),
                "message_id": headers.get("Message-ID", ""),
                "reply_to": headers.get("Reply-To", ""),
                "body_text": body_text,
                "body_html": body_html,
                "attachments": attachments,
                "headers": headers,
            }

        except Exception as e:
            logger.error(f"Error parsing Gmail message: {e}")
            return {}

    async def scan_new_emails(self, user: User) -> List[Email]:
        """
        Scan new emails for threats

        Args:
            user: User to scan emails for

        Returns:
            List of processed Email objects
        """
        try:
            processed_emails = []

            # Get new messages
            messages = await self.get_messages(query="is:unread")

            for message_meta in messages:
                try:
                    # Get detailed message
                    message = await self.get_message_details(message_meta["id"])
                    parsed = self.parse_message(message)

                    if not parsed:
                        continue

                    # Create Email object
                    email = Email(
                        id=parsed["id"],
                        sender_email=parsed["sender_email"],
                        recipient_email=parsed["recipient_email"],
                        subject=parsed["subject"],
                        body_text=parsed["body_text"],
                        body_html=parsed["body_html"],
                        received_date=datetime.now(),
                        user_id=user.id,
                        source_platform="gmail",
                        platform_message_id=parsed["id"],
                        headers=json.dumps(parsed["headers"]),
                        has_attachments=len(parsed["attachments"]) > 0,
                        attachment_count=len(parsed["attachments"]),
                    )

                    # Analyze for threats
                    analysis_result = await self.threat_analyzer.analyze_email(email)

                    # Update email with analysis results
                    email.is_phishing = analysis_result.get("is_phishing", False)
                    email.risk_score = analysis_result.get("risk_score", 0.0)
                    email.threat_level = analysis_result.get("threat_level", "low")
                    email.ai_analysis_result = json.dumps(analysis_result)

                    # Auto-quarantine if high risk
                    if email.risk_score > 0.8:
                        await self.quarantine_message(message_meta["id"])
                        email.is_quarantined = True
                        email.status = "quarantined"

                    processed_emails.append(email)

                except Exception as e:
                    logger.error(
                        f"Error processing Gmail message {message_meta.get('id')}: {e}"
                    )
                    continue

            logger.info(f"Processed {len(processed_emails)} Gmail messages")
            return processed_emails

        except Exception as e:
            logger.error(f"Error scanning Gmail emails: {e}")
            raise GmailAPIError(f"Email scanning failed: {e}")

    async def quarantine_message(self, message_id: str) -> bool:
        """
        Quarantine a Gmail message by moving to quarantine label

        Args:
            message_id: Gmail message ID

        Returns:
            bool: True if successful
        """
        try:
            if not self.service:
                await self.authenticate()

            # Create quarantine label if it doesn't exist
            quarantine_label_id = await self.get_or_create_label(
                "PhishGuard-Quarantine"
            )

            # Move message to quarantine
            self.service.users().messages().modify(
                userId="me",
                id=message_id,
                body={
                    "addLabelIds": [quarantine_label_id],
                    "removeLabelIds": ["INBOX"],
                },
            ).execute()

            logger.info(f"Gmail message {message_id} quarantined successfully")
            return True

        except Exception as e:
            logger.error(f"Error quarantining Gmail message {message_id}: {e}")
            return False

    async def restore_message(self, message_id: str) -> bool:
        """
        Restore a quarantined message to inbox

        Args:
            message_id: Gmail message ID

        Returns:
            bool: True if successful
        """
        try:
            if not self.service:
                await self.authenticate()

            quarantine_label_id = await self.get_or_create_label(
                "PhishGuard-Quarantine"
            )

            # Restore message to inbox
            self.service.users().messages().modify(
                userId="me",
                id=message_id,
                body={
                    "addLabelIds": ["INBOX"],
                    "removeLabelIds": [quarantine_label_id],
                },
            ).execute()

            logger.info(f"Gmail message {message_id} restored successfully")
            return True

        except Exception as e:
            logger.error(f"Error restoring Gmail message {message_id}: {e}")
            return False

    async def get_or_create_label(self, label_name: str) -> str:
        """
        Get or create a Gmail label

        Args:
            label_name: Name of the label

        Returns:
            Label ID
        """
        try:
            if not self.service:
                await self.authenticate()

            # Check if label exists
            labels = self.service.users().labels().list(userId="me").execute()

            for label in labels.get("labels", []):
                if label["name"] == label_name:
                    return label["id"]

            # Create new label
            label_object = {
                "name": label_name,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show",
            }

            created_label = (
                self.service.users()
                .labels()
                .create(userId="me", body=label_object)
                .execute()
            )

            logger.info(f"Created Gmail label: {label_name}")
            return created_label["id"]

        except Exception as e:
            logger.error(f"Error creating Gmail label {label_name}: {e}")
            raise GmailAPIError(f"Label creation failed: {e}")

    async def send_notification_email(
        self, to_email: str, subject: str, message: str, html_message: str = None
    ) -> bool:
        """
        Send notification email via Gmail

        Args:
            to_email: Recipient email
            subject: Email subject
            message: Plain text message
            html_message: HTML message (optional)

        Returns:
            bool: True if sent successfully
        """
        try:
            if not self.service:
                await self.authenticate()

            # Create message
            msg = MIMEMultipart("alternative")
            msg["to"] = to_email
            msg["subject"] = subject

            # Add text part
            text_part = MIMEText(message, "plain")
            msg.attach(text_part)

            # Add HTML part if provided
            if html_message:
                html_part = MIMEText(html_message, "html")
                msg.attach(html_part)

            # Encode message
            raw_message = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")

            # Send message
            sent_message = (
                self.service.users()
                .messages()
                .send(userId="me", body={"raw": raw_message})
                .execute()
            )

            logger.info(f"Notification email sent to {to_email}: {sent_message['id']}")
            return True

        except Exception as e:
            logger.error(f"Error sending notification email to {to_email}: {e}")
            return False

    async def get_email_statistics(self) -> Dict[str, int]:
        """
        Get email statistics from Gmail

        Returns:
            Dictionary with email counts
        """
        try:
            if not self.service:
                await self.authenticate()

            # Get various email counts
            total_messages = await self.get_messages(query="", max_results=1)
            unread_messages = await self.get_messages(query="is:unread", max_results=1)

            # Get quarantine label messages
            quarantine_label_id = await self.get_or_create_label(
                "PhishGuard-Quarantine"
            )
            quarantine_messages = await self.get_messages(
                query=f"label:{quarantine_label_id}", max_results=1
            )

            return {
                "total_emails": len(total_messages),
                "unread_emails": len(unread_messages),
                "quarantined_emails": len(quarantine_messages),
            }

        except Exception as e:
            logger.error(f"Error getting Gmail statistics: {e}")
            return {"total_emails": 0, "unread_emails": 0, "quarantined_emails": 0}


# Utility functions for Gmail integration
async def create_gmail_integration() -> GmailIntegration:
    """Create and authenticate Gmail integration"""
    integration = GmailIntegration()
    await integration.authenticate()
    return integration


async def scan_gmail_for_threats(user: User) -> List[Email]:
    """Convenience function to scan Gmail for threats"""
    integration = await create_gmail_integration()
    return await integration.scan_new_emails(user)

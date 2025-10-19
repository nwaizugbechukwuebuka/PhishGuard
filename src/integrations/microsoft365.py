"""
Microsoft 365 Integration for PhishGuard
Handles Microsoft 365 email scanning, quarantine, and management via Graph API
"""

import json
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List

import aiohttp
from msal import ConfidentialClientApplication, PublicClientApplication

from src.ai_engine.inference import ThreatAnalyzer
from src.api.models.email import Email
from src.api.models.user import User
from src.api.utils.logger import get_logger

logger = get_logger(__name__)


class Microsoft365Error(Exception):
    """Custom exception for Microsoft 365 integration errors"""

    pass


class Microsoft365Integration:
    """Microsoft 365 Graph API integration for email threat detection"""

    # Microsoft Graph API endpoints
    BASE_URL = "https://graph.microsoft.com/v1.0"

    # Required scopes for email operations
    SCOPES = [
        "https://graph.microsoft.com/Mail.Read",
        "https://graph.microsoft.com/Mail.ReadWrite",
        "https://graph.microsoft.com/Mail.Send",
        "https://graph.microsoft.com/User.Read",
    ]

    def __init__(
        self,
        client_id: str = None,
        client_secret: str = None,
        tenant_id: str = None,
        redirect_uri: str = None,
    ):
        """
        Initialize Microsoft 365 integration

        Args:
            client_id: Azure AD application client ID
            client_secret: Azure AD application client secret
            tenant_id: Azure AD tenant ID
            redirect_uri: OAuth redirect URI
        """
        self.client_id = client_id or os.getenv("MICROSOFT365_CLIENT_ID")
        self.client_secret = client_secret or os.getenv("MICROSOFT365_CLIENT_SECRET")
        self.tenant_id = tenant_id or os.getenv("MICROSOFT365_TENANT_ID")
        self.redirect_uri = redirect_uri or os.getenv(
            "MICROSOFT365_REDIRECT_URI",
            "http://localhost:8000/auth/microsoft365/callback",
        )

        self.access_token = None
        self.refresh_token = None
        self.token_expires_at = None
        self.threat_analyzer = ThreatAnalyzer()

        # Initialize MSAL client
        if self.client_secret:
            # Confidential client (server-to-server)
            self.msal_client = ConfidentialClientApplication(
                client_id=self.client_id,
                client_credential=self.client_secret,
                authority=f"https://login.microsoftonline.com/{self.tenant_id}",
            )
        else:
            # Public client (user authentication)
            self.msal_client = PublicClientApplication(
                client_id=self.client_id,
                authority=f"https://login.microsoftonline.com/{self.tenant_id}",
            )

    async def authenticate_with_code(self, authorization_code: str) -> bool:
        """
        Authenticate using authorization code flow

        Args:
            authorization_code: OAuth authorization code

        Returns:
            bool: True if authentication successful
        """
        try:
            # Exchange authorization code for tokens
            result = self.msal_client.acquire_token_by_authorization_code(
                code=authorization_code,
                scopes=self.SCOPES,
                redirect_uri=self.redirect_uri,
            )

            if "access_token" in result:
                self.access_token = result["access_token"]
                self.refresh_token = result.get("refresh_token")
                self.token_expires_at = datetime.now() + timedelta(
                    seconds=result.get("expires_in", 3600)
                )

                logger.info("Microsoft 365 authentication successful")
                return True
            else:
                logger.error(
                    f"Microsoft 365 authentication failed: {result.get('error_description')}"
                )
                return False

        except Exception as e:
            logger.error(f"Microsoft 365 authentication error: {e}")
            return False

    async def authenticate_with_client_credentials(self) -> bool:
        """
        Authenticate using client credentials flow (app-only)

        Returns:
            bool: True if authentication successful
        """
        try:
            if not self.client_secret:
                logger.error("Client secret required for client credentials flow")
                return False

            # Acquire token using client credentials
            result = self.msal_client.acquire_token_for_client(
                scopes=["https://graph.microsoft.com/.default"]
            )

            if "access_token" in result:
                self.access_token = result["access_token"]
                self.token_expires_at = datetime.now() + timedelta(
                    seconds=result.get("expires_in", 3600)
                )

                logger.info(
                    "Microsoft 365 client credentials authentication successful"
                )
                return True
            else:
                logger.error(
                    f"Microsoft 365 client credentials authentication failed: {result.get('error_description')}"
                )
                return False

        except Exception as e:
            logger.error(f"Microsoft 365 client credentials authentication error: {e}")
            return False

    async def refresh_access_token(self) -> bool:
        """
        Refresh access token using refresh token

        Returns:
            bool: True if refresh successful
        """
        try:
            if not self.refresh_token:
                logger.warning("No refresh token available")
                return False

            # Try to acquire token silently
            accounts = self.msal_client.get_accounts()
            if accounts:
                result = self.msal_client.acquire_token_silent(
                    scopes=self.SCOPES, account=accounts[0]
                )

                if "access_token" in result:
                    self.access_token = result["access_token"]
                    self.token_expires_at = datetime.now() + timedelta(
                        seconds=result.get("expires_in", 3600)
                    )
                    logger.info("Microsoft 365 token refreshed successfully")
                    return True

            return False

        except Exception as e:
            logger.error(f"Microsoft 365 token refresh error: {e}")
            return False

    async def ensure_valid_token(self) -> bool:
        """
        Ensure we have a valid access token

        Returns:
            bool: True if valid token available
        """
        if not self.access_token:
            return False

        # Check if token is expired
        if self.token_expires_at and datetime.now() >= self.token_expires_at:
            return await self.refresh_access_token()

        return True

    async def make_graph_request(
        self, endpoint: str, method: str = "GET", data: Dict = None, params: Dict = None
    ) -> Dict[str, Any]:
        """
        Make authenticated request to Microsoft Graph API

        Args:
            endpoint: API endpoint
            method: HTTP method
            data: Request body data
            params: Query parameters

        Returns:
            API response data
        """
        if not await self.ensure_valid_token():
            raise Microsoft365Error("No valid access token available")

        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }

        url = f"{self.BASE_URL}{endpoint}"

        try:
            async with aiohttp.ClientSession() as session:
                if method.upper() == "GET":
                    async with session.get(
                        url, headers=headers, params=params
                    ) as response:
                        if response.status == 200:
                            return await response.json()
                        else:
                            error_text = await response.text()
                            raise Microsoft365Error(
                                f"Graph API error: {response.status} - {error_text}"
                            )

                elif method.upper() == "POST":
                    async with session.post(
                        url, headers=headers, json=data, params=params
                    ) as response:
                        if response.status in [200, 201]:
                            return await response.json()
                        else:
                            error_text = await response.text()
                            raise Microsoft365Error(
                                f"Graph API error: {response.status} - {error_text}"
                            )

                elif method.upper() == "PATCH":
                    async with session.patch(
                        url, headers=headers, json=data, params=params
                    ) as response:
                        if response.status == 200:
                            return await response.json()
                        else:
                            error_text = await response.text()
                            raise Microsoft365Error(
                                f"Graph API error: {response.status} - {error_text}"
                            )

                else:
                    raise Microsoft365Error(f"Unsupported HTTP method: {method}")

        except aiohttp.ClientError as e:
            logger.error(f"HTTP client error: {e}")
            raise Microsoft365Error(f"HTTP client error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error in Graph API request: {e}")
            raise Microsoft365Error(f"Unexpected error: {e}")

    async def get_user_profile(self) -> Dict[str, Any]:
        """
        Get current user profile

        Returns:
            User profile data
        """
        try:
            return await self.make_graph_request("/me")
        except Exception as e:
            logger.error(f"Error getting user profile: {e}")
            raise Microsoft365Error(f"Failed to get user profile: {e}")

    async def get_messages(
        self,
        folder: str = "inbox",
        filter_query: str = None,
        top: int = 100,
        skip: int = 0,
        select: str = None,
    ) -> List[Dict[str, Any]]:
        """
        Get messages from specified folder

        Args:
            folder: Folder name (inbox, sentitems, drafts, etc.)
            filter_query: OData filter query
            top: Number of messages to retrieve
            skip: Number of messages to skip
            select: Fields to select

        Returns:
            List of message data
        """
        try:
            params = {"$top": top, "$skip": skip}

            if filter_query:
                params["$filter"] = filter_query

            if select:
                params["$select"] = select

            endpoint = f"/me/mailFolders/{folder}/messages"
            result = await self.make_graph_request(endpoint, params=params)

            messages = result.get("value", [])
            logger.info(f"Retrieved {len(messages)} messages from {folder}")
            return messages

        except Exception as e:
            logger.error(f"Error getting messages from {folder}: {e}")
            raise Microsoft365Error(f"Failed to get messages: {e}")

    async def get_message_details(self, message_id: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific message

        Args:
            message_id: Microsoft Graph message ID

        Returns:
            Detailed message information
        """
        try:
            endpoint = f"/me/messages/{message_id}"
            params = {"$expand": "attachments"}

            return await self.make_graph_request(endpoint, params=params)

        except Exception as e:
            logger.error(f"Error getting message details {message_id}: {e}")
            raise Microsoft365Error(f"Failed to get message details: {e}")

    def parse_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse Microsoft Graph message into structured format

        Args:
            message: Raw Microsoft Graph message

        Returns:
            Parsed message data
        """
        try:
            # Extract sender information
            sender = message.get("sender", {}).get("emailAddress", {})
            sender_email = sender.get("address", "")

            # Extract recipients
            to_recipients = message.get("toRecipients", [])
            recipient_emails = [
                r.get("emailAddress", {}).get("address", "") for r in to_recipients
            ]

            cc_recipients = message.get("ccRecipients", [])
            cc_emails = [
                r.get("emailAddress", {}).get("address", "") for r in cc_recipients
            ]

            bcc_recipients = message.get("bccRecipients", [])
            bcc_emails = [
                r.get("emailAddress", {}).get("address", "") for r in bcc_recipients
            ]

            # Extract body content
            body = message.get("body", {})
            body_content = body.get("content", "")
            body_type = body.get("contentType", "text")

            # Extract attachments
            attachments = []
            for attachment in message.get("attachments", []):
                attachments.append(
                    {
                        "id": attachment.get("id"),
                        "name": attachment.get("name"),
                        "contentType": attachment.get("contentType"),
                        "size": attachment.get("size", 0),
                        "isInline": attachment.get("isInline", False),
                    }
                )

            return {
                "id": message.get("id"),
                "conversation_id": message.get("conversationId"),
                "subject": message.get("subject", ""),
                "sender_email": sender_email,
                "recipient_emails": recipient_emails,
                "cc_emails": cc_emails,
                "bcc_emails": bcc_emails,
                "received_date": message.get("receivedDateTime"),
                "sent_date": message.get("sentDateTime"),
                "body_content": body_content,
                "body_type": body_type,
                "importance": message.get("importance", "normal"),
                "is_read": message.get("isRead", False),
                "has_attachments": message.get("hasAttachments", False),
                "attachments": attachments,
                "internet_message_id": message.get("internetMessageId"),
                "web_link": message.get("webLink"),
                "categories": message.get("categories", []),
                "flag": message.get("flag", {}),
                "inference_classification": message.get("inferenceClassification"),
            }

        except Exception as e:
            logger.error(f"Error parsing Microsoft 365 message: {e}")
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

            # Get unread messages
            messages = await self.get_messages(
                folder="inbox", filter_query="isRead eq false", top=100
            )

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
                        recipient_email=",".join(parsed["recipient_emails"]),
                        subject=parsed["subject"],
                        body_text=(
                            parsed["body_content"]
                            if parsed["body_type"] == "text"
                            else ""
                        ),
                        body_html=(
                            parsed["body_content"]
                            if parsed["body_type"] == "html"
                            else ""
                        ),
                        received_date=(
                            datetime.fromisoformat(
                                parsed["received_date"].replace("Z", "+00:00")
                            )
                            if parsed["received_date"]
                            else datetime.now()
                        ),
                        user_id=user.id,
                        source_platform="microsoft365",
                        platform_message_id=parsed["id"],
                        headers=json.dumps(
                            {
                                "internet_message_id": parsed["internet_message_id"],
                                "conversation_id": parsed["conversation_id"],
                                "importance": parsed["importance"],
                            }
                        ),
                        has_attachments=parsed["has_attachments"],
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
                        f"Error processing Microsoft 365 message {message_meta.get('id')}: {e}"
                    )
                    continue

            logger.info(f"Processed {len(processed_emails)} Microsoft 365 messages")
            return processed_emails

        except Exception as e:
            logger.error(f"Error scanning Microsoft 365 emails: {e}")
            raise Microsoft365Error(f"Email scanning failed: {e}")

    async def quarantine_message(self, message_id: str) -> bool:
        """
        Quarantine a message by moving to quarantine folder

        Args:
            message_id: Microsoft Graph message ID

        Returns:
            bool: True if successful
        """
        try:
            # Get or create quarantine folder
            quarantine_folder_id = await self.get_or_create_folder(
                "PhishGuard-Quarantine"
            )

            # Move message to quarantine folder
            move_data = {"destinationId": quarantine_folder_id}

            endpoint = f"/me/messages/{message_id}/move"
            await self.make_graph_request(endpoint, method="POST", data=move_data)

            logger.info(f"Microsoft 365 message {message_id} quarantined successfully")
            return True

        except Exception as e:
            logger.error(f"Error quarantining Microsoft 365 message {message_id}: {e}")
            return False

    async def restore_message(self, message_id: str) -> bool:
        """
        Restore a quarantined message to inbox

        Args:
            message_id: Microsoft Graph message ID

        Returns:
            bool: True if successful
        """
        try:
            # Get inbox folder ID
            inbox_folder = await self.get_folder("inbox")

            # Move message back to inbox
            move_data = {"destinationId": inbox_folder["id"]}

            endpoint = f"/me/messages/{message_id}/move"
            await self.make_graph_request(endpoint, method="POST", data=move_data)

            logger.info(f"Microsoft 365 message {message_id} restored successfully")
            return True

        except Exception as e:
            logger.error(f"Error restoring Microsoft 365 message {message_id}: {e}")
            return False

    async def get_folder(self, folder_name: str) -> Dict[str, Any]:
        """
        Get folder by name

        Args:
            folder_name: Name of the folder

        Returns:
            Folder information
        """
        try:
            endpoint = f"/me/mailFolders"
            params = {"$filter": f"displayName eq '{folder_name}'"}

            result = await self.make_graph_request(endpoint, params=params)
            folders = result.get("value", [])

            if folders:
                return folders[0]
            else:
                raise Microsoft365Error(f"Folder '{folder_name}' not found")

        except Exception as e:
            logger.error(f"Error getting folder {folder_name}: {e}")
            raise Microsoft365Error(f"Failed to get folder: {e}")

    async def get_or_create_folder(self, folder_name: str) -> str:
        """
        Get or create a mail folder

        Args:
            folder_name: Name of the folder

        Returns:
            Folder ID
        """
        try:
            # Try to get existing folder
            try:
                folder = await self.get_folder(folder_name)
                return folder["id"]
            except Microsoft365Error:
                pass

            # Create new folder
            folder_data = {"displayName": folder_name}

            endpoint = "/me/mailFolders"
            created_folder = await self.make_graph_request(
                endpoint, method="POST", data=folder_data
            )

            logger.info(f"Created Microsoft 365 folder: {folder_name}")
            return created_folder["id"]

        except Exception as e:
            logger.error(f"Error creating folder {folder_name}: {e}")
            raise Microsoft365Error(f"Folder creation failed: {e}")

    async def send_email(
        self,
        to_email: str,
        subject: str,
        body_content: str,
        body_type: str = "text",
        cc_emails: List[str] = None,
        bcc_emails: List[str] = None,
    ) -> bool:
        """
        Send email via Microsoft 365

        Args:
            to_email: Recipient email
            subject: Email subject
            body_content: Email body content
            body_type: Content type (text or html)
            cc_emails: CC recipients
            bcc_emails: BCC recipients

        Returns:
            bool: True if sent successfully
        """
        try:
            # Prepare recipients
            to_recipients = [{"emailAddress": {"address": to_email}}]

            cc_recipients = []
            if cc_emails:
                cc_recipients = [
                    {"emailAddress": {"address": email}} for email in cc_emails
                ]

            bcc_recipients = []
            if bcc_emails:
                bcc_recipients = [
                    {"emailAddress": {"address": email}} for email in bcc_emails
                ]

            # Prepare message
            message_data = {
                "message": {
                    "subject": subject,
                    "body": {"contentType": body_type, "content": body_content},
                    "toRecipients": to_recipients,
                    "ccRecipients": cc_recipients,
                    "bccRecipients": bcc_recipients,
                }
            }

            # Send message
            endpoint = "/me/sendMail"
            await self.make_graph_request(endpoint, method="POST", data=message_data)

            logger.info(f"Email sent successfully to {to_email}")
            return True

        except Exception as e:
            logger.error(f"Error sending email to {to_email}: {e}")
            return False

    async def get_email_statistics(self) -> Dict[str, int]:
        """
        Get email statistics from Microsoft 365

        Returns:
            Dictionary with email counts
        """
        try:
            # Get inbox messages count
            inbox_messages = await self.get_messages(folder="inbox", top=1)

            # Get unread messages count
            unread_messages = await self.get_messages(
                folder="inbox", filter_query="isRead eq false", top=1
            )

            # Get quarantine folder messages count
            try:
                quarantine_messages = await self.get_messages(
                    folder="PhishGuard-Quarantine", top=1
                )
                quarantined_count = len(quarantine_messages)
            except:
                quarantined_count = 0

            return {
                "total_emails": len(inbox_messages),
                "unread_emails": len(unread_messages),
                "quarantined_emails": quarantined_count,
            }

        except Exception as e:
            logger.error(f"Error getting Microsoft 365 statistics: {e}")
            return {"total_emails": 0, "unread_emails": 0, "quarantined_emails": 0}


# Utility functions for Microsoft 365 integration
async def create_microsoft365_integration() -> Microsoft365Integration:
    """Create Microsoft 365 integration"""
    return Microsoft365Integration()


async def scan_microsoft365_for_threats(
    user: User, integration: Microsoft365Integration = None
) -> List[Email]:
    """Convenience function to scan Microsoft 365 for threats"""
    if not integration:
        integration = await create_microsoft365_integration()

    return await integration.scan_new_emails(user)

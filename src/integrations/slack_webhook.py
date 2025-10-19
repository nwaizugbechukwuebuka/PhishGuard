"""
Slack Webhook Integration for PhishGuard
Sends threat notifications and alerts to Slack channels
"""

import os
import json
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime

import aiohttp

from src.api.models.email import Email
from src.api.models.notification import Notification
from src.api.utils.logger import get_logger

logger = get_logger(__name__)

class SlackWebhookError(Exception):
    """Custom exception for Slack webhook errors"""
    pass

class SlackIntegration:
    """Slack webhook integration for threat notifications"""
    
    def __init__(self, webhook_url: str = None, channel: str = None, username: str = None):
        """
        Initialize Slack integration
        
        Args:
            webhook_url: Slack webhook URL
            channel: Default Slack channel
            username: Bot username for messages
        """
        self.webhook_url = webhook_url or os.getenv('SLACK_WEBHOOK_URL')
        self.default_channel = channel or os.getenv('SLACK_CHANNEL', '#phishguard-alerts')
        self.username = username or os.getenv('SLACK_USERNAME', 'PhishGuard Bot')
        
        if not self.webhook_url:
            logger.warning("Slack webhook URL not configured")
    
    async def send_message(
        self,
        text: str,
        channel: str = None,
        username: str = None,
        icon_emoji: str = ":shield:",
        attachments: List[Dict] = None,
        blocks: List[Dict] = None
    ) -> bool:
        """
        Send message to Slack
        
        Args:
            text: Message text
            channel: Slack channel (optional)
            username: Bot username (optional)
            icon_emoji: Bot icon emoji
            attachments: Message attachments
            blocks: Slack blocks for rich formatting
            
        Returns:
            bool: True if message sent successfully
        """
        if not self.webhook_url:
            logger.error("Slack webhook URL not configured")
            return False
        
        try:
            payload = {
                "text": text,
                "channel": channel or self.default_channel,
                "username": username or self.username,
                "icon_emoji": icon_emoji
            }
            
            if attachments:
                payload["attachments"] = attachments
            
            if blocks:
                payload["blocks"] = blocks
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                ) as response:
                    if response.status == 200:
                        logger.info(f"Slack message sent successfully to {channel or self.default_channel}")
                        return True
                    else:
                        error_text = await response.text()
                        logger.error(f"Slack webhook error: {response.status} - {error_text}")
                        return False
                        
        except aiohttp.ClientError as e:
            logger.error(f"Slack webhook client error: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending Slack message: {e}")
            return False
    
    async def send_threat_alert(
        self,
        email: Email,
        threat_details: Dict[str, Any],
        channel: str = None
    ) -> bool:
        """
        Send threat detection alert to Slack
        
        Args:
            email: Detected threat email
            threat_details: Threat analysis details
            channel: Slack channel (optional)
            
        Returns:
            bool: True if alert sent successfully
        """
        try:
            # Determine alert color based on threat level
            color_map = {
                "low": "#36a64f",      # Green
                "medium": "#ff9500",   # Orange
                "high": "#ff4444",     # Red
                "critical": "#8b0000"  # Dark Red
            }
            
            threat_level = threat_details.get("threat_level", "low")
            risk_score = threat_details.get("risk_score", 0.0)
            
            # Create rich message attachment
            attachment = {
                "color": color_map.get(threat_level, "#36a64f"),
                "title": f"🚨 Phishing Threat Detected - {threat_level.upper()} Risk",
                "title_link": f"https://phishguard.local/emails/{email.id}",
                "fields": [
                    {
                        "title": "Sender",
                        "value": email.sender_email,
                        "short": True
                    },
                    {
                        "title": "Recipient",
                        "value": email.recipient_email,
                        "short": True
                    },
                    {
                        "title": "Subject",
                        "value": email.subject or "No Subject",
                        "short": False
                    },
                    {
                        "title": "Risk Score",
                        "value": f"{risk_score:.2%}",
                        "short": True
                    },
                    {
                        "title": "Threat Level",
                        "value": threat_level.upper(),
                        "short": True
                    },
                    {
                        "title": "Platform",
                        "value": email.source_platform.title(),
                        "short": True
                    },
                    {
                        "title": "Status",
                        "value": "Quarantined" if email.is_quarantined else "Under Review",
                        "short": True
                    }
                ],
                "footer": "PhishGuard Threat Detection",
                "footer_icon": "https://phishguard.local/static/icon.png",
                "ts": int(datetime.now().timestamp())
            }
            
            # Add threat indicators if available
            indicators = threat_details.get("indicators", [])
            if indicators:
                indicator_text = "\n".join([f"• {indicator}" for indicator in indicators[:5]])
                attachment["fields"].append({
                    "title": "Threat Indicators",
                    "value": indicator_text,
                    "short": False
                })
            
            # Main alert text
            alert_text = (
                f"🔍 **Phishing email detected** with {threat_level} risk level!\n"
                f"Risk Score: {risk_score:.2%} | "
                f"Platform: {email.source_platform.title()}"
            )
            
            return await self.send_message(
                text=alert_text,
                channel=channel,
                attachments=[attachment],
                icon_emoji=":warning:"
            )
            
        except Exception as e:
            logger.error(f"Error sending Slack threat alert: {e}")
            return False
    
    async def send_quarantine_notification(
        self,
        email: Email,
        action: str = "quarantined",
        user_email: str = None,
        channel: str = None
    ) -> bool:
        """
        Send quarantine action notification
        
        Args:
            email: Email that was quarantined/restored
            action: Action taken (quarantined, restored, deleted)
            user_email: User who performed the action
            channel: Slack channel (optional)
            
        Returns:
            bool: True if notification sent successfully
        """
        try:
            # Action-specific formatting
            action_map = {
                "quarantined": {
                    "emoji": ":lock:",
                    "color": "#ff9500",
                    "title": "Email Quarantined"
                },
                "restored": {
                    "emoji": ":unlock:",
                    "color": "#36a64f",
                    "title": "Email Restored"
                },
                "deleted": {
                    "emoji": ":wastebasket:",
                    "color": "#ff4444",
                    "title": "Email Deleted"
                }
            }
            
            action_info = action_map.get(action, action_map["quarantined"])
            
            attachment = {
                "color": action_info["color"],
                "title": f"{action_info['emoji']} {action_info['title']}",
                "fields": [
                    {
                        "title": "Sender",
                        "value": email.sender_email,
                        "short": True
                    },
                    {
                        "title": "Subject",
                        "value": email.subject or "No Subject",
                        "short": False
                    },
                    {
                        "title": "Action Taken",
                        "value": action.title(),
                        "short": True
                    },
                    {
                        "title": "Timestamp",
                        "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "short": True
                    }
                ],
                "footer": "PhishGuard Quarantine System",
                "ts": int(datetime.now().timestamp())
            }
            
            if user_email:
                attachment["fields"].append({
                    "title": "Performed By",
                    "value": user_email,
                    "short": True
                })
            
            alert_text = f"📧 Email {action} successfully"
            
            return await self.send_message(
                text=alert_text,
                channel=channel,
                attachments=[attachment]
            )
            
        except Exception as e:
            logger.error(f"Error sending Slack quarantine notification: {e}")
            return False
    
    async def send_system_alert(
        self,
        alert_type: str,
        message: str,
        severity: str = "info",
        details: Dict[str, Any] = None,
        channel: str = None
    ) -> bool:
        """
        Send system-level alert
        
        Args:
            alert_type: Type of alert (error, warning, info, success)
            message: Alert message
            severity: Alert severity
            details: Additional details
            channel: Slack channel (optional)
            
        Returns:
            bool: True if alert sent successfully
        """
        try:
            # Severity-specific formatting
            severity_map = {
                "critical": {"emoji": ":rotating_light:", "color": "#8b0000"},
                "error": {"emoji": ":x:", "color": "#ff4444"},
                "warning": {"emoji": ":warning:", "color": "#ff9500"},
                "info": {"emoji": ":information_source:", "color": "#0099cc"},
                "success": {"emoji": ":white_check_mark:", "color": "#36a64f"}
            }
            
            severity_info = severity_map.get(severity, severity_map["info"])
            
            attachment = {
                "color": severity_info["color"],
                "title": f"{severity_info['emoji']} System Alert: {alert_type}",
                "text": message,
                "fields": [
                    {
                        "title": "Severity",
                        "value": severity.upper(),
                        "short": True
                    },
                    {
                        "title": "Timestamp",
                        "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "short": True
                    }
                ],
                "footer": "PhishGuard System Monitor",
                "ts": int(datetime.now().timestamp())
            }
            
            # Add additional details if provided
            if details:
                for key, value in details.items():
                    attachment["fields"].append({
                        "title": key.replace("_", " ").title(),
                        "value": str(value),
                        "short": True
                    })
            
            return await self.send_message(
                text=f"🔔 PhishGuard System Alert: {alert_type}",
                channel=channel,
                attachments=[attachment]
            )
            
        except Exception as e:
            logger.error(f"Error sending Slack system alert: {e}")
            return False
    
    async def send_daily_summary(
        self,
        summary_data: Dict[str, Any],
        channel: str = None
    ) -> bool:
        """
        Send daily threat summary
        
        Args:
            summary_data: Summary statistics
            channel: Slack channel (optional)
            
        Returns:
            bool: True if summary sent successfully
        """
        try:
            total_emails = summary_data.get("total_emails", 0)
            threats_detected = summary_data.get("threats_detected", 0)
            quarantined = summary_data.get("quarantined", 0)
            false_positives = summary_data.get("false_positives", 0)
            
            threat_rate = (threats_detected / total_emails * 100) if total_emails > 0 else 0
            
            attachment = {
                "color": "#0099cc",
                "title": "📊 Daily PhishGuard Summary",
                "fields": [
                    {
                        "title": "Total Emails Processed",
                        "value": f"{total_emails:,}",
                        "short": True
                    },
                    {
                        "title": "Threats Detected",
                        "value": f"{threats_detected:,}",
                        "short": True
                    },
                    {
                        "title": "Emails Quarantined",
                        "value": f"{quarantined:,}",
                        "short": True
                    },
                    {
                        "title": "Threat Detection Rate",
                        "value": f"{threat_rate:.2f}%",
                        "short": True
                    },
                    {
                        "title": "False Positives",
                        "value": f"{false_positives:,}",
                        "short": True
                    },
                    {
                        "title": "System Status",
                        "value": summary_data.get("system_status", "Operational"),
                        "short": True
                    }
                ],
                "footer": "PhishGuard Daily Report",
                "footer_icon": "https://phishguard.local/static/icon.png",
                "ts": int(datetime.now().timestamp())
            }
            
            # Add top threat types if available
            top_threats = summary_data.get("top_threat_types", [])
            if top_threats:
                threat_text = "\n".join([
                    f"{i+1}. {threat['type']} ({threat['count']} detected)"
                    for i, threat in enumerate(top_threats[:5])
                ])
                attachment["fields"].append({
                    "title": "Top Threat Types",
                    "value": threat_text,
                    "short": False
                })
            
            summary_text = (
                f"📈 **Daily Summary** for {datetime.now().strftime('%Y-%m-%d')}\n"
                f"Processed {total_emails:,} emails, detected {threats_detected:,} threats"
            )
            
            return await self.send_message(
                text=summary_text,
                channel=channel,
                attachments=[attachment],
                icon_emoji=":bar_chart:"
            )
            
        except Exception as e:
            logger.error(f"Error sending Slack daily summary: {e}")
            return False
    
    async def send_user_report_notification(
        self,
        reporter_email: str,
        reported_email: Email,
        report_type: str = "phishing",
        channel: str = None
    ) -> bool:
        """
        Send notification about user-reported email
        
        Args:
            reporter_email: Email of the user who reported
            reported_email: The reported email
            report_type: Type of report (phishing, spam, etc.)
            channel: Slack channel (optional)
            
        Returns:
            bool: True if notification sent successfully
        """
        try:
            attachment = {
                "color": "#ff9500",
                "title": "👥 User Report Received",
                "fields": [
                    {
                        "title": "Reported By",
                        "value": reporter_email,
                        "short": True
                    },
                    {
                        "title": "Report Type",
                        "value": report_type.title(),
                        "short": True
                    },
                    {
                        "title": "Original Sender",
                        "value": reported_email.sender_email,
                        "short": True
                    },
                    {
                        "title": "Subject",
                        "value": reported_email.subject or "No Subject",
                        "short": False
                    },
                    {
                        "title": "Platform",
                        "value": reported_email.source_platform.title(),
                        "short": True
                    },
                    {
                        "title": "Timestamp",
                        "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "short": True
                    }
                ],
                "footer": "PhishGuard User Reports",
                "ts": int(datetime.now().timestamp())
            }
            
            alert_text = f"📝 New {report_type} report from user: {reporter_email}"
            
            return await self.send_message(
                text=alert_text,
                channel=channel,
                attachments=[attachment],
                icon_emoji=":memo:"
            )
            
        except Exception as e:
            logger.error(f"Error sending Slack user report notification: {e}")
            return False
    
    def is_configured(self) -> bool:
        """
        Check if Slack integration is properly configured
        
        Returns:
            bool: True if configured
        """
        return bool(self.webhook_url)

# Utility functions for Slack integration
async def create_slack_integration() -> SlackIntegration:
    """Create Slack integration"""
    return SlackIntegration()

async def send_threat_to_slack(email: Email, threat_details: Dict[str, Any]) -> bool:
    """Convenience function to send threat alert to Slack"""
    slack = await create_slack_integration()
    if slack.is_configured():
        return await slack.send_threat_alert(email, threat_details)
    return False

async def send_system_alert_to_slack(alert_type: str, message: str, severity: str = "info") -> bool:
    """Convenience function to send system alert to Slack"""
    slack = await create_slack_integration()
    if slack.is_configured():
        return await slack.send_system_alert(alert_type, message, severity)
    return False

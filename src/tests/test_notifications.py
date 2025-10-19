"""
Comprehensive test suite for PhishGuard notification system.
Tests email notifications, Slack alerts, in-app notifications, and templates.
"""

import json
import os
import sys
from datetime import datetime, timedelta
from unittest.mock import MagicMock, Mock, patch

import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.models.notification import Notification
from api.services.notification_service import NotificationService
from api.utils.mail_client import MailClient
from integrations.slack_webhook import SlackNotifier
from tasks.notify_tasks import (
    send_daily_digest,
    send_email_notification,
    send_slack_notification,
    send_system_alert,
    send_threat_notification,
)


class TestNotificationService:
    """Test the main notification service."""

    def setUp(self):
        self.notification_service = NotificationService()

    @patch("api.services.notification_service.get_db")
    def test_create_notification(self, mock_get_db):
        """Test creating in-app notification."""
        mock_db = Mock()
        mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

        notification_data = {
            "user_id": 1,
            "title": "Threat Detected",
            "message": "A phishing email was blocked",
            "notification_type": "threat_alert",
            "metadata": {"threat_type": "phishing", "confidence": 0.95},
        }

        result = self.notification_service.create_notification(notification_data)

        assert result["success"] == True
        mock_db.add.assert_called_once()
        mock_db.commit.assert_called_once()

    @patch("api.services.notification_service.get_db")
    def test_get_user_notifications(self, mock_get_db):
        """Test retrieving user notifications."""
        mock_db = Mock()
        mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

        # Mock notifications
        mock_notifications = [
            Mock(
                id=1,
                title="Threat Alert",
                message="Phishing detected",
                is_read=False,
                created_at=datetime.now(),
            ),
            Mock(
                id=2,
                title="System Update",
                message="Model updated",
                is_read=True,
                created_at=datetime.now() - timedelta(hours=1),
            ),
        ]

        mock_db.query().filter().order_by().limit().all.return_value = (
            mock_notifications
        )

        notifications = self.notification_service.get_user_notifications(user_id=1)

        assert len(notifications) == 2
        assert notifications[0]["title"] == "Threat Alert"
        assert notifications[0]["is_read"] == False

    @patch("api.services.notification_service.get_db")
    def test_mark_notification_read(self, mock_get_db):
        """Test marking notification as read."""
        mock_db = Mock()
        mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

        mock_notification = Mock()
        mock_notification.is_read = False
        mock_db.query().filter().first.return_value = mock_notification

        result = self.notification_service.mark_as_read(notification_id=1, user_id=1)

        assert result["success"] == True
        assert mock_notification.is_read == True
        mock_db.commit.assert_called_once()

    @patch("api.services.notification_service.get_db")
    def test_delete_notification(self, mock_get_db):
        """Test deleting notification."""
        mock_db = Mock()
        mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

        mock_notification = Mock()
        mock_db.query().filter().first.return_value = mock_notification

        result = self.notification_service.delete_notification(
            notification_id=1, user_id=1
        )

        assert result["success"] == True
        mock_db.delete.assert_called_once_with(mock_notification)
        mock_db.commit.assert_called_once()

    def test_notification_priority_handling(self):
        """Test notification priority and urgency handling."""
        high_priority = {
            "user_id": 1,
            "title": "Critical Threat",
            "message": "Immediate action required",
            "notification_type": "critical_alert",
            "priority": "high",
        }

        low_priority = {
            "user_id": 1,
            "title": "System Info",
            "message": "Regular maintenance completed",
            "notification_type": "system_info",
            "priority": "low",
        }

        with patch.object(
            self.notification_service, "create_notification"
        ) as mock_create:
            mock_create.return_value = {"success": True}

            # High priority should trigger immediate notification
            self.notification_service.create_notification(high_priority)
            self.notification_service.create_notification(low_priority)

            assert mock_create.call_count == 2


class TestMailClient:
    """Test email notification functionality."""

    def setUp(self):
        self.mail_client = MailClient()

    @patch("api.utils.mail_client.smtplib.SMTP")
    def test_send_threat_alert_email(self, mock_smtp):
        """Test sending threat alert email."""
        mock_server = Mock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        email_data = {
            "to": "admin@company.com",
            "subject": "PhishGuard Alert: Threat Detected",
            "threat_type": "phishing",
            "confidence": 0.95,
            "email_subject": "Urgent: Verify Account",
            "sender": "fake@phishing.com",
        }

        result = self.mail_client.send_threat_alert(email_data)

        assert result == True
        mock_server.send_message.assert_called_once()

    @patch("api.utils.mail_client.smtplib.SMTP")
    def test_send_daily_digest(self, mock_smtp):
        """Test sending daily digest email."""
        mock_server = Mock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        digest_data = {
            "to": "manager@company.com",
            "date": "2024-01-15",
            "total_emails": 1000,
            "threats_detected": 25,
            "threats_blocked": 23,
            "top_threats": [
                {"type": "phishing", "count": 15},
                {"type": "malware", "count": 8},
                {"type": "spam", "count": 2},
            ],
        }

        result = self.mail_client.send_daily_digest(digest_data)

        assert result == True
        mock_server.send_message.assert_called_once()

    def test_email_template_rendering(self):
        """Test email template rendering."""
        template_data = {
            "user_name": "John Doe",
            "threat_type": "phishing",
            "confidence": 0.95,
            "email_subject": "Account Verification",
            "timestamp": datetime.now().isoformat(),
        }

        html_content = self.mail_client.render_threat_template(template_data)

        assert "John Doe" in html_content
        assert "phishing" in html_content.lower()
        assert "95%" in html_content or "0.95" in html_content
        assert "<html>" in html_content  # Should be HTML format

    def test_email_formatting_validation(self):
        """Test email address format validation."""
        valid_emails = [
            "user@company.com",
            "admin+alerts@example.org",
            "security.team@sub.domain.com",
        ]

        invalid_emails = [
            "not-an-email",
            "@company.com",
            "user@",
            "user..name@company.com",
        ]

        for email in valid_emails:
            assert self.mail_client.validate_email(email) == True

        for email in invalid_emails:
            assert self.mail_client.validate_email(email) == False

    @patch("api.utils.mail_client.smtplib.SMTP")
    def test_smtp_authentication_failure(self, mock_smtp):
        """Test handling SMTP authentication failure."""
        mock_server = Mock()
        mock_smtp.return_value.__enter__.return_value = mock_server
        mock_server.login.side_effect = Exception("Authentication failed")

        email_data = {
            "to": "test@company.com",
            "subject": "Test",
            "body": "Test content",
        }

        result = self.mail_client.send_email(email_data)

        assert result == False

    @patch("api.utils.mail_client.smtplib.SMTP")
    def test_email_retry_mechanism(self, mock_smtp):
        """Test email retry mechanism on failure."""
        mock_server = Mock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        # First attempt fails, second succeeds
        mock_server.send_message.side_effect = [
            Exception("Temporary failure"),
            None,  # Success
        ]

        email_data = {
            "to": "test@company.com",
            "subject": "Test",
            "body": "Test content",
        }

        result = self.mail_client.send_email_with_retry(email_data, max_retries=2)

        assert result == True
        assert mock_server.send_message.call_count == 2


class TestSlackNotifications:
    """Test Slack notification integration."""

    def setUp(self):
        self.slack = SlackNotifier()

    @patch("integrations.slack_webhook.requests.post")
    def test_send_threat_notification(self, mock_post):
        """Test sending threat notification to Slack."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        threat_data = {
            "threat_type": "phishing",
            "confidence": 0.95,
            "email_subject": "Urgent Account Verification",
            "sender": "fake@phishing.com",
            "affected_users": ["user1@company.com", "user2@company.com"],
        }

        result = self.slack.send_threat_notification(threat_data)

        assert result == True
        mock_post.assert_called_once()

        # Verify payload structure
        call_args = mock_post.call_args
        payload = call_args[1]["json"]
        assert "attachments" in payload or "blocks" in payload

    def test_slack_message_formatting(self):
        """Test Slack message formatting and structure."""
        threat_data = {
            "threat_type": "malware",
            "confidence": 0.88,
            "email_subject": "Invoice Document",
            "sender": "accounting@fake-company.com",
            "indicators": ["malicious_attachment", "suspicious_domain"],
        }

        formatted = self.slack.format_threat_message(threat_data)

        assert "malware" in formatted.lower()
        assert "88%" in formatted or "0.88" in formatted
        assert "Invoice Document" in formatted
        assert len(formatted) > 50  # Should be detailed

    @patch("integrations.slack_webhook.requests.post")
    def test_send_daily_summary_slack(self, mock_post):
        """Test sending daily summary to Slack."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        summary_data = {
            "date": "2024-01-15",
            "total_emails_processed": 1500,
            "threats_detected": 35,
            "threats_blocked": 33,
            "false_positives": 2,
            "top_threat_types": [
                {"type": "phishing", "count": 20},
                {"type": "malware", "count": 10},
                {"type": "spam", "count": 5},
            ],
        }

        result = self.slack.send_daily_summary(summary_data)

        assert result == True
        mock_post.assert_called_once()

    def test_slack_channel_routing(self):
        """Test routing notifications to different Slack channels."""
        channels = {
            "critical": "#security-alerts",
            "high": "#security-team",
            "medium": "#it-notifications",
            "low": "#general-updates",
        }

        for severity, channel in channels.items():
            with patch.object(self.slack, "send_to_channel") as mock_send:
                mock_send.return_value = True

                threat_data = {"threat_type": "phishing", "severity": severity}
                result = self.slack.send_threat_notification(threat_data, channel)

                assert result == True
                mock_send.assert_called_with(threat_data, channel)


class TestNotificationTasks:
    """Test Celery notification tasks."""

    @patch("tasks.notify_tasks.NotificationService")
    @patch("tasks.notify_tasks.MailClient")
    def test_send_threat_notification_task(self, mock_mail, mock_notification):
        """Test threat notification Celery task."""
        mock_mail_instance = mock_mail.return_value
        mock_mail_instance.send_threat_alert.return_value = True

        mock_notification_instance = mock_notification.return_value
        mock_notification_instance.create_notification.return_value = {"success": True}

        threat_data = {
            "user_id": 1,
            "threat_type": "phishing",
            "confidence": 0.95,
            "email_subject": "Account Verification",
            "sender": "fake@phishing.com",
        }

        result = send_threat_notification.apply(args=[threat_data])

        assert result.successful()
        assert result.result["status"] == "completed"

    @patch("tasks.notify_tasks.MailClient")
    def test_send_email_notification_task(self, mock_mail):
        """Test email notification Celery task."""
        mock_mail_instance = mock_mail.return_value
        mock_mail_instance.send_email.return_value = True

        email_data = {
            "to": "admin@company.com",
            "subject": "PhishGuard Alert",
            "template": "threat_alert",
            "context": {"threat_type": "phishing", "confidence": 0.95},
        }

        result = send_email_notification.apply(args=[email_data])

        assert result.successful()
        assert result.result["status"] == "sent"

    @patch("tasks.notify_tasks.SlackNotifier")
    def test_send_slack_notification_task(self, mock_slack):
        """Test Slack notification Celery task."""
        mock_slack_instance = mock_slack.return_value
        mock_slack_instance.send_threat_notification.return_value = True

        slack_data = {
            "channel": "#security-alerts",
            "threat_type": "malware",
            "confidence": 0.92,
            "email_subject": "Invoice PDF",
        }

        result = send_slack_notification.apply(args=[slack_data])

        assert result.successful()
        assert result.result["status"] == "sent"

    @patch("tasks.notify_tasks.get_db")
    @patch("tasks.notify_tasks.MailClient")
    def test_send_daily_digest_task(self, mock_mail, mock_db):
        """Test daily digest Celery task."""
        # Mock database query results
        mock_db_session = Mock()
        mock_db.return_value.__next__ = Mock(return_value=mock_db_session)

        # Mock email query results
        mock_db_session.query().filter().count.return_value = 1000  # Total emails
        mock_db_session.query().filter().filter().count.side_effect = [
            25,
            23,
        ]  # Threats detected/blocked

        mock_mail_instance = mock_mail.return_value
        mock_mail_instance.send_daily_digest.return_value = True

        result = send_daily_digest.apply()

        assert result.successful()
        assert result.result["status"] == "completed"

    @patch("tasks.notify_tasks.MailClient")
    @patch("tasks.notify_tasks.SlackNotifier")
    def test_send_system_alert_task(self, mock_slack, mock_mail):
        """Test system alert Celery task."""
        mock_mail_instance = mock_mail.return_value
        mock_mail_instance.send_system_alert.return_value = True

        mock_slack_instance = mock_slack.return_value
        mock_slack_instance.send_system_alert.return_value = True

        alert_data = {
            "alert_type": "model_performance_degraded",
            "message": "Model accuracy dropped below threshold",
            "severity": "high",
            "metadata": {"current_accuracy": 0.78, "threshold": 0.85},
        }

        result = send_system_alert.apply(args=[alert_data])

        assert result.successful()
        assert result.result["status"] == "completed"


class TestNotificationTemplates:
    """Test notification template system."""

    def test_threat_alert_template(self):
        """Test threat alert email template."""
        template_data = {
            "user_name": "Security Admin",
            "threat_type": "phishing",
            "confidence": 0.95,
            "email_subject": "Urgent: Account Verification Required",
            "sender": "security@fake-bank.com",
            "timestamp": datetime.now(),
            "indicators": ["suspicious_url", "domain_spoofing", "urgency_language"],
        }

        mail_client = MailClient()
        html_content = mail_client.render_template("threat_alert.html", template_data)

        assert "Security Admin" in html_content
        assert "phishing" in html_content.lower()
        assert "95%" in html_content
        assert "suspicious_url" in html_content
        assert "<html>" in html_content.lower()

    def test_daily_digest_template(self):
        """Test daily digest email template."""
        template_data = {
            "recipient_name": "IT Manager",
            "date": "2024-01-15",
            "summary": {
                "total_emails": 1500,
                "threats_detected": 35,
                "threats_blocked": 33,
                "false_positives": 2,
                "detection_rate": 97.1,
            },
            "top_threats": [
                {"type": "Phishing", "count": 20, "percentage": 57.1},
                {"type": "Malware", "count": 10, "percentage": 28.6},
                {"type": "Spam", "count": 5, "percentage": 14.3},
            ],
            "trends": {"threat_increase": 12.5, "accuracy_change": -0.2},
        }

        mail_client = MailClient()
        html_content = mail_client.render_template("daily_digest.html", template_data)

        assert "IT Manager" in html_content
        assert "1500" in html_content
        assert "35" in html_content
        assert "Phishing" in html_content
        assert "97.1" in html_content

    def test_system_alert_template(self):
        """Test system alert template."""
        template_data = {
            "alert_type": "Model Performance Degraded",
            "severity": "High",
            "message": "Detection accuracy has dropped below acceptable threshold",
            "details": {
                "current_accuracy": 0.78,
                "threshold": 0.85,
                "recommended_action": "Retrain model with recent data",
            },
            "timestamp": datetime.now(),
        }

        mail_client = MailClient()
        html_content = mail_client.render_template("system_alert.html", template_data)

        assert "Model Performance Degraded" in html_content
        assert "High" in html_content
        assert "0.78" in html_content
        assert "Retrain model" in html_content

    def test_template_security_validation(self):
        """Test template security and XSS protection."""
        # Test with potentially malicious template data
        malicious_data = {
            "user_name": '<script>alert("xss")</script>John Doe',
            "threat_type": '<img src=x onerror=alert("xss")>phishing',
            "email_subject": '"><script>alert("xss")</script><"',
        }

        mail_client = MailClient()
        html_content = mail_client.render_template("threat_alert.html", malicious_data)

        # Should escape malicious content
        assert "<script>" not in html_content
        assert "onerror=" not in html_content
        assert "&lt;script&gt;" in html_content or "script" not in html_content.lower()


class TestNotificationPreferences:
    """Test user notification preferences."""

    def test_user_notification_preferences(self):
        """Test setting user notification preferences."""
        preferences = {
            "email_alerts": True,
            "slack_notifications": False,
            "in_app_notifications": True,
            "digest_frequency": "daily",
            "threat_threshold": 0.8,  # Only notify for threats above 80% confidence
        }

        notification_service = NotificationService()

        with patch.object(notification_service, "update_preferences") as mock_update:
            mock_update.return_value = {"success": True}

            result = notification_service.set_user_preferences(
                user_id=1, preferences=preferences
            )

            assert result["success"] == True
            mock_update.assert_called_with(1, preferences)

    def test_notification_filtering_by_preferences(self):
        """Test filtering notifications based on user preferences."""
        user_preferences = {
            "threat_threshold": 0.8,
            "notification_types": ["phishing", "malware"],
            "business_hours_only": True,
        }

        notifications = [
            {
                "threat_type": "phishing",
                "confidence": 0.95,
                "timestamp": datetime.now().replace(hour=10),
            },
            {
                "threat_type": "spam",
                "confidence": 0.75,
                "timestamp": datetime.now().replace(hour=14),
            },
            {
                "threat_type": "malware",
                "confidence": 0.65,
                "timestamp": datetime.now().replace(hour=22),
            },
            {
                "threat_type": "phishing",
                "confidence": 0.85,
                "timestamp": datetime.now().replace(hour=16),
            },
        ]

        notification_service = NotificationService()
        filtered = notification_service.filter_by_preferences(
            notifications, user_preferences
        )

        # Should only include phishing during business hours with high confidence
        assert len(filtered) == 2
        assert all(n["threat_type"] in ["phishing", "malware"] for n in filtered)
        assert all(n["confidence"] >= 0.8 for n in filtered)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

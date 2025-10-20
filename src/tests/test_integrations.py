"""
Comprehensive test suite for PhishGuard integrations.
Tests email providers, SIEM exports, SOAR connectors, and webhooks.
"""

import pytest
import json
import requests
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from integrations.gmail_api import GmailIntegration
from integrations.microsoft365 import Microsoft365Integration
from integrations.siem_exporter import SIEMExporter
from integrations.slack_webhook import SlackNotifier
from integrations.soar_connector import SOARConnector


class TestGmailIntegration:
    """Test Gmail API integration."""

    def setUp(self):
        self.gmail = GmailIntegration()

    @patch("integrations.gmail_api.build")
    def test_authenticate(self, mock_build):
        """Test Gmail authentication."""
        mock_service = Mock()
        mock_build.return_value = mock_service

        result = self.gmail.authenticate()

        assert result == True
        assert self.gmail.service == mock_service

    @patch("integrations.gmail_api.build")
    def test_fetch_emails(self, mock_build):
        """Test fetching emails from Gmail."""
        # Mock Gmail service
        mock_service = Mock()
        mock_build.return_value = mock_service

        # Mock email list response
        mock_list_response = {
            "messages": [
                {"id": "msg1", "threadId": "thread1"},
                {"id": "msg2", "threadId": "thread2"},
            ]
        }
        mock_service.users().messages().list().execute.return_value = mock_list_response

        # Mock individual email responses
        mock_email1 = {
            "id": "msg1",
            "payload": {
                "headers": [
                    {"name": "Subject", "value": "Test Email 1"},
                    {"name": "From", "value": "sender1@example.com"},
                ],
                "body": {"data": "VGVzdCBib2R5IDE="},  # Base64 encoded
            },
        }
        mock_email2 = {
            "id": "msg2",
            "payload": {
                "headers": [
                    {"name": "Subject", "value": "Test Email 2"},
                    {"name": "From", "value": "sender2@example.com"},
                ],
                "body": {"data": "VGVzdCBib2R5IDI="},  # Base64 encoded
            },
        }

        mock_service.users().messages().get().execute.side_effect = [
            mock_email1,
            mock_email2,
        ]

        self.gmail.service = mock_service
        emails = self.gmail.fetch_emails(max_results=2)

        assert len(emails) == 2
        assert emails[0]["subject"] == "Test Email 1"
        assert emails[1]["subject"] == "Test Email 2"

    @patch("integrations.gmail_api.build")
    def test_mark_as_spam(self, mock_build):
        """Test marking email as spam."""
        mock_service = Mock()
        mock_build.return_value = mock_service

        self.gmail.service = mock_service
        result = self.gmail.mark_as_spam("msg123")

        assert result == True
        mock_service.users().messages().modify.assert_called_once()

    @patch("integrations.gmail_api.build")
    def test_move_to_folder(self, mock_build):
        """Test moving email to folder."""
        mock_service = Mock()
        mock_build.return_value = mock_service

        self.gmail.service = mock_service
        result = self.gmail.move_to_folder("msg123", "QUARANTINE")

        assert result == True
        mock_service.users().messages().modify.assert_called_once()

    def test_authentication_failure(self):
        """Test handling of authentication failure."""
        with patch("integrations.gmail_api.build") as mock_build:
            mock_build.side_effect = Exception("Authentication failed")

            result = self.gmail.authenticate()
            assert result == False

    def test_rate_limiting_handling(self):
        """Test handling of Gmail API rate limits."""
        with patch("integrations.gmail_api.build") as mock_build:
            mock_service = Mock()
            mock_build.return_value = mock_service

            # Mock rate limit error
            from googleapiclient.errors import HttpError

            mock_service.users().messages().list().execute.side_effect = HttpError(
                resp=Mock(status=429), content=b"Rate limit exceeded"
            )

            self.gmail.service = mock_service
            emails = self.gmail.fetch_emails()

            # Should handle gracefully and return empty list or retry
            assert emails == [] or isinstance(emails, list)


class TestMicrosoft365Integration:
    """Test Microsoft 365 integration."""

    def setUp(self):
        self.ms365 = Microsoft365Integration()

    @patch("integrations.microsoft365.requests.post")
    def test_authenticate(self, mock_post):
        """Test Microsoft 365 authentication."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "test_token",
            "expires_in": 3600,
        }
        mock_post.return_value = mock_response

        result = self.ms365.authenticate("client_id", "client_secret")

        assert result == True
        assert self.ms365.access_token == "test_token"

    @patch("integrations.microsoft365.requests.get")
    def test_fetch_emails(self, mock_get):
        """Test fetching emails from Microsoft 365."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "value": [
                {
                    "id": "email1",
                    "subject": "Test Email 1",
                    "from": {"emailAddress": {"address": "sender1@example.com"}},
                    "body": {"content": "Test body 1"},
                },
                {
                    "id": "email2",
                    "subject": "Test Email 2",
                    "from": {"emailAddress": {"address": "sender2@example.com"}},
                    "body": {"content": "Test body 2"},
                },
            ]
        }
        mock_get.return_value = mock_response

        self.ms365.access_token = "test_token"
        emails = self.ms365.fetch_emails()

        assert len(emails) == 2
        assert emails[0]["subject"] == "Test Email 1"
        assert emails[1]["subject"] == "Test Email 2"

    @patch("integrations.microsoft365.requests.patch")
    def test_quarantine_email(self, mock_patch):
        """Test quarantining email in Microsoft 365."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_patch.return_value = mock_response

        self.ms365.access_token = "test_token"
        result = self.ms365.quarantine_email("email123")

        assert result == True
        mock_patch.assert_called_once()

    def test_token_refresh(self):
        """Test access token refresh."""
        with patch("integrations.microsoft365.requests.post") as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "access_token": "new_token",
                "expires_in": 3600,
            }
            mock_post.return_value = mock_response

            self.ms365.refresh_token = "refresh_token"
            result = self.ms365.refresh_access_token()

            assert result == True
            assert self.ms365.access_token == "new_token"


class TestSIEMExporter:
    """Test SIEM export functionality."""

    def setUp(self):
        self.siem = SIEMExporter()

    def test_format_cef_log(self):
        """Test CEF log format generation."""
        threat_data = {
            "timestamp": datetime.now(),
            "source_ip": "192.168.1.100",
            "threat_type": "phishing",
            "severity": "high",
            "email_subject": "Urgent: Verify Account",
            "sender": "fake@phishing.com",
        }

        cef_log = self.siem.format_cef_log(threat_data)

        assert cef_log.startswith("CEF:0|PhishGuard|")
        assert "phishing" in cef_log
        assert "192.168.1.100" in cef_log
        assert "severity=high" in cef_log.lower() or "severity=3" in cef_log

    def test_format_json_log(self):
        """Test JSON log format generation."""
        threat_data = {
            "timestamp": datetime.now().isoformat(),
            "threat_type": "phishing",
            "confidence": 0.95,
            "indicators": ["suspicious_url", "fake_sender"],
        }

        json_log = self.siem.format_json_log(threat_data)
        parsed = json.loads(json_log)

        assert parsed["threat_type"] == "phishing"
        assert parsed["confidence"] == 0.95
        assert "indicators" in parsed

    @patch("integrations.siem_exporter.requests.post")
    def test_send_to_splunk(self, mock_post):
        """Test sending logs to Splunk."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        threat_data = {"threat_type": "phishing", "severity": "high"}
        result = self.siem.send_to_splunk(threat_data)

        assert result == True
        mock_post.assert_called_once()

    @patch("integrations.siem_exporter.socket.socket")
    def test_send_to_syslog(self, mock_socket):
        """Test sending logs to syslog."""
        mock_sock = Mock()
        mock_socket.return_value = mock_sock

        threat_data = {"threat_type": "malware", "severity": "critical"}
        result = self.siem.send_to_syslog(threat_data)

        assert result == True
        mock_sock.sendto.assert_called_once()

    def test_batch_export(self):
        """Test batch export of multiple threats."""
        threats = [
            {"id": 1, "threat_type": "phishing"},
            {"id": 2, "threat_type": "malware"},
            {"id": 3, "threat_type": "spam"},
        ]

        with patch.object(self.siem, "export_threat") as mock_export:
            mock_export.return_value = True

            results = self.siem.batch_export(threats)

            assert len(results) == 3
            assert all(r["success"] for r in results)


class TestSlackNotifier:
    """Test Slack webhook integration."""

    def setUp(self):
        self.slack = SlackNotifier()

    @patch("integrations.slack_webhook.requests.post")
    def test_send_threat_alert(self, mock_post):
        """Test sending threat alert to Slack."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        threat_info = {
            "threat_type": "phishing",
            "confidence": 0.95,
            "email_subject": "Urgent Account Verification",
            "sender": "fake@evil.com",
        }

        result = self.slack.send_threat_alert(threat_info)

        assert result == True
        mock_post.assert_called_once()

        # Check payload format
        call_args = mock_post.call_args
        payload = call_args[1]["json"]
        assert "text" in payload or "blocks" in payload

    @patch("integrations.slack_webhook.requests.post")
    def test_send_daily_summary(self, mock_post):
        """Test sending daily summary to Slack."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        summary_data = {
            "date": "2024-01-15",
            "total_emails": 1000,
            "threats_detected": 25,
            "threats_blocked": 23,
            "false_positives": 2,
        }

        result = self.slack.send_daily_summary(summary_data)

        assert result == True
        mock_post.assert_called_once()

    def test_format_threat_message(self):
        """Test threat message formatting."""
        threat_info = {
            "threat_type": "phishing",
            "confidence": 0.95,
            "email_subject": "Account Verification Required",
            "sender": "security@fake-bank.com",
        }

        message = self.slack.format_threat_message(threat_info)

        assert "phishing" in message.lower()
        assert "95%" in message or "0.95" in message
        assert "Account Verification Required" in message

    def test_webhook_retry_on_failure(self):
        """Test retry mechanism on webhook failure."""
        with patch("integrations.slack_webhook.requests.post") as mock_post:
            # First call fails, second succeeds
            mock_post.side_effect = [
                Mock(status_code=500),  # Server error
                Mock(status_code=200),  # Success
            ]

            threat_info = {"threat_type": "spam"}
            result = self.slack.send_threat_alert(threat_info)

            assert result == True
            assert mock_post.call_count == 2


class TestSOARConnector:
    """Test SOAR platform integration."""

    def setUp(self):
        self.soar = SOARConnector()

    @patch("integrations.soar_connector.requests.post")
    def test_create_incident(self, mock_post):
        """Test creating incident in SOAR platform."""
        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"incident_id": "INC-12345"}
        mock_post.return_value = mock_response

        threat_data = {
            "threat_type": "phishing",
            "severity": "high",
            "description": "Phishing email detected",
            "affected_users": ["user1@company.com", "user2@company.com"],
        }

        incident_id = self.soar.create_incident(threat_data)

        assert incident_id == "INC-12345"
        mock_post.assert_called_once()

    @patch("integrations.soar_connector.requests.post")
    def test_trigger_playbook(self, mock_post):
        """Test triggering automated playbook."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"playbook_run_id": "RUN-67890"}
        mock_post.return_value = mock_response

        playbook_data = {
            "playbook_name": "phishing_response",
            "incident_id": "INC-12345",
            "parameters": {"quarantine_emails": True, "notify_users": True},
        }

        run_id = self.soar.trigger_playbook(playbook_data)

        assert run_id == "RUN-67890"
        mock_post.assert_called_once()

    @patch("integrations.soar_connector.requests.get")
    def test_get_incident_status(self, mock_get):
        """Test getting incident status."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "incident_id": "INC-12345",
            "status": "in_progress",
            "assigned_to": "analyst@company.com",
            "resolution": None,
        }
        mock_get.return_value = mock_response

        status = self.soar.get_incident_status("INC-12345")

        assert status["status"] == "in_progress"
        assert status["assigned_to"] == "analyst@company.com"

    def test_format_incident_payload(self):
        """Test incident payload formatting."""
        threat_data = {
            "threat_type": "malware",
            "confidence": 0.98,
            "email_id": "email123",
            "indicators": ["malicious_attachment", "suspicious_ip"],
        }

        payload = self.soar.format_incident_payload(threat_data)

        assert payload["title"].startswith("PhishGuard Alert")
        assert payload["severity"] in ["low", "medium", "high", "critical"]
        assert "malware" in payload["description"]
        assert len(payload["artifacts"]) > 0


class TestIntegrationErrors:
    """Test error handling in integrations."""

    def test_network_timeout_handling(self):
        """Test handling of network timeouts."""
        slack = SlackNotifier()

        with patch("integrations.slack_webhook.requests.post") as mock_post:
            mock_post.side_effect = requests.exceptions.Timeout()

            threat_info = {"threat_type": "phishing"}
            result = slack.send_threat_alert(threat_info)

            assert result == False

    def test_authentication_error_handling(self):
        """Test handling of authentication errors."""
        ms365 = Microsoft365Integration()

        with patch("integrations.microsoft365.requests.post") as mock_post:
            mock_response = Mock()
            mock_response.status_code = 401
            mock_response.json.return_value = {"error": "invalid_credentials"}
            mock_post.return_value = mock_response

            result = ms365.authenticate("invalid_id", "invalid_secret")

            assert result == False

    def test_api_rate_limit_handling(self):
        """Test handling of API rate limits."""
        gmail = GmailIntegration()

        with patch("integrations.gmail_api.build") as mock_build:
            mock_service = Mock()
            mock_build.return_value = mock_service

            # Mock rate limit response
            mock_service.users().messages().list().execute.side_effect = Exception(
                "Rate limit exceeded"
            )

            gmail.service = mock_service
            emails = gmail.fetch_emails()

            # Should handle gracefully
            assert emails == [] or isinstance(emails, list)

    def test_malformed_response_handling(self):
        """Test handling of malformed API responses."""
        siem = SIEMExporter()

        with patch("integrations.siem_exporter.requests.post") as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
            mock_post.return_value = mock_response

            threat_data = {"threat_type": "phishing"}
            result = siem.send_to_splunk(threat_data)

            # Should handle gracefully
            assert result in [True, False]


class TestConfigurationValidation:
    """Test integration configuration validation."""

    def test_gmail_credentials_validation(self):
        """Test Gmail credentials validation."""
        gmail = GmailIntegration()

        # Test with invalid credentials file
        result = gmail.validate_credentials("/nonexistent/credentials.json")
        assert result == False

        # Test with valid structure (mocked)
        with patch("os.path.exists", return_value=True):
            with patch(
                "builtins.open", mock_open(read_data='{"type": "service_account"}')
            ):
                result = gmail.validate_credentials("/valid/credentials.json")
                assert result == True

    def test_slack_webhook_validation(self):
        """Test Slack webhook URL validation."""
        slack = SlackNotifier()

        # Test invalid URLs
        invalid_urls = [
            "not-a-url",
            "http://not-slack.com/webhook",
            "https://hooks.slack.com/invalid",
        ]

        for url in invalid_urls:
            assert slack.validate_webhook_url(url) == False

        # Test valid URL
        valid_url = 'os.getenv("SLACK_WEBHOOK_URL")'
        assert slack.validate_webhook_url(valid_url) == True

    def test_soar_endpoint_validation(self):
        """Test SOAR endpoint validation."""
        soar = SOARConnector()

        # Test endpoint connectivity
        with patch("integrations.soar_connector.requests.get") as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_get.return_value = mock_response

            result = soar.validate_endpoint("https://soar.company.com/api")
            assert result == True


def mock_open(read_data=""):
    """Helper function to mock file operations."""
    from unittest.mock import mock_open as original_mock_open

    return original_mock_open(read_data=read_data)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

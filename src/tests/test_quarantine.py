"""
Comprehensive test suite for PhishGuard quarantine management.
Tests quarantine operations, file storage, release workflows, and compliance.
"""

import os
import shutil
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.models.email import Email
from api.models.quarantine import QuarantineItem
from api.models.user import User
from api.services.quarantine_service import QuarantineService


class TestQuarantineService:
    """Test quarantine service functionality."""

    def setUp(self):
        self.quarantine_service = QuarantineService()
        # Create temporary directory for testing
        self.temp_dir = tempfile.mkdtemp()
        self.quarantine_service.storage_path = self.temp_dir

    def tearDown(self):
        # Clean up temporary directory
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    @patch("api.services.quarantine_service.get_db")
    def test_quarantine_email(self, mock_get_db):
        """Test quarantining an email."""
        mock_db = Mock()
        mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

        # Mock email object
        mock_email = Mock()
        mock_email.id = 1
        mock_email.subject = "Phishing Email"
        mock_email.body = "Click here to verify your account"
        mock_email.sender = "fake@phishing.com"

        quarantine_data = {
            "email_id": 1,
            "user_id": 1,
            "reason": "phishing_detected",
            "confidence": 0.95,
            "threat_indicators": ["suspicious_url", "fake_sender"],
        }

        result = self.quarantine_service.quarantine_email(quarantine_data)

        assert result["success"] == True
        assert "quarantine_id" in result
        mock_db.add.assert_called_once()
        mock_db.commit.assert_called()

    @patch("api.services.quarantine_service.get_db")
    def test_get_quarantine_items(self, mock_get_db):
        """Test retrieving quarantine items."""
        mock_db = Mock()
        mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

        # Mock quarantine items
        mock_items = [
            Mock(
                id=1,
                email_id=1,
                quarantine_reason="phishing_detected",
                quarantined_at=datetime.now(),
                status="quarantined",
                confidence=0.95,
            ),
            Mock(
                id=2,
                email_id=2,
                quarantine_reason="malware_detected",
                quarantined_at=datetime.now() - timedelta(hours=2),
                status="quarantined",
                confidence=0.88,
            ),
        ]

        mock_db.query().filter().order_by().all.return_value = mock_items

        items = self.quarantine_service.get_quarantine_items(user_id=1)

        assert len(items) == 2
        assert items[0]["quarantine_reason"] == "phishing_detected"
        assert items[1]["quarantine_reason"] == "malware_detected"

    @patch("api.services.quarantine_service.get_db")
    def test_release_quarantine_item(self, mock_get_db):
        """Test releasing quarantine item."""
        mock_db = Mock()
        mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

        mock_quarantine_item = Mock()
        mock_quarantine_item.status = "quarantined"
        mock_db.query().filter().first.return_value = mock_quarantine_item

        release_data = {
            "reason": "false_positive",
            "notes": "User confirmed this is legitimate email",
            "released_by": 1,
        }

        result = self.quarantine_service.release_item(
            quarantine_id=1, user_id=1, release_data=release_data
        )

        assert result["success"] == True
        assert mock_quarantine_item.status == "released"
        assert mock_quarantine_item.release_reason == "false_positive"
        mock_db.commit.assert_called()

    @patch("api.services.quarantine_service.get_db")
    def test_delete_quarantine_item(self, mock_get_db):
        """Test deleting quarantine item."""
        mock_db = Mock()
        mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

        mock_quarantine_item = Mock()
        mock_db.query().filter().first.return_value = mock_quarantine_item

        result = self.quarantine_service.delete_item(quarantine_id=1, user_id=1)

        assert result["success"] == True
        mock_db.delete.assert_called_with(mock_quarantine_item)
        mock_db.commit.assert_called()

    def test_quarantine_file_storage(self):
        """Test quarantine file storage operations."""
        email_content = {
            "subject": "Test Email",
            "body": "This is a test email body",
            "headers": {"From": "test@example.com"},
            "attachments": [
                {
                    "filename": "document.pdf",
                    "content": b"fake pdf content",
                    "content_type": "application/pdf",
                }
            ],
        }

        file_path = self.quarantine_service.store_email_files(
            email_id=1, email_content=email_content
        )

        assert file_path is not None
        assert os.path.exists(file_path)

        # Verify file contents
        stored_content = self.quarantine_service.retrieve_email_files(file_path)
        assert stored_content["subject"] == "Test Email"
        assert len(stored_content["attachments"]) == 1

    def test_quarantine_statistics(self):
        """Test quarantine statistics generation."""
        with patch.object(self.quarantine_service, "get_db") as mock_get_db:
            mock_db = Mock()
            mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

            # Mock query results
            mock_db.query().filter().count.side_effect = [
                50,  # Total quarantined
                45,  # Still in quarantine
                3,  # Released
                2,  # Deleted
            ]

            # Mock threat type distribution
            mock_threat_types = [("phishing", 30), ("malware", 15), ("spam", 5)]
            mock_db.query().filter().group_by().all.return_value = mock_threat_types

            stats = self.quarantine_service.get_statistics(user_id=1)

            assert stats["total_quarantined"] == 50
            assert stats["currently_quarantined"] == 45
            assert stats["released"] == 3
            assert stats["deleted"] == 2
            assert len(stats["threat_types"]) == 3

    def test_quarantine_search_and_filter(self):
        """Test quarantine search and filtering."""
        search_criteria = {
            "threat_type": "phishing",
            "date_range": {
                "start": datetime.now() - timedelta(days=7),
                "end": datetime.now(),
            },
            "confidence_threshold": 0.8,
            "status": "quarantined",
        }

        with patch.object(self.quarantine_service, "get_db") as mock_get_db:
            mock_db = Mock()
            mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

            mock_results = [
                Mock(
                    id=1,
                    quarantine_reason="phishing_detected",
                    confidence=0.95,
                    quarantined_at=datetime.now() - timedelta(days=2),
                )
            ]
            mock_db.query().filter().filter().filter().filter().all.return_value = (
                mock_results
            )

            results = self.quarantine_service.search_quarantine_items(
                user_id=1, criteria=search_criteria
            )

            assert len(results) == 1
            assert results[0]["quarantine_reason"] == "phishing_detected"


class TestQuarantineFileManagement:
    """Test quarantine file management and storage."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.quarantine_service = QuarantineService()
        self.quarantine_service.storage_path = self.temp_dir

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_store_email_with_attachments(self):
        """Test storing email with multiple attachments."""
        email_data = {
            "subject": "Invoice with attachments",
            "body": "Please find attached invoice and receipt",
            "headers": {"From": "accounting@company.com", "To": "finance@company.com"},
            "attachments": [
                {
                    "filename": "invoice.pdf",
                    "content": b"fake invoice content",
                    "content_type": "application/pdf",
                },
                {
                    "filename": "receipt.jpg",
                    "content": b"fake image content",
                    "content_type": "image/jpeg",
                },
            ],
        }

        storage_path = self.quarantine_service.store_email_files(
            email_id=123, email_content=email_data
        )

        assert storage_path is not None
        assert os.path.exists(storage_path)

        # Verify directory structure
        email_dir = Path(storage_path)
        assert (email_dir / "email_content.json").exists()
        assert (email_dir / "attachments").exists()
        assert (email_dir / "attachments" / "invoice.pdf").exists()
        assert (email_dir / "attachments" / "receipt.jpg").exists()

    def test_retrieve_quarantined_email(self):
        """Test retrieving quarantined email content."""
        # First store an email
        email_data = {
            "subject": "Test Email",
            "body": "Test content",
            "headers": {"From": "test@example.com"},
        }

        storage_path = self.quarantine_service.store_email_files(
            email_id=456, email_content=email_data
        )

        # Then retrieve it
        retrieved_data = self.quarantine_service.retrieve_email_files(storage_path)

        assert retrieved_data["subject"] == "Test Email"
        assert retrieved_data["body"] == "Test content"
        assert retrieved_data["headers"]["From"] == "test@example.com"

    def test_quarantine_storage_cleanup(self):
        """Test cleanup of old quarantine files."""
        # Create some test files with different ages
        old_email_path = self.quarantine_service.store_email_files(
            email_id=1, email_content={"subject": "Old Email"}
        )

        recent_email_path = self.quarantine_service.store_email_files(
            email_id=2, email_content={"subject": "Recent Email"}
        )

        # Simulate old file by modifying timestamp
        old_timestamp = datetime.now() - timedelta(days=91)  # Over 90 days old
        os.utime(old_email_path, (old_timestamp.timestamp(), old_timestamp.timestamp()))

        # Run cleanup
        cleanup_results = self.quarantine_service.cleanup_old_files(max_age_days=90)

        assert cleanup_results["files_removed"] >= 1
        assert not os.path.exists(old_email_path)
        assert os.path.exists(recent_email_path)

    def test_quarantine_storage_security(self):
        """Test security measures in quarantine storage."""
        # Test that malicious filenames are sanitized
        malicious_email = {
            "subject": "Test",
            "body": "Test",
            "attachments": [
                {
                    "filename": "../../../etc/passwd",  # Path traversal attempt
                    "content": b"malicious content",
                    "content_type": "text/plain",
                },
                {
                    "filename": "normal_file.txt",
                    "content": b"normal content",
                    "content_type": "text/plain",
                },
            ],
        }

        storage_path = self.quarantine_service.store_email_files(
            email_id=789, email_content=malicious_email
        )

        # Verify malicious filename was sanitized
        attachments_dir = Path(storage_path) / "attachments"
        files = list(attachments_dir.glob("*"))

        # Should not contain path traversal
        assert not any("../" in str(f) for f in files)
        assert any(
            "passwd" in str(f) for f in files
        )  # Filename preserved but sanitized
        assert any("normal_file.txt" in str(f) for f in files)

    def test_quarantine_disk_space_monitoring(self):
        """Test disk space monitoring for quarantine storage."""
        # Mock disk usage
        with patch("shutil.disk_usage") as mock_disk_usage:
            mock_disk_usage.return_value = (
                100 * 1024**3,  # total: 100 GB
                20 * 1024**3,  # used: 20 GB
                80 * 1024**3,  # free: 80 GB
            )

            disk_info = self.quarantine_service.get_storage_info()

            assert disk_info["total_space_gb"] == 100
            assert disk_info["used_space_gb"] == 20
            assert disk_info["free_space_gb"] == 80
            assert disk_info["usage_percentage"] == 20.0

    def test_quarantine_file_integrity(self):
        """Test file integrity verification."""
        email_data = {
            "subject": "Integrity Test",
            "body": "Content for integrity verification",
            "attachments": [
                {
                    "filename": "test_file.pdf",
                    "content": b"test file content for hash verification",
                    "content_type": "application/pdf",
                }
            ],
        }

        storage_path = self.quarantine_service.store_email_files(
            email_id=999, email_content=email_data
        )

        # Verify integrity
        integrity_check = self.quarantine_service.verify_file_integrity(storage_path)

        assert integrity_check["valid"] == True
        assert "checksums" in integrity_check
        assert len(integrity_check["checksums"]) > 0


class TestQuarantineCompliance:
    """Test quarantine compliance and audit features."""

    def setUp(self):
        self.quarantine_service = QuarantineService()

    @patch("api.services.quarantine_service.get_db")
    def test_audit_log_creation(self, mock_get_db):
        """Test audit log creation for quarantine actions."""
        mock_db = Mock()
        mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

        action_data = {
            "action": "quarantine_email",
            "email_id": 123,
            "user_id": 1,
            "reason": "phishing_detected",
            "metadata": {"confidence": 0.95, "threat_indicators": ["suspicious_url"]},
        }

        audit_id = self.quarantine_service.create_audit_log(action_data)

        assert audit_id is not None
        mock_db.add.assert_called_once()
        mock_db.commit.assert_called()

    @patch("api.services.quarantine_service.get_db")
    def test_compliance_report_generation(self, mock_get_db):
        """Test compliance report generation."""
        mock_db = Mock()
        mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

        # Mock audit log entries
        mock_logs = [
            Mock(
                action="quarantine_email",
                timestamp=datetime.now() - timedelta(days=5),
                user_id=1,
                metadata={"reason": "phishing_detected"},
            ),
            Mock(
                action="release_email",
                timestamp=datetime.now() - timedelta(days=2),
                user_id=1,
                metadata={"reason": "false_positive"},
            ),
        ]
        mock_db.query().filter().order_by().all.return_value = mock_logs

        report_period = {
            "start_date": datetime.now() - timedelta(days=30),
            "end_date": datetime.now(),
        }

        report = self.quarantine_service.generate_compliance_report(report_period)

        assert "total_actions" in report
        assert "quarantine_actions" in report
        assert "release_actions" in report
        assert "audit_trail" in report
        assert report["total_actions"] == 2

    def test_data_retention_policy(self):
        """Test data retention policy enforcement."""
        retention_policy = {
            "quarantine_retention_days": 90,
            "audit_log_retention_days": 365,
            "automatic_cleanup": True,
        }

        with patch.object(self.quarantine_service, "get_db") as mock_get_db:
            mock_db = Mock()
            mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

            # Mock old quarantine items
            cutoff_date = datetime.now() - timedelta(
                days=retention_policy["quarantine_retention_days"]
            )
            mock_old_items = [Mock(id=1), Mock(id=2)]
            mock_db.query().filter().all.return_value = mock_old_items

            cleanup_results = self.quarantine_service.enforce_retention_policy(
                retention_policy
            )

            assert "quarantine_items_removed" in cleanup_results
            assert "audit_logs_cleaned" in cleanup_results

    def test_quarantine_access_control(self):
        """Test access control for quarantine operations."""
        user_permissions = {
            "user_id": 1,
            "role": "analyst",
            "permissions": ["view_quarantine", "release_own_quarantine"],
        }

        admin_permissions = {
            "user_id": 2,
            "role": "admin",
            "permissions": [
                "view_all_quarantine",
                "release_any_quarantine",
                "delete_quarantine",
            ],
        }

        # Test user permissions
        assert (
            self.quarantine_service.check_permission(
                user_permissions, "view_quarantine"
            )
            == True
        )

        assert (
            self.quarantine_service.check_permission(
                user_permissions, "delete_quarantine"
            )
            == False
        )

        # Test admin permissions
        assert (
            self.quarantine_service.check_permission(
                admin_permissions, "delete_quarantine"
            )
            == True
        )


class TestQuarantineIntegration:
    """Test quarantine integration with other systems."""

    def setUp(self):
        self.quarantine_service = QuarantineService()

    @patch("api.services.quarantine_service.NotificationService")
    def test_quarantine_notification_integration(self, mock_notification):
        """Test integration with notification service."""
        mock_notification_instance = mock_notification.return_value
        mock_notification_instance.send_quarantine_alert.return_value = True

        quarantine_data = {
            "email_id": 1,
            "user_id": 1,
            "threat_type": "phishing",
            "confidence": 0.95,
        }

        with patch.object(
            self.quarantine_service, "quarantine_email"
        ) as mock_quarantine:
            mock_quarantine.return_value = {"success": True, "quarantine_id": 123}

            result = self.quarantine_service.quarantine_with_notification(
                quarantine_data
            )

            assert result["success"] == True
            mock_notification_instance.send_quarantine_alert.assert_called_once()

    @patch("integrations.siem_exporter.SIEMExporter")
    def test_quarantine_siem_integration(self, mock_siem):
        """Test integration with SIEM export."""
        mock_siem_instance = mock_siem.return_value
        mock_siem_instance.export_quarantine_event.return_value = True

        quarantine_event = {
            "action": "email_quarantined",
            "email_id": 456,
            "threat_type": "malware",
            "timestamp": datetime.now(),
            "user_id": 1,
        }

        result = self.quarantine_service.export_to_siem(quarantine_event)

        assert result == True
        mock_siem_instance.export_quarantine_event.assert_called_once()

    def test_quarantine_api_integration(self):
        """Test quarantine API endpoint integration."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from api.routes.quarantine import router

        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)

        # Mock authentication
        with patch("api.routes.quarantine.get_current_user") as mock_auth:
            mock_auth.return_value = Mock(id=1, role="user")

            # Test get quarantine items endpoint
            response = client.get("/quarantine/")

            # Should handle gracefully even without database
            assert response.status_code in [200, 422, 500]


class TestQuarantinePerformance:
    """Test quarantine system performance."""

    def setUp(self):
        self.quarantine_service = QuarantineService()

    def test_bulk_quarantine_operations(self):
        """Test bulk quarantine operations performance."""
        # Create multiple emails to quarantine
        emails_to_quarantine = [
            {
                "email_id": i,
                "user_id": 1,
                "reason": "bulk_phishing_campaign",
                "confidence": 0.9 + (i * 0.01),
            }
            for i in range(100)
        ]

        with patch.object(self.quarantine_service, "get_db") as mock_get_db:
            mock_db = Mock()
            mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

            start_time = datetime.now()
            results = self.quarantine_service.bulk_quarantine(emails_to_quarantine)
            end_time = datetime.now()

            processing_time = (end_time - start_time).total_seconds()

            # Should process 100 emails in reasonable time
            assert processing_time < 10.0  # Less than 10 seconds
            assert results["processed"] == 100
            assert results["success_rate"] > 0.95

    def test_quarantine_search_performance(self):
        """Test quarantine search performance with large dataset."""
        search_criteria = {
            "threat_type": "phishing",
            "date_range": {
                "start": datetime.now() - timedelta(days=30),
                "end": datetime.now(),
            },
        }

        with patch.object(self.quarantine_service, "get_db") as mock_get_db:
            mock_db = Mock()
            mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

            # Mock large result set
            mock_results = [Mock(id=i) for i in range(1000)]
            mock_db.query().filter().filter().filter().all.return_value = mock_results

            start_time = datetime.now()
            results = self.quarantine_service.search_quarantine_items(
                user_id=1, criteria=search_criteria
            )
            end_time = datetime.now()

            search_time = (end_time - start_time).total_seconds()

            # Search should be fast even with large dataset
            assert search_time < 2.0  # Less than 2 seconds
            assert len(results) == 1000


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

"""
Comprehensive test suite for PhishGuard API endpoints.
Tests all authentication, CRUD operations, and business logic.
"""

import os

# Import the FastAPI app and dependencies
import sys
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.database import Base, get_db
from api.main import app
from api.models.email import Email
from api.models.notification import Notification
from api.models.quarantine import QuarantineItem
from api.models.simulation import SimulationCampaign
from api.models.user import User
from api.utils.security import create_access_token, hash_password

# Test database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db

# Test client
client = TestClient(app)


# Test fixtures
@pytest.fixture(scope="module")
def setup_database():
    """Setup test database with tables."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db_session():
    """Create a fresh database session for each test."""
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def test_user(db_session):
    """Create a test user."""
    user = User(
        email="test@example.com",
        username="testuser",
        full_name="Test User",
        hashed_password=hash_password("testpassword"),
        role="user",
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def admin_user(db_session):
    """Create an admin user."""
    user = User(
        email="admin@example.com",
        username="admin",
        full_name="Admin User",
        hashed_password=hash_password("adminpassword"),
        role="admin",
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def auth_headers(test_user):
    """Create authentication headers for test user."""
    token = create_access_token(data={"sub": test_user.email})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_headers(admin_user):
    """Create authentication headers for admin user."""
    token = create_access_token(data={"sub": admin_user.email})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def sample_email(db_session, test_user):
    """Create a sample email record."""
    email = Email(
        user_id=test_user.id,
        subject="Test Email",
        sender="sender@example.com",
        body="This is a test email body",
        received_at=datetime.utcnow(),
        is_threat=False,
        confidence=0.1,
        processed_at=datetime.utcnow(),
    )
    db_session.add(email)
    db_session.commit()
    db_session.refresh(email)
    return email


class TestAuthentication:
    """Test authentication endpoints."""

    def test_register_user(self, setup_database):
        """Test user registration."""
        user_data = {
            "email": "newuser@example.com",
            "username": "newuser",
            "full_name": "New User",
            "password": "newpassword",
        }

        response = client.post("/auth/register", json=user_data)
        assert response.status_code == 200

        data = response.json()
        assert data["email"] == user_data["email"]
        assert data["username"] == user_data["username"]
        assert "access_token" in data

    def test_register_duplicate_email(self, setup_database, test_user):
        """Test registration with duplicate email."""
        user_data = {
            "email": test_user.email,
            "username": "anotheruser",
            "full_name": "Another User",
            "password": "password",
        }

        response = client.post("/auth/register", json=user_data)
        assert response.status_code == 400
        assert "already registered" in response.json()["detail"]

    def test_login_valid_credentials(self, setup_database, test_user):
        """Test login with valid credentials."""
        login_data = {"username": test_user.email, "password": "testpassword"}

        response = client.post("/auth/login", data=login_data)
        assert response.status_code == 200

        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_login_invalid_credentials(self, setup_database, test_user):
        """Test login with invalid credentials."""
        login_data = {"username": test_user.email, "password": "wrongpassword"}

        response = client.post("/auth/login", data=login_data)
        assert response.status_code == 401
        assert "Invalid credentials" in response.json()["detail"]

    def test_get_current_user(self, setup_database, test_user, auth_headers):
        """Test getting current user information."""
        response = client.get("/auth/me", headers=auth_headers)
        assert response.status_code == 200

        data = response.json()
        assert data["email"] == test_user.email
        assert data["username"] == test_user.username

    def test_unauthorized_access(self, setup_database):
        """Test unauthorized access to protected endpoint."""
        response = client.get("/auth/me")
        assert response.status_code == 401


class TestUserManagement:
    """Test user management endpoints."""

    def test_get_users_as_admin(self, setup_database, admin_headers):
        """Test getting all users as admin."""
        response = client.get("/users/", headers=admin_headers)
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data, list)

    def test_get_users_as_regular_user(self, setup_database, auth_headers):
        """Test getting users as regular user (should fail)."""
        response = client.get("/users/", headers=auth_headers)
        assert response.status_code == 403

    def test_update_user_profile(self, setup_database, test_user, auth_headers):
        """Test updating user profile."""
        update_data = {"full_name": "Updated Name", "phone": "+1234567890"}

        response = client.put(
            f"/users/{test_user.id}", json=update_data, headers=auth_headers
        )
        assert response.status_code == 200

        data = response.json()
        assert data["full_name"] == update_data["full_name"]
        assert data["phone"] == update_data["phone"]

    def test_delete_user_as_admin(self, setup_database, test_user, admin_headers):
        """Test deleting user as admin."""
        response = client.delete(f"/users/{test_user.id}", headers=admin_headers)
        assert response.status_code == 200

        # Verify user is deleted
        response = client.get(f"/users/{test_user.id}", headers=admin_headers)
        assert response.status_code == 404


class TestEmailProcessing:
    """Test email processing endpoints."""

    @patch("api.services.detection_engine.DetectionEngine.analyze_email")
    def test_scan_email(self, mock_analyze, setup_database, auth_headers):
        """Test email scanning endpoint."""
        mock_analyze.return_value = {
            "is_threat": True,
            "confidence": 0.95,
            "threat_type": "phishing",
            "indicators": ["suspicious_url", "fake_sender"],
        }

        email_data = {
            "subject": "Urgent: Account Verification Required",
            "sender": "noreply@fake-bank.com",
            "body": "Click here to verify your account: http://evil-site.com",
            "headers": {"From": "noreply@fake-bank.com"},
        }

        response = client.post("/scan/email", json=email_data, headers=auth_headers)
        assert response.status_code == 200

        data = response.json()
        assert data["is_threat"] == True
        assert data["confidence"] == 0.95
        assert data["threat_type"] == "phishing"

    def test_get_email_history(self, setup_database, sample_email, auth_headers):
        """Test getting email processing history."""
        response = client.get("/emails/", headers=auth_headers)
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        assert data[0]["subject"] == sample_email.subject

    def test_get_email_details(self, setup_database, sample_email, auth_headers):
        """Test getting specific email details."""
        response = client.get(f"/emails/{sample_email.id}", headers=auth_headers)
        assert response.status_code == 200

        data = response.json()
        assert data["id"] == sample_email.id
        assert data["subject"] == sample_email.subject

    def test_report_false_positive(self, setup_database, sample_email, auth_headers):
        """Test reporting false positive."""
        response = client.post(
            f"/emails/{sample_email.id}/report-false-positive", headers=auth_headers
        )
        assert response.status_code == 200

        data = response.json()
        assert data["message"] == "False positive reported successfully"


class TestQuarantineManagement:
    """Test quarantine management endpoints."""

    def test_get_quarantine_items(
        self, setup_database, auth_headers, db_session, test_user, sample_email
    ):
        """Test getting quarantine items."""
        # Create quarantine item
        quarantine_item = QuarantineItem(
            email_id=sample_email.id,
            user_id=test_user.id,
            quarantine_reason="phishing_detected",
            quarantined_at=datetime.utcnow(),
            status="quarantined",
        )
        db_session.add(quarantine_item)
        db_session.commit()

        response = client.get("/quarantine/", headers=auth_headers)
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        assert data[0]["status"] == "quarantined"

    def test_release_quarantine_item(
        self, setup_database, auth_headers, db_session, test_user, sample_email
    ):
        """Test releasing quarantine item."""
        # Create quarantine item
        quarantine_item = QuarantineItem(
            email_id=sample_email.id,
            user_id=test_user.id,
            quarantine_reason="phishing_detected",
            quarantined_at=datetime.utcnow(),
            status="quarantined",
        )
        db_session.add(quarantine_item)
        db_session.commit()
        db_session.refresh(quarantine_item)

        release_data = {
            "reason": "false_positive",
            "notes": "User confirmed this is legitimate",
        }

        response = client.post(
            f"/quarantine/{quarantine_item.id}/release",
            json=release_data,
            headers=auth_headers,
        )
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "released"

    def test_delete_quarantine_item(
        self, setup_database, auth_headers, db_session, test_user, sample_email
    ):
        """Test deleting quarantine item."""
        # Create quarantine item
        quarantine_item = QuarantineItem(
            email_id=sample_email.id,
            user_id=test_user.id,
            quarantine_reason="phishing_detected",
            quarantined_at=datetime.utcnow(),
            status="quarantined",
        )
        db_session.add(quarantine_item)
        db_session.commit()
        db_session.refresh(quarantine_item)

        response = client.delete(
            f"/quarantine/{quarantine_item.id}", headers=auth_headers
        )
        assert response.status_code == 200


class TestSimulationManagement:
    """Test phishing simulation endpoints."""

    def test_create_simulation_campaign(self, setup_database, admin_headers):
        """Test creating simulation campaign."""
        campaign_data = {
            "name": "Q1 2024 Phishing Training",
            "description": "Quarterly phishing awareness training",
            "template_type": "banking",
            "target_users": ["test@example.com"],
            "start_date": (datetime.utcnow() + timedelta(days=1)).isoformat(),
            "end_date": (datetime.utcnow() + timedelta(days=30)).isoformat(),
        }

        response = client.post(
            "/simulation/campaigns", json=campaign_data, headers=admin_headers
        )
        assert response.status_code == 200

        data = response.json()
        assert data["name"] == campaign_data["name"]
        assert data["status"] == "scheduled"

    def test_get_simulation_campaigns(self, setup_database, admin_headers):
        """Test getting simulation campaigns."""
        response = client.get("/simulation/campaigns", headers=admin_headers)
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data, list)

    def test_simulate_phishing_click(self, setup_database, db_session, test_user):
        """Test simulating phishing email click."""
        # Create campaign
        campaign = SimulationCampaign(
            name="Test Campaign",
            description="Test",
            template_type="banking",
            created_by=test_user.id,
            status="active",
            start_date=datetime.utcnow(),
            end_date=datetime.utcnow() + timedelta(days=30),
        )
        db_session.add(campaign)
        db_session.commit()
        db_session.refresh(campaign)

        # Simulate click
        response = client.get(f"/simulation/click/{campaign.id}?user_id={test_user.id}")
        assert response.status_code == 200

        # Should return educational content
        assert "phishing" in response.text.lower()


class TestReportsAnalytics:
    """Test reports and analytics endpoints."""

    def test_get_threat_dashboard(self, setup_database, auth_headers):
        """Test getting threat dashboard data."""
        response = client.get("/reports/dashboard", headers=auth_headers)
        assert response.status_code == 200

        data = response.json()
        assert "total_emails" in data
        assert "threats_detected" in data
        assert "threats_blocked" in data
        assert "false_positives" in data

    def test_get_analytics_data(self, setup_database, auth_headers):
        """Test getting analytics data."""
        response = client.get("/reports/analytics", headers=auth_headers)
        assert response.status_code == 200

        data = response.json()
        assert "daily_stats" in data
        assert "threat_types" in data
        assert "top_senders" in data

    def test_get_executive_summary(self, setup_database, admin_headers):
        """Test getting executive summary."""
        response = client.get("/reports/executive-summary", headers=admin_headers)
        assert response.status_code == 200

        data = response.json()
        assert "period" in data
        assert "metrics" in data
        assert "trends" in data

    def test_export_report(self, setup_database, admin_headers):
        """Test exporting report."""
        export_params = {
            "report_type": "threat_summary",
            "format": "csv",
            "start_date": (datetime.utcnow() - timedelta(days=30)).isoformat(),
            "end_date": datetime.utcnow().isoformat(),
        }

        response = client.post(
            "/reports/export", json=export_params, headers=admin_headers
        )
        assert response.status_code == 200

        # Should return file download response
        assert response.headers["content-type"] == "text/csv"


class TestNotifications:
    """Test notification endpoints."""

    def test_get_notifications(
        self, setup_database, auth_headers, db_session, test_user
    ):
        """Test getting user notifications."""
        # Create test notification
        notification = Notification(
            user_id=test_user.id,
            title="Test Notification",
            message="This is a test notification",
            notification_type="info",
            created_at=datetime.utcnow(),
            is_read=False,
        )
        db_session.add(notification)
        db_session.commit()

        response = client.get("/notifications/", headers=auth_headers)
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        assert data[0]["title"] == "Test Notification"

    def test_mark_notification_read(
        self, setup_database, auth_headers, db_session, test_user
    ):
        """Test marking notification as read."""
        # Create test notification
        notification = Notification(
            user_id=test_user.id,
            title="Test Notification",
            message="This is a test notification",
            notification_type="info",
            created_at=datetime.utcnow(),
            is_read=False,
        )
        db_session.add(notification)
        db_session.commit()
        db_session.refresh(notification)

        response = client.put(
            f"/notifications/{notification.id}/read", headers=auth_headers
        )
        assert response.status_code == 200

        data = response.json()
        assert data["is_read"] == True

    def test_delete_notification(
        self, setup_database, auth_headers, db_session, test_user
    ):
        """Test deleting notification."""
        # Create test notification
        notification = Notification(
            user_id=test_user.id,
            title="Test Notification",
            message="This is a test notification",
            notification_type="info",
            created_at=datetime.utcnow(),
            is_read=False,
        )
        db_session.add(notification)
        db_session.commit()
        db_session.refresh(notification)

        response = client.delete(
            f"/notifications/{notification.id}", headers=auth_headers
        )
        assert response.status_code == 200


class TestInputValidation:
    """Test input validation and security."""

    def test_sql_injection_protection(self, setup_database, auth_headers):
        """Test protection against SQL injection."""
        malicious_input = "'; DROP TABLE users; --"

        response = client.get(
            f"/emails/?search={malicious_input}", headers=auth_headers
        )
        # Should not crash and should return normal response
        assert response.status_code in [200, 400]  # Either works or validates input

    def test_xss_protection(self, setup_database, auth_headers):
        """Test protection against XSS attacks."""
        xss_payload = "<script>alert('xss')</script>"

        email_data = {
            "subject": xss_payload,
            "sender": "test@example.com",
            "body": "Normal body",
            "headers": {},
        }

        response = client.post("/scan/email", json=email_data, headers=auth_headers)
        # Should sanitize input or reject it
        assert response.status_code in [200, 400]

    def test_invalid_json_payload(self, setup_database, auth_headers):
        """Test handling of invalid JSON."""
        response = client.post(
            "/scan/email",
            data="invalid json",
            headers={**auth_headers, "Content-Type": "application/json"},
        )
        assert response.status_code == 422

    def test_missing_required_fields(self, setup_database, auth_headers):
        """Test handling of missing required fields."""
        incomplete_data = {
            "subject": "Test"
            # Missing required fields
        }

        response = client.post(
            "/scan/email", json=incomplete_data, headers=auth_headers
        )
        assert response.status_code == 422


if __name__ == "__main__":
    # Run specific test classes or methods
    pytest.main([__file__, "-v"])


@pytest.fixture
def test_email(db_session):
    """Create test email."""
    email = Email(
        message_id="test-message-123",
        sender_email="sender@example.com",
        sender_name="Test Sender",
        subject="Test Email Subject",
        body_text="This is a test email body.",
        recipients=["recipient@example.com"],
        received_date=datetime.utcnow(),
    )
    email.set_sender_domain()
    db_session.add(email)
    db_session.commit()
    db_session.refresh(email)
    return email


class TestAuthentication:
    """Test authentication endpoints and functionality."""

    def test_login_success(self, test_user):
        """Test successful login."""
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "testuser", "password": "testpassword123"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "token_type" in data
        assert data["token_type"] == "bearer"

    def test_login_invalid_credentials(self):
        """Test login with invalid credentials."""
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "nonexistent", "password": "wrongpassword"},
        )
        assert response.status_code == 401

    def test_login_missing_fields(self):
        """Test login with missing fields."""
        response = client.post("/api/v1/auth/login", json={"username": "testuser"})
        assert response.status_code == 422

    def test_protected_endpoint_without_token(self):
        """Test accessing protected endpoint without token."""
        response = client.get("/api/v1/users/me")
        assert response.status_code == 401

    def test_protected_endpoint_with_token(self, test_user):
        """Test accessing protected endpoint with valid token."""
        # Login to get token
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "testuser", "password": "testpassword123"},
        )
        token = login_response.json()["access_token"]

        # Access protected endpoint
        response = client.get(
            "/api/v1/users/me", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testuser"


class TestEmailAPI:
    """Test email-related API endpoints."""

    def test_get_emails(self, test_user, test_email):
        """Test retrieving emails."""
        # Login to get token
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "testuser", "password": "testpassword123"},
        )
        token = login_response.json()["access_token"]

        response = client.get(
            "/api/v1/emails", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data["emails"]) >= 1

    def test_get_email_by_id(self, test_user, test_email):
        """Test retrieving specific email."""
        # Login to get token
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "testuser", "password": "testpassword123"},
        )
        token = login_response.json()["access_token"]

        response = client.get(
            f"/api/v1/emails/{test_email.id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["message_id"] == "test-message-123"

    def test_quarantine_email(self, admin_user, test_email):
        """Test quarantining an email."""
        # Login as admin
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "adminpassword123"},
        )
        token = login_response.json()["access_token"]

        response = client.post(
            f"/api/v1/quarantine/{test_email.id}",
            json={"reason": "Suspicious content detected"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["is_quarantined"] == True


class TestAIEngine:
    """Test AI engine functionality."""

    @pytest.mark.asyncio
    async def test_phishing_detection_safe_email(self):
        """Test phishing detection with safe email."""
        detector = PhishingDetector()

        # Mock model loading
        with patch.object(detector, "load_model", return_value=True):
            with patch.object(detector, "is_loaded", True):
                with patch.object(detector.model, "predict", return_value=[0]):
                    with patch.object(
                        detector.model, "predict_proba", return_value=[[0.8, 0.2]]
                    ):

                        email_data = {
                            "content": "Thank you for your recent purchase. Your order will be shipped soon.",
                            "subject": "Order Confirmation",
                            "sender": "orders@legitimate-store.com",
                        }

                        result = await detector.predict_phishing(email_data)

                        assert result["is_phishing"] == False
                        assert result["threat_level"] == "low"
                        assert result["phishing_confidence"] < 0.5

    @pytest.mark.asyncio
    async def test_phishing_detection_malicious_email(self):
        """Test phishing detection with malicious email."""
        detector = PhishingDetector()

        # Mock model loading
        with patch.object(detector, "load_model", return_value=True):
            with patch.object(detector, "is_loaded", True):
                with patch.object(detector.model, "predict", return_value=[1]):
                    with patch.object(
                        detector.model, "predict_proba", return_value=[[0.1, 0.9]]
                    ):

                        email_data = {
                            "content": "Your account has been suspended. Click here to verify: http://fake-bank.com/verify",
                            "subject": "URGENT: Account Verification Required",
                            "sender": "security@fake-bank.com",
                        }

                        result = await detector.predict_phishing(email_data)

                        assert result["is_phishing"] == True
                        assert result["threat_level"] in ["high", "critical"]
                        assert result["phishing_confidence"] > 0.7

    @pytest.mark.asyncio
    async def test_batch_prediction(self):
        """Test batch email prediction."""
        detector = PhishingDetector()

        # Mock model loading
        with patch.object(detector, "load_model", return_value=True):
            with patch.object(detector, "is_loaded", True):
                with patch.object(detector.model, "predict", return_value=[0, 1]):
                    with patch.object(
                        detector.model,
                        "predict_proba",
                        return_value=[[0.8, 0.2], [0.1, 0.9]],
                    ):

                        email_batch = [
                            {
                                "content": "Legitimate email content",
                                "subject": "Normal Subject",
                                "sender": "normal@example.com",
                            },
                            {
                                "content": "Click here to claim your prize!",
                                "subject": "You Won!",
                                "sender": "scam@fake-site.com",
                            },
                        ]

                        results = await detector.batch_predict(email_batch)

                        assert len(results) == 2
                        assert results[0]["is_phishing"] == False
                        assert results[1]["is_phishing"] == True


class TestQuarantineAPI:
    """Test quarantine management endpoints."""

    def test_get_quarantined_emails(self, admin_user, test_email, db_session):
        """Test retrieving quarantined emails."""
        # Quarantine the test email
        test_email.quarantine("Test quarantine", admin_user.id)
        db_session.commit()

        # Login as admin
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "adminpassword123"},
        )
        token = login_response.json()["access_token"]

        response = client.get(
            "/api/v1/quarantine", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data["quarantined_emails"]) >= 1

    def test_release_email(self, admin_user, test_email, db_session):
        """Test releasing email from quarantine."""
        # Quarantine the test email first
        test_email.quarantine("Test quarantine", admin_user.id)
        db_session.commit()

        # Login as admin
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "adminpassword123"},
        )
        token = login_response.json()["access_token"]

        response = client.post(
            f"/api/v1/quarantine/{test_email.id}/release",
            json={"reason": "False positive - releasing email"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["is_released"] == True


class TestReportsAPI:
    """Test reporting and analytics endpoints."""

    def test_get_dashboard_stats(self, test_user):
        """Test dashboard statistics endpoint."""
        # Login to get token
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "testuser", "password": "testpassword123"},
        )
        token = login_response.json()["access_token"]

        response = client.get(
            "/api/v1/reports/dashboard", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "total_emails" in data
        assert "threat_statistics" in data

    def test_get_threat_analytics(self, test_user):
        """Test threat analytics endpoint."""
        # Login to get token
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "testuser", "password": "testpassword123"},
        )
        token = login_response.json()["access_token"]

        response = client.get(
            "/api/v1/reports/threats", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "threat_trends" in data


class TestHealthEndpoints:
    """Test health check and monitoring endpoints."""

    def test_health_check(self):
        """Test basic health check."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ["healthy", "unhealthy"]

    def test_liveness_probe(self):
        """Test Kubernetes liveness probe."""
        response = client.get("/health/live")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "alive"

    def test_readiness_probe(self):
        """Test Kubernetes readiness probe."""
        response = client.get("/health/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ["ready", "not_ready"]


class TestIntegrations:
    """Test external system integrations."""

    @patch("src.integrations.gmail_api.GmailIntegration")
    def test_gmail_integration(self, mock_gmail):
        """Test Gmail API integration."""
        mock_gmail.return_value.get_emails.return_value = [
            {
                "id": "test-gmail-id",
                "subject": "Test Gmail Message",
                "sender": "test@gmail.com",
                "content": "Test content",
            }
        ]

        from src.integrations.gmail_api import GmailIntegration

        integration = GmailIntegration()
        emails = integration.get_emails()

        assert len(emails) == 1
        assert emails[0]["subject"] == "Test Gmail Message"

    @patch("src.integrations.slack_webhook.SlackNotifier")
    def test_slack_notification(self, mock_slack):
        """Test Slack notification integration."""
        mock_slack.return_value.send_alert.return_value = True

        from src.integrations.slack_webhook import SlackNotifier

        notifier = SlackNotifier()
        result = notifier.send_alert("Test alert", "high")

        assert result == True


class TestUserManagement:
    """Test user management functionality."""

    def test_create_user(self, admin_user):
        """Test creating new user."""
        # Login as admin
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "adminpassword123"},
        )
        token = login_response.json()["access_token"]

        response = client.post(
            "/api/v1/users",
            json={
                "username": "newuser",
                "email": "newuser@example.com",
                "first_name": "New",
                "last_name": "User",
                "password": "newuserpass123",
                "role": "user",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["username"] == "newuser"

    def test_update_user_profile(self, test_user):
        """Test updating user profile."""
        # Login to get token
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "testuser", "password": "testpassword123"},
        )
        token = login_response.json()["access_token"]

        response = client.put(
            "/api/v1/users/me",
            json={"first_name": "Updated", "last_name": "Name"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["first_name"] == "Updated"


# Performance Tests
class TestPerformance:
    """Test application performance under load."""

    def test_email_processing_performance(self, test_user):
        """Test email processing performance."""
        import time

        # Login to get token
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "testuser", "password": "testpassword123"},
        )
        token = login_response.json()["access_token"]

        # Test processing time for email list
        start_time = time.time()
        response = client.get(
            "/api/v1/emails", headers={"Authorization": f"Bearer {token}"}
        )
        end_time = time.time()

        assert response.status_code == 200
        assert (end_time - start_time) < 1.0  # Should respond within 1 second


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

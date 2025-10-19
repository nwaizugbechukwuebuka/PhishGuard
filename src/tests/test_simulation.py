"""
Comprehensive test suite for PhishGuard simulation system.
Tests phishing simulation campaigns, user tracking, and training effectiveness.
"""

import json
import os
import sys
from datetime import datetime, timedelta
from unittest.mock import MagicMock, Mock, patch
from urllib.parse import urlparse

import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.models.simulation import (
    SimulationCampaign,
    SimulationEmail,
    SimulationInteraction,
)
from api.models.user import User
from api.services.simulation_service import SimulationService
from tasks.simulation_tasks import (
    create_simulation_campaign,
    process_simulation_interaction,
    schedule_simulation_emails,
    send_simulation_email,
    send_simulation_feedback,
)


class TestSimulationService:
    """Test simulation service functionality."""

    def setUp(self):
        self.simulation_service = SimulationService()

    @patch("api.services.simulation_service.get_db")
    def test_create_simulation_campaign(self, mock_get_db):
        """Test creating a simulation campaign."""
        mock_db = Mock()
        mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

        campaign_data = {
            "name": "Q1 2024 Phishing Training",
            "description": "Quarterly phishing awareness campaign",
            "template_type": "banking",
            "target_users": ["user1@company.com", "user2@company.com"],
            "start_date": datetime.now() + timedelta(days=1),
            "end_date": datetime.now() + timedelta(days=30),
            "created_by": 1,
        }

        result = self.simulation_service.create_campaign(campaign_data)

        assert result["success"] == True
        assert "campaign_id" in result
        mock_db.add.assert_called_once()
        mock_db.commit.assert_called()

    @patch("api.services.simulation_service.get_db")
    def test_get_campaign_list(self, mock_get_db):
        """Test retrieving campaign list."""
        mock_db = Mock()
        mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

        mock_campaigns = [
            Mock(
                id=1,
                name="Banking Simulation",
                status="active",
                created_at=datetime.now(),
                target_count=100,
                completion_rate=75.5,
            ),
            Mock(
                id=2,
                name="IT Support Simulation",
                status="scheduled",
                created_at=datetime.now() - timedelta(days=2),
                target_count=50,
                completion_rate=0.0,
            ),
        ]

        mock_db.query().filter().order_by().all.return_value = mock_campaigns

        campaigns = self.simulation_service.get_campaigns(created_by=1)

        assert len(campaigns) == 2
        assert campaigns[0]["name"] == "Banking Simulation"
        assert campaigns[0]["status"] == "active"

    @patch("api.services.simulation_service.get_db")
    def test_schedule_simulation_emails(self, mock_get_db):
        """Test scheduling simulation emails."""
        mock_db = Mock()
        mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

        campaign_id = 1
        target_users = [
            {"email": "user1@company.com", "name": "John Doe"},
            {"email": "user2@company.com", "name": "Jane Smith"},
        ]

        schedule_config = {
            "distribution_method": "random",
            "time_window": {"start_hour": 9, "end_hour": 17},
            "days_spread": 7,
        }

        result = self.simulation_service.schedule_emails(
            campaign_id, target_users, schedule_config
        )

        assert result["success"] == True
        assert result["emails_scheduled"] == 2
        assert mock_db.add.call_count == 2  # Two emails scheduled

    @patch("api.services.simulation_service.get_db")
    def test_track_simulation_interaction(self, mock_get_db):
        """Test tracking simulation interactions."""
        mock_db = Mock()
        mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

        interaction_data = {
            "simulation_email_id": 1,
            "user_email": "user@company.com",
            "interaction_type": "email_opened",
            "timestamp": datetime.now(),
            "user_agent": "Mozilla/5.0...",
            "ip_address": "192.168.1.100",
        }

        result = self.simulation_service.track_interaction(interaction_data)

        assert result["success"] == True
        mock_db.add.assert_called_once()
        mock_db.commit.assert_called()

    @patch("api.services.simulation_service.get_db")
    def test_get_campaign_analytics(self, mock_get_db):
        """Test campaign analytics generation."""
        mock_db = Mock()
        mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

        # Mock campaign
        mock_campaign = Mock(
            id=1,
            name="Test Campaign",
            start_date=datetime.now() - timedelta(days=7),
            end_date=datetime.now() + timedelta(days=23),
        )
        mock_db.query().filter().first.return_value = mock_campaign

        # Mock simulation emails
        mock_emails = [Mock(id=i) for i in range(1, 11)]  # 10 emails
        mock_db.query().filter().all.return_value = mock_emails

        # Mock interactions
        mock_interactions = [
            Mock(interaction_type="email_opened", timestamp=datetime.now()),
            Mock(interaction_type="link_clicked", timestamp=datetime.now()),
            Mock(interaction_type="credentials_entered", timestamp=datetime.now()),
            Mock(interaction_type="reported_suspicious", timestamp=datetime.now()),
        ]
        mock_db.query().join().filter().all.return_value = mock_interactions

        analytics = self.simulation_service.get_campaign_analytics(campaign_id=1)

        assert "campaign_info" in analytics
        assert "email_metrics" in analytics
        assert "interaction_metrics" in analytics
        assert analytics["email_metrics"]["total_sent"] == 10
        assert analytics["interaction_metrics"]["total_interactions"] == 4

    def test_simulation_template_management(self):
        """Test simulation template management."""
        template_data = {
            "template_type": "banking",
            "subject_line": "Urgent: Account Verification Required",
            "email_body": "Your account will be suspended unless you verify immediately.",
            "sender_display": "Bank Security Team",
            "landing_page_url": "https://fake-bank-verify.com/login",
            "difficulty_level": "medium",
        }

        result = self.simulation_service.create_template(template_data)

        assert result["success"] == True
        assert "template_id" in result

        # Test template retrieval
        templates = self.simulation_service.get_templates(template_type="banking")
        assert len(templates) >= 1

    def test_user_simulation_history(self):
        """Test user simulation history tracking."""
        with patch.object(self.simulation_service, "get_db") as mock_get_db:
            mock_db = Mock()
            mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

            # Mock user simulation history
            mock_history = [
                Mock(
                    campaign_name="Banking Simulation",
                    sent_date=datetime.now() - timedelta(days=30),
                    interaction_type="link_clicked",
                    outcome="failed",
                    feedback_sent=True,
                ),
                Mock(
                    campaign_name="IT Support Simulation",
                    sent_date=datetime.now() - timedelta(days=15),
                    interaction_type="reported_suspicious",
                    outcome="passed",
                    feedback_sent=True,
                ),
            ]
            mock_db.query().join().filter().order_by().all.return_value = mock_history

            history = self.simulation_service.get_user_history(
                user_email="user@company.com"
            )

            assert len(history) == 2
            assert history[0]["outcome"] == "failed"
            assert history[1]["outcome"] == "passed"


class TestSimulationTemplates:
    """Test simulation template system."""

    def setUp(self):
        self.simulation_service = SimulationService()

    def test_banking_template_generation(self):
        """Test banking phishing template generation."""
        template_config = {
            "template_type": "banking",
            "target_bank": "Example Bank",
            "urgency_level": "high",
            "personalization": {"user_name": "John Doe", "account_number": "****1234"},
        }

        template = self.simulation_service.generate_email_template(template_config)

        assert "Example Bank" in template["subject"]
        assert "John Doe" in template["body"]
        assert "****1234" in template["body"]
        assert "urgent" in template["body"].lower()
        assert template["sender_domain"] != "example-bank.com"  # Should be spoofed

    def test_it_support_template_generation(self):
        """Test IT support phishing template generation."""
        template_config = {
            "template_type": "it_support",
            "company_name": "TechCorp",
            "issue_type": "password_reset",
            "personalization": {"user_name": "Jane Smith", "employee_id": "EMP001"},
        }

        template = self.simulation_service.generate_email_template(template_config)

        assert (
            "IT Support" in template["subject"]
            or "Technical Support" in template["subject"]
        )
        assert "TechCorp" in template["body"]
        assert "Jane Smith" in template["body"]
        assert "password" in template["body"].lower()

    def test_social_engineering_template(self):
        """Test social engineering template generation."""
        template_config = {
            "template_type": "social_engineering",
            "scenario": "ceo_fraud",
            "personalization": {
                "user_name": "Finance Manager",
                "ceo_name": "Robert Johnson",
            },
        }

        template = self.simulation_service.generate_email_template(template_config)

        assert "Robert Johnson" in template["body"]
        assert "Finance Manager" in template["body"]
        assert (
            "urgent" in template["body"].lower()
            or "confidential" in template["body"].lower()
        )

    def test_template_difficulty_levels(self):
        """Test different template difficulty levels."""
        difficulties = ["easy", "medium", "hard"]

        for difficulty in difficulties:
            template_config = {
                "template_type": "banking",
                "difficulty_level": difficulty,
                "personalization": {"user_name": "Test User"},
            }

            template = self.simulation_service.generate_email_template(template_config)

            assert template["difficulty_level"] == difficulty

            if difficulty == "easy":
                # Easy templates should have obvious red flags
                assert any(
                    indicator in template["body"].lower()
                    for indicator in [
                        "click here immediately",
                        "urgent action required",
                    ]
                )
            elif difficulty == "hard":
                # Hard templates should be more sophisticated
                assert len(template["body"]) > 200  # More detailed content

    def test_template_localization(self):
        """Test template localization support."""
        template_config = {
            "template_type": "banking",
            "language": "es",  # Spanish
            "target_bank": "Banco Ejemplo",
            "personalization": {"user_name": "María García"},
        }

        template = self.simulation_service.generate_email_template(template_config)

        # Should contain Spanish content
        assert "Banco Ejemplo" in template["body"]
        assert "María García" in template["body"]
        # Basic Spanish words for banking
        assert any(
            word in template["body"].lower()
            for word in ["cuenta", "banco", "verificar"]
        )


class TestSimulationInteractions:
    """Test simulation interaction tracking and analysis."""

    def setUp(self):
        self.simulation_service = SimulationService()

    def test_email_open_tracking(self):
        """Test email open tracking."""
        interaction_data = {
            "simulation_email_id": 1,
            "interaction_type": "email_opened",
            "timestamp": datetime.now(),
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "ip_address": "192.168.1.100",
        }

        with patch.object(self.simulation_service, "track_interaction") as mock_track:
            mock_track.return_value = {"success": True}

            result = self.simulation_service.process_email_open(
                simulation_email_id=1, request_data=interaction_data
            )

            assert result["success"] == True
            mock_track.assert_called_once()

    def test_link_click_tracking(self):
        """Test phishing link click tracking."""
        click_data = {
            "simulation_email_id": 1,
            "link_id": "primary_cta",
            "timestamp": datetime.now(),
            "referer": "https://email.company.com",
            "user_agent": "Mozilla/5.0...",
        }

        with patch.object(self.simulation_service, "track_interaction") as mock_track:
            mock_track.return_value = {"success": True}

            result = self.simulation_service.process_link_click(click_data)

            assert result["success"] == True
            assert result["show_landing_page"] == True
            mock_track.assert_called_once()

    def test_credential_submission_tracking(self):
        """Test credential submission tracking."""
        submission_data = {
            "simulation_email_id": 1,
            "username_entered": "user@company.com",
            "password_entered": "[REDACTED]",  # Should be logged as redacted
            "additional_fields": {"phone": "555-0123", "ssn": "[REDACTED]"},
            "timestamp": datetime.now(),
        }

        with patch.object(self.simulation_service, "track_interaction") as mock_track:
            mock_track.return_value = {"success": True}

            result = self.simulation_service.process_credential_submission(
                submission_data
            )

            assert result["success"] == True
            assert result["show_education"] == True
            mock_track.assert_called_once()

            # Verify sensitive data is not stored
            call_args = mock_track.call_args[0][0]
            assert "[REDACTED]" in str(call_args)

    def test_suspicious_email_reporting(self):
        """Test reporting email as suspicious."""
        report_data = {
            "simulation_email_id": 1,
            "user_email": "user@company.com",
            "report_method": "security_button",
            "timestamp": datetime.now(),
            "reason": "Suspicious sender and urgent language",
        }

        with patch.object(self.simulation_service, "track_interaction") as mock_track:
            mock_track.return_value = {"success": True}

            result = self.simulation_service.process_suspicious_report(report_data)

            assert result["success"] == True
            assert result["outcome"] == "passed"
            assert result["show_positive_feedback"] == True
            mock_track.assert_called_once()

    def test_interaction_analytics(self):
        """Test interaction analytics calculation."""
        campaign_id = 1

        with patch.object(self.simulation_service, "get_db") as mock_get_db:
            mock_db = Mock()
            mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

            # Mock interaction data
            mock_interactions = [
                Mock(interaction_type="email_opened", timestamp=datetime.now()),
                Mock(interaction_type="link_clicked", timestamp=datetime.now()),
                Mock(interaction_type="credentials_entered", timestamp=datetime.now()),
                Mock(
                    interaction_type="reported_suspicious",
                    timestamp=datetime.now() + timedelta(minutes=5),
                ),
            ]
            mock_db.query().join().filter().all.return_value = mock_interactions

            analytics = self.simulation_service.calculate_interaction_analytics(
                campaign_id
            )

            assert analytics["total_interactions"] == 4
            assert analytics["open_rate"] > 0
            assert analytics["click_rate"] > 0
            assert analytics["report_rate"] > 0
            assert "avg_time_to_report" in analytics


class TestSimulationEducation:
    """Test educational feedback and training components."""

    def setUp(self):
        self.simulation_service = SimulationService()

    def test_educational_feedback_generation(self):
        """Test generation of educational feedback."""
        interaction_context = {
            "simulation_type": "banking",
            "user_action": "clicked_link",
            "difficulty_level": "medium",
            "user_history": {"previous_simulations": 3, "pass_rate": 0.67},
        }

        feedback = self.simulation_service.generate_educational_feedback(
            interaction_context
        )

        assert "explanation" in feedback
        assert "red_flags" in feedback
        assert "best_practices" in feedback
        assert "additional_resources" in feedback
        assert len(feedback["red_flags"]) > 0

    def test_personalized_training_recommendations(self):
        """Test personalized training recommendations."""
        user_profile = {
            "email": "user@company.com",
            "department": "Finance",
            "simulation_history": [
                {"type": "banking", "outcome": "failed"},
                {"type": "it_support", "outcome": "passed"},
                {"type": "social_engineering", "outcome": "failed"},
            ],
            "weak_areas": ["urgency_tactics", "domain_spoofing"],
        }

        recommendations = self.simulation_service.generate_training_recommendations(
            user_profile
        )

        assert "recommended_modules" in recommendations
        assert "priority_areas" in recommendations
        assert "estimated_time" in recommendations
        assert len(recommendations["recommended_modules"]) > 0
        assert "urgency_tactics" in recommendations["priority_areas"]

    def test_educational_content_delivery(self):
        """Test educational content delivery system."""
        education_request = {
            "user_email": "user@company.com",
            "simulation_id": 1,
            "failed_area": "link_clicking",
            "content_format": "interactive",
        }

        content = self.simulation_service.deliver_educational_content(education_request)

        assert "content_type" in content
        assert "modules" in content
        assert "interactive_elements" in content
        assert content["content_type"] == "interactive"

    def test_progress_tracking(self):
        """Test user progress tracking."""
        user_email = "user@company.com"

        with patch.object(self.simulation_service, "get_db") as mock_get_db:
            mock_db = Mock()
            mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

            # Mock user progress data
            mock_progress = [
                Mock(
                    simulation_date=datetime.now() - timedelta(days=90),
                    outcome="failed",
                    improvement_score=0.2,
                ),
                Mock(
                    simulation_date=datetime.now() - timedelta(days=60),
                    outcome="passed",
                    improvement_score=0.6,
                ),
                Mock(
                    simulation_date=datetime.now() - timedelta(days=30),
                    outcome="passed",
                    improvement_score=0.8,
                ),
            ]
            mock_db.query().filter().order_by().all.return_value = mock_progress

            progress = self.simulation_service.track_user_progress(user_email)

            assert "overall_improvement" in progress
            assert "trend_direction" in progress
            assert "current_score" in progress
            assert progress["trend_direction"] == "improving"


class TestSimulationCampaignManagement:
    """Test simulation campaign management features."""

    def setUp(self):
        self.simulation_service = SimulationService()

    @patch("api.services.simulation_service.get_db")
    def test_campaign_lifecycle_management(self, mock_get_db):
        """Test complete campaign lifecycle."""
        mock_db = Mock()
        mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

        # Create campaign
        campaign_data = {
            "name": "Lifecycle Test Campaign",
            "template_type": "banking",
            "target_users": ["user1@company.com", "user2@company.com"],
            "start_date": datetime.now() + timedelta(days=1),
        }

        mock_campaign = Mock(id=1, status="scheduled")
        mock_db.add.return_value = None
        mock_db.commit.return_value = None
        mock_db.refresh.return_value = None

        # Test campaign creation
        create_result = self.simulation_service.create_campaign(campaign_data)
        assert create_result["success"] == True

        # Test campaign activation
        mock_db.query().filter().first.return_value = mock_campaign
        activate_result = self.simulation_service.activate_campaign(campaign_id=1)
        assert activate_result["success"] == True

        # Test campaign completion
        complete_result = self.simulation_service.complete_campaign(campaign_id=1)
        assert complete_result["success"] == True

    def test_campaign_scheduling_optimization(self):
        """Test campaign scheduling optimization."""
        target_users = [
            {
                "email": f"user{i}@company.com",
                "timezone": "UTC-5",
                "department": "Finance",
            }
            for i in range(100)
        ]

        schedule_config = {
            "distribution_method": "optimized",
            "respect_timezones": True,
            "avoid_weekends": True,
            "spread_duration_hours": 168,  # 1 week
        }

        schedule = self.simulation_service.optimize_email_schedule(
            target_users, schedule_config
        )

        assert len(schedule) == 100
        assert all("send_time" in email for email in schedule)

        # Verify no weekend sends if configured
        if schedule_config["avoid_weekends"]:
            weekend_sends = [
                email
                for email in schedule
                if email["send_time"].weekday() in [5, 6]  # Saturday, Sunday
            ]
            assert len(weekend_sends) == 0

    def test_campaign_template_ab_testing(self):
        """Test A/B testing for simulation templates."""
        campaign_id = 1

        template_variants = [
            {
                "variant_name": "A_urgent",
                "subject": "URGENT: Account Verification Required",
                "urgency_level": "high",
            },
            {
                "variant_name": "B_polite",
                "subject": "Please verify your account information",
                "urgency_level": "low",
            },
        ]

        target_users = [f"user{i}@company.com" for i in range(100)]

        ab_config = {"split_ratio": 0.5, "randomization_seed": 12345}  # 50/50 split

        assignment = self.simulation_service.setup_ab_test(
            campaign_id, template_variants, target_users, ab_config
        )

        assert len(assignment["variant_A"]) + len(assignment["variant_B"]) == 100
        assert (
            abs(len(assignment["variant_A"]) - len(assignment["variant_B"])) <= 1
        )  # Even split

    def test_campaign_compliance_controls(self):
        """Test campaign compliance and safety controls."""
        campaign_data = {
            "name": "Compliance Test Campaign",
            "target_users": ["ceo@company.com", "legal@company.com"],
            "template_type": "high_privilege_attack",
        }

        # Test executive protection
        compliance_check = self.simulation_service.check_campaign_compliance(
            campaign_data
        )

        assert "executive_targets" in compliance_check["warnings"]
        assert compliance_check["requires_approval"] == True

        # Test frequency limits
        frequent_campaign = {
            "name": "Frequent Campaign",
            "target_users": ["user@company.com"],
            "last_simulation_days_ago": 5,  # Too recent
        }

        frequency_check = self.simulation_service.check_simulation_frequency(
            frequent_campaign
        )
        assert frequency_check["allowed"] == False
        assert "too_frequent" in frequency_check["reason"]


class TestSimulationReporting:
    """Test simulation reporting and analytics."""

    def setUp(self):
        self.simulation_service = SimulationService()

    def test_executive_dashboard_report(self):
        """Test executive dashboard report generation."""
        report_period = {
            "start_date": datetime.now() - timedelta(days=90),
            "end_date": datetime.now(),
        }

        with patch.object(self.simulation_service, "get_db") as mock_get_db:
            mock_db = Mock()
            mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

            # Mock campaign data
            mock_campaigns = [Mock(id=i, status="completed") for i in range(5)]
            mock_db.query().filter().filter().all.return_value = mock_campaigns

            # Mock overall metrics
            mock_db.query().join().filter().count.side_effect = [
                500,
                300,
                50,
                150,
            ]  # sent, opened, clicked, reported

            report = self.simulation_service.generate_executive_report(report_period)

            assert "summary_metrics" in report
            assert "trend_analysis" in report
            assert "risk_assessment" in report
            assert "recommendations" in report
            assert report["summary_metrics"]["total_campaigns"] == 5

    def test_departmental_performance_report(self):
        """Test departmental performance analysis."""
        departments = ["Finance", "IT", "HR", "Sales"]

        with patch.object(self.simulation_service, "get_db") as mock_get_db:
            mock_db = Mock()
            mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

            # Mock departmental data
            mock_dept_data = [
                Mock(department="Finance", pass_rate=0.65, avg_report_time=45),
                Mock(department="IT", pass_rate=0.85, avg_report_time=30),
                Mock(department="HR", pass_rate=0.70, avg_report_time=60),
                Mock(department="Sales", pass_rate=0.55, avg_report_time=90),
            ]
            mock_db.query().join().group_by().all.return_value = mock_dept_data

            report = self.simulation_service.generate_departmental_report()

            assert len(report["departments"]) == 4
            assert report["departments"][0]["department"] == "Finance"
            assert "risk_ranking" in report
            assert "improvement_recommendations" in report

    def test_individual_user_report(self):
        """Test individual user performance report."""
        user_email = "user@company.com"

        with patch.object(self.simulation_service, "get_db") as mock_get_db:
            mock_db = Mock()
            mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

            # Mock user simulation history
            mock_history = [
                Mock(
                    campaign_name="Banking Test",
                    sent_date=datetime.now() - timedelta(days=30),
                    outcome="failed",
                    time_to_click=120,
                    template_type="banking",
                ),
                Mock(
                    campaign_name="IT Support Test",
                    sent_date=datetime.now() - timedelta(days=15),
                    outcome="passed",
                    time_to_report=300,
                    template_type="it_support",
                ),
            ]
            mock_db.query().join().filter().order_by().all.return_value = mock_history

            report = self.simulation_service.generate_user_report(user_email)

            assert "user_profile" in report
            assert "simulation_history" in report
            assert "performance_trends" in report
            assert "training_recommendations" in report
            assert len(report["simulation_history"]) == 2

    def test_trend_analysis(self):
        """Test trend analysis across time periods."""
        time_periods = [
            {
                "start": datetime.now() - timedelta(days=180),
                "end": datetime.now() - timedelta(days=90),
            },
            {"start": datetime.now() - timedelta(days=90), "end": datetime.now()},
        ]

        with patch.object(self.simulation_service, "get_db") as mock_get_db:
            mock_db = Mock()
            mock_get_db.return_value.__next__ = Mock(return_value=mock_db)

            # Mock trend data for two periods
            mock_db.query().join().filter().filter().count.side_effect = [
                200,
                120,
                30,
                50,  # Period 1: sent, opened, clicked, reported
                250,
                180,
                25,
                80,  # Period 2: sent, opened, clicked, reported
            ]

            trends = self.simulation_service.analyze_trends(time_periods)

            assert "period_comparison" in trends
            assert "improvement_metrics" in trends
            assert (
                trends["improvement_metrics"]["click_rate_change"] < 0
            )  # Improved (lower click rate)
            assert (
                trends["improvement_metrics"]["report_rate_change"] > 0
            )  # Improved (higher report rate)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

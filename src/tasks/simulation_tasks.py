"""
Celery tasks for managing phishing simulations and security training.
This module handles simulation campaigns, email generation, and training analytics.
"""

import logging
import os
import random
import sys
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from celery import Celery
from sqlalchemy.orm import Session

# Add src directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.database import get_db
from api.models.email import Email
from api.models.simulation import Simulation, SimulationResult, SimulationTemplate
from api.models.user import User
from api.services.notification_service import NotificationService
from api.services.simulation_service import SimulationService
from api.utils.config import settings
from api.utils.logger import get_logger
from api.utils.mail_client import MailClient
from tasks.notify_tasks import send_email_notification

# Get Celery app instance
from tasks.scan_tasks import celery_app

logger = get_logger(__name__)

# Initialize services
simulation_service = SimulationService()
notification_service = NotificationService()
mail_client = MailClient()


@celery_app.task(bind=True, max_retries=3, default_retry_delay=60)
def create_simulation_campaign(
    self, simulation_config: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Create and start a new phishing simulation campaign.

    Args:
        simulation_config: Configuration for the simulation campaign

    Returns:
        Dictionary with campaign creation results
    """
    try:
        logger.info(f"Creating simulation campaign: {simulation_config.get('name')}")

        db = next(get_db())

        # Create simulation record
        simulation = Simulation(
            name=simulation_config["name"],
            description=simulation_config.get("description", ""),
            template_id=simulation_config["template_id"],
            target_groups=simulation_config.get("target_groups", []),
            start_date=datetime.fromisoformat(simulation_config["start_date"]),
            end_date=datetime.fromisoformat(simulation_config["end_date"]),
            frequency=simulation_config.get("frequency", "once"),
            difficulty=simulation_config.get("difficulty", "medium"),
            created_by=simulation_config.get("created_by", "system"),
            status="scheduled",
            created_at=datetime.utcnow(),
        )

        db.add(simulation)
        db.commit()

        # Get target users
        target_users = get_simulation_targets(
            db,
            simulation_config.get("target_groups", []),
            simulation_config.get("target_users", []),
        )

        if not target_users:
            simulation.status = "failed"
            simulation.error_message = "No target users found"
            db.commit()
            return {
                "status": "failed",
                "simulation_id": simulation.id,
                "error": "No target users found",
            }

        # Schedule simulation emails
        schedule_result = schedule_simulation_emails.delay(
            simulation.id, [user.id for user in target_users]
        )

        simulation.status = "active"
        simulation.target_count = len(target_users)
        db.commit()

        logger.info(
            f"Simulation campaign created: {simulation.id} with {len(target_users)} targets"
        )

        return {
            "status": "created",
            "simulation_id": simulation.id,
            "target_count": len(target_users),
            "schedule_task_id": schedule_result.id,
            "created_at": datetime.utcnow().isoformat(),
        }

    except Exception as exc:
        logger.error(f"Error creating simulation campaign: {str(exc)}")

        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc, countdown=60 * (self.request.retries + 1))

        return {
            "status": "failed",
            "error": str(exc),
            "created_at": datetime.utcnow().isoformat(),
        }
    finally:
        if "db" in locals():
            db.close()


@celery_app.task(bind=True, max_retries=3)
def schedule_simulation_emails(
    self, simulation_id: int, target_user_ids: List[int]
) -> Dict[str, Any]:
    """
    Schedule phishing simulation emails to target users.

    Args:
        simulation_id: ID of the simulation campaign
        target_user_ids: List of user IDs to target

    Returns:
        Dictionary with scheduling results
    """
    try:
        logger.info(f"Scheduling simulation emails for simulation {simulation_id}")

        db = next(get_db())

        # Get simulation details
        simulation = db.query(Simulation).filter(Simulation.id == simulation_id).first()
        if not simulation:
            raise ValueError(f"Simulation {simulation_id} not found")

        # Get simulation template
        template = (
            db.query(SimulationTemplate)
            .filter(SimulationTemplate.id == simulation.template_id)
            .first()
        )
        if not template:
            raise ValueError(f"Template {simulation.template_id} not found")

        # Get target users
        target_users = db.query(User).filter(User.id.in_(target_user_ids)).all()

        # Schedule emails with random delays to avoid detection
        scheduled_tasks = []
        base_delay = 0

        for user in target_users:
            # Add random delay between 0-30 minutes
            delay = base_delay + random.randint(0, 1800)

            # Schedule individual simulation email
            task = send_simulation_email.apply_async(
                args=[simulation_id, user.id, template.id], countdown=delay
            )

            scheduled_tasks.append(
                {
                    "user_id": user.id,
                    "user_email": user.email,
                    "task_id": task.id,
                    "scheduled_for": (
                        datetime.utcnow() + timedelta(seconds=delay)
                    ).isoformat(),
                }
            )

            # Create simulation result record
            result = SimulationResult(
                simulation_id=simulation_id,
                user_id=user.id,
                email_sent=False,
                sent_at=None,
                clicked=False,
                clicked_at=None,
                reported=False,
                reported_at=None,
                status="scheduled",
                created_at=datetime.utcnow(),
            )
            db.add(result)

            base_delay += 60  # 1 minute between emails minimum

        db.commit()

        logger.info(f"Scheduled {len(scheduled_tasks)} simulation emails")

        return {
            "status": "scheduled",
            "simulation_id": simulation_id,
            "emails_scheduled": len(scheduled_tasks),
            "scheduled_tasks": scheduled_tasks,
            "scheduled_at": datetime.utcnow().isoformat(),
        }

    except Exception as exc:
        logger.error(f"Error scheduling simulation emails: {str(exc)}")

        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc, countdown=300)

        return {
            "status": "failed",
            "simulation_id": simulation_id,
            "error": str(exc),
            "scheduled_at": datetime.utcnow().isoformat(),
        }
    finally:
        if "db" in locals():
            db.close()


@celery_app.task(bind=True, max_retries=3)
def send_simulation_email(
    self, simulation_id: int, user_id: int, template_id: int
) -> Dict[str, Any]:
    """
    Send a single phishing simulation email to a user.

    Args:
        simulation_id: ID of the simulation campaign
        user_id: ID of target user
        template_id: ID of email template

    Returns:
        Dictionary with send results
    """
    try:
        logger.info(
            f"Sending simulation email for simulation {simulation_id} to user {user_id}"
        )

        db = next(get_db())

        # Get required data
        simulation = db.query(Simulation).filter(Simulation.id == simulation_id).first()
        user = db.query(User).filter(User.id == user_id).first()
        template = (
            db.query(SimulationTemplate)
            .filter(SimulationTemplate.id == template_id)
            .first()
        )

        if not all([simulation, user, template]):
            raise ValueError("Required simulation, user, or template not found")

        # Get simulation result record
        result = (
            db.query(SimulationResult)
            .filter(
                SimulationResult.simulation_id == simulation_id,
                SimulationResult.user_id == user_id,
            )
            .first()
        )

        if not result:
            raise ValueError(
                f"Simulation result record not found for simulation {simulation_id}, user {user_id}"
            )

        # Generate unique tracking ID
        tracking_id = str(uuid.uuid4())

        # Personalize email content
        personalized_content = personalize_simulation_email(
            template.content, user, tracking_id, simulation_id
        )

        # Generate tracking URLs
        click_url = generate_tracking_url("click", tracking_id)
        report_url = generate_tracking_url("report", tracking_id)

        # Replace placeholders in email content
        email_body = personalized_content.replace("{CLICK_URL}", click_url)
        email_body = email_body.replace("{REPORT_URL}", report_url)

        # Send email
        send_result = mail_client.send_email(
            to_email=user.email,
            subject=template.subject,
            body=email_body,
            is_html=True,
            from_name=template.sender_name or "Security Team",
            from_email=template.sender_email or settings.SIMULATION_FROM_EMAIL,
        )

        if send_result["success"]:
            # Update simulation result
            result.email_sent = True
            result.sent_at = datetime.utcnow()
            result.status = "sent"
            result.tracking_id = tracking_id
            result.message_id = send_result.get("message_id")

            db.commit()

            logger.info(f"Simulation email sent successfully to {user.email}")

            return {
                "status": "sent",
                "simulation_id": simulation_id,
                "user_id": user_id,
                "user_email": user.email,
                "tracking_id": tracking_id,
                "message_id": send_result.get("message_id"),
                "sent_at": datetime.utcnow().isoformat(),
            }
        else:
            # Update failure status
            result.status = "failed"
            result.error_message = send_result.get("error", "Unknown error")
            db.commit()

            logger.error(
                f"Failed to send simulation email to {user.email}: {send_result.get('error')}"
            )

            return {
                "status": "failed",
                "simulation_id": simulation_id,
                "user_id": user_id,
                "user_email": user.email,
                "error": send_result.get("error"),
                "sent_at": datetime.utcnow().isoformat(),
            }

    except Exception as exc:
        logger.error(f"Error sending simulation email: {str(exc)}")

        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc, countdown=60 * (self.request.retries + 1))

        return {
            "status": "failed",
            "simulation_id": simulation_id,
            "user_id": user_id,
            "error": str(exc),
            "sent_at": datetime.utcnow().isoformat(),
        }
    finally:
        if "db" in locals():
            db.close()


@celery_app.task
def process_simulation_interaction(
    tracking_id: str, interaction_type: str, metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Process user interaction with simulation email (click, report, etc.).

    Args:
        tracking_id: Unique tracking identifier
        interaction_type: Type of interaction (click, report, etc.)
        metadata: Additional interaction metadata

    Returns:
        Dictionary with processing results
    """
    try:
        logger.info(
            f"Processing simulation interaction: {interaction_type} for {tracking_id}"
        )

        db = next(get_db())

        # Find simulation result by tracking ID
        result = (
            db.query(SimulationResult)
            .filter(SimulationResult.tracking_id == tracking_id)
            .first()
        )

        if not result:
            logger.warning(
                f"Simulation result not found for tracking ID: {tracking_id}"
            )
            return {
                "status": "not_found",
                "tracking_id": tracking_id,
                "interaction_type": interaction_type,
            }

        interaction_time = datetime.utcnow()

        # Process different interaction types
        if interaction_type == "click":
            if not result.clicked:
                result.clicked = True
                result.clicked_at = interaction_time
                result.click_metadata = metadata or {}

                # Send immediate feedback email
                send_simulation_feedback.delay(
                    result.user_id, "clicked", result.simulation_id
                )

        elif interaction_type == "report":
            if not result.reported:
                result.reported = True
                result.reported_at = interaction_time
                result.report_metadata = metadata or {}

                # Send positive feedback email
                send_simulation_feedback.delay(
                    result.user_id, "reported", result.simulation_id
                )

        elif interaction_type == "credentials":
            result.credentials_entered = True
            result.credentials_at = interaction_time
            result.credentials_metadata = metadata or {}

            # Send urgent feedback email
            send_simulation_feedback.delay(
                result.user_id, "credentials", result.simulation_id
            )

        # Update overall status
        if result.reported:
            result.status = "reported"
        elif result.credentials_entered:
            result.status = "credentials_entered"
        elif result.clicked:
            result.status = "clicked"

        db.commit()

        logger.info(
            f"Simulation interaction processed: {interaction_type} for user {result.user_id}"
        )

        return {
            "status": "processed",
            "tracking_id": tracking_id,
            "interaction_type": interaction_type,
            "user_id": result.user_id,
            "simulation_id": result.simulation_id,
            "processed_at": interaction_time.isoformat(),
        }

    except Exception as exc:
        logger.error(f"Error processing simulation interaction: {str(exc)}")
        return {
            "status": "failed",
            "tracking_id": tracking_id,
            "interaction_type": interaction_type,
            "error": str(exc),
            "processed_at": datetime.utcnow().isoformat(),
        }
    finally:
        if "db" in locals():
            db.close()


@celery_app.task(bind=True, max_retries=3)
def send_simulation_feedback(
    self, user_id: int, feedback_type: str, simulation_id: int
) -> Dict[str, Any]:
    """
    Send educational feedback to user after simulation interaction.

    Args:
        user_id: ID of user to send feedback to
        feedback_type: Type of feedback (clicked, reported, credentials)
        simulation_id: ID of simulation campaign

    Returns:
        Dictionary with feedback results
    """
    try:
        logger.info(f"Sending simulation feedback to user {user_id}: {feedback_type}")

        db = next(get_db())

        # Get user and simulation data
        user = db.query(User).filter(User.id == user_id).first()
        simulation = db.query(Simulation).filter(Simulation.id == simulation_id).first()

        if not user or not simulation:
            raise ValueError("User or simulation not found")

        # Generate feedback content based on interaction type
        if feedback_type == "clicked":
            subject = "🎣 You clicked a simulated phishing email"
            content = generate_click_feedback_content(user, simulation)
        elif feedback_type == "reported":
            subject = "✅ Great job! You correctly reported a phishing simulation"
            content = generate_report_feedback_content(user, simulation)
        elif feedback_type == "credentials":
            subject = "⚠️ Security Alert: Credentials entered in phishing simulation"
            content = generate_credentials_feedback_content(user, simulation)
        else:
            raise ValueError(f"Unknown feedback type: {feedback_type}")

        # Send feedback email
        send_result = mail_client.send_email(
            to_email=user.email,
            subject=subject,
            body=content,
            is_html=True,
            from_name="PhishGuard Security Training",
            from_email=settings.TRAINING_FROM_EMAIL,
        )

        if send_result["success"]:
            logger.info(f"Simulation feedback sent to {user.email}")
            return {
                "status": "sent",
                "user_id": user_id,
                "user_email": user.email,
                "feedback_type": feedback_type,
                "sent_at": datetime.utcnow().isoformat(),
            }
        else:
            logger.error(
                f"Failed to send feedback to {user.email}: {send_result.get('error')}"
            )
            return {
                "status": "failed",
                "user_id": user_id,
                "user_email": user.email,
                "feedback_type": feedback_type,
                "error": send_result.get("error"),
                "sent_at": datetime.utcnow().isoformat(),
            }

    except Exception as exc:
        logger.error(f"Error sending simulation feedback: {str(exc)}")

        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc, countdown=60)

        return {
            "status": "failed",
            "user_id": user_id,
            "feedback_type": feedback_type,
            "error": str(exc),
            "sent_at": datetime.utcnow().isoformat(),
        }
    finally:
        if "db" in locals():
            db.close()


@celery_app.task
def generate_simulation_report(simulation_id: int) -> Dict[str, Any]:
    """
    Generate comprehensive report for completed simulation.

    Args:
        simulation_id: ID of simulation to generate report for

    Returns:
        Dictionary with report data
    """
    try:
        logger.info(f"Generating simulation report for {simulation_id}")

        db = next(get_db())

        # Get simulation data
        simulation = db.query(Simulation).filter(Simulation.id == simulation_id).first()
        if not simulation:
            raise ValueError(f"Simulation {simulation_id} not found")

        # Get all simulation results
        results = (
            db.query(SimulationResult)
            .filter(SimulationResult.simulation_id == simulation_id)
            .all()
        )

        if not results:
            return {
                "status": "no_data",
                "simulation_id": simulation_id,
                "message": "No simulation results found",
            }

        # Calculate statistics
        total_sent = len([r for r in results if r.email_sent])
        total_clicked = len([r for r in results if r.clicked])
        total_reported = len([r for r in results if r.reported])
        total_credentials = len(
            [r for r in results if getattr(r, "credentials_entered", False)]
        )

        click_rate = (total_clicked / total_sent * 100) if total_sent > 0 else 0
        report_rate = (total_reported / total_sent * 100) if total_sent > 0 else 0
        credentials_rate = (
            (total_credentials / total_sent * 100) if total_sent > 0 else 0
        )

        # Calculate response times
        click_times = [
            (r.clicked_at - r.sent_at).total_seconds() / 60
            for r in results
            if r.clicked and r.sent_at and r.clicked_at
        ]
        avg_click_time = sum(click_times) / len(click_times) if click_times else 0

        report_times = [
            (r.reported_at - r.sent_at).total_seconds() / 60
            for r in results
            if r.reported and r.sent_at and r.reported_at
        ]
        avg_report_time = sum(report_times) / len(report_times) if report_times else 0

        # Generate department breakdown
        department_stats = {}
        for result in results:
            if result.user and result.user.department:
                dept = result.user.department
                if dept not in department_stats:
                    department_stats[dept] = {
                        "total": 0,
                        "clicked": 0,
                        "reported": 0,
                        "credentials": 0,
                    }

                department_stats[dept]["total"] += 1
                if result.clicked:
                    department_stats[dept]["clicked"] += 1
                if result.reported:
                    department_stats[dept]["reported"] += 1
                if getattr(result, "credentials_entered", False):
                    department_stats[dept]["credentials"] += 1

        # Create comprehensive report
        report_data = {
            "simulation_id": simulation_id,
            "simulation_name": simulation.name,
            "simulation_type": (
                simulation.template.type if simulation.template else "unknown"
            ),
            "start_date": simulation.start_date.isoformat(),
            "end_date": simulation.end_date.isoformat(),
            "generated_at": datetime.utcnow().isoformat(),
            "overview": {
                "total_targets": len(results),
                "emails_sent": total_sent,
                "emails_clicked": total_clicked,
                "emails_reported": total_reported,
                "credentials_entered": total_credentials,
            },
            "rates": {
                "click_rate": round(click_rate, 2),
                "report_rate": round(report_rate, 2),
                "credentials_rate": round(credentials_rate, 2),
                "security_awareness": round(100 - click_rate, 2),
            },
            "timing": {
                "avg_click_time_minutes": round(avg_click_time, 2),
                "avg_report_time_minutes": round(avg_report_time, 2),
            },
            "department_breakdown": department_stats,
            "recommendations": generate_simulation_recommendations(
                click_rate, report_rate, credentials_rate
            ),
        }

        # Update simulation status
        simulation.status = "completed"
        simulation.report_data = report_data
        simulation.completed_at = datetime.utcnow()
        db.commit()

        logger.info(f"Simulation report generated for {simulation_id}")

        return {
            "status": "completed",
            "simulation_id": simulation_id,
            "report_data": report_data,
            "generated_at": datetime.utcnow().isoformat(),
        }

    except Exception as exc:
        logger.error(f"Error generating simulation report: {str(exc)}")
        return {
            "status": "failed",
            "simulation_id": simulation_id,
            "error": str(exc),
            "generated_at": datetime.utcnow().isoformat(),
        }
    finally:
        if "db" in locals():
            db.close()


# Helper functions


def get_simulation_targets(
    db: Session, target_groups: List[str], target_users: List[int]
) -> List[User]:
    """Get list of target users for simulation."""
    users = []

    # Get users by groups/departments
    if target_groups:
        group_users = (
            db.query(User)
            .filter(User.department.in_(target_groups), User.active == True)
            .all()
        )
        users.extend(group_users)

    # Get specific users
    if target_users:
        specific_users = (
            db.query(User).filter(User.id.in_(target_users), User.active == True).all()
        )
        users.extend(specific_users)

    # Remove duplicates
    unique_users = list({user.id: user for user in users}.values())

    return unique_users


def personalize_simulation_email(
    template_content: str, user: User, tracking_id: str, simulation_id: int
) -> str:
    """Personalize simulation email content for specific user."""
    content = template_content

    # Replace user-specific placeholders
    content = content.replace(
        "{USER_NAME}", user.first_name or user.email.split("@")[0]
    )
    content = content.replace("{USER_EMAIL}", user.email)
    content = content.replace("{USER_DEPARTMENT}", user.department or "Unknown")
    content = content.replace("{COMPANY_NAME}", settings.ORGANIZATION_NAME)

    # Add tracking parameters
    content = content.replace("{TRACKING_ID}", tracking_id)
    content = content.replace("{SIMULATION_ID}", str(simulation_id))

    return content


def generate_tracking_url(action: str, tracking_id: str) -> str:
    """Generate tracking URL for simulation interactions."""
    base_url = settings.FRONTEND_URL
    return f"{base_url}/simulation/track/{action}/{tracking_id}"


def generate_click_feedback_content(user: User, simulation: Simulation) -> str:
    """Generate feedback content for users who clicked simulation email."""
    return f"""
    <html>
    <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 8px; padding: 20px; margin-bottom: 20px;">
            <h2 style="color: #856404; margin-top: 0;">🎣 This was a simulated phishing email</h2>
            <p>Hi {user.first_name or 'there'},</p>
            <p>You just clicked on a link in a simulated phishing email as part of our security awareness training program.</p>
        </div>
        
        <h3>What happened?</h3>
        <p>The email you received was not a real threat, but a training simulation designed to help you recognize phishing attempts.</p>
        
        <h3>Red flags you might have missed:</h3>
        <ul>
            <li>Urgent or threatening language</li>
            <li>Requests for personal information</li>
            <li>Suspicious sender address</li>
            <li>Generic greetings</li>
            <li>Unexpected attachments or links</li>
        </ul>
        
        <h3>What should you do next time?</h3>
        <ol>
            <li><strong>Don't click suspicious links</strong> - Hover over links to see where they lead</li>
            <li><strong>Verify the sender</strong> - Contact them through a different channel</li>
            <li><strong>Report suspicious emails</strong> - Use the report button in your email client</li>
            <li><strong>When in doubt, ask</strong> - Contact IT security team</li>
        </ol>
        
        <div style="background-color: #d4edda; border: 1px solid #c3e6cb; border-radius: 8px; padding: 15px; margin: 20px 0;">
            <p style="margin: 0;"><strong>Remember:</strong> It's better to be cautious and report a suspicious email than to fall victim to a real attack.</p>
        </div>
        
        <p>For more security training resources, visit our <a href="{settings.FRONTEND_URL}/training">Security Training Portal</a>.</p>
        
        <p>Best regards,<br>The Security Team</p>
    </body>
    </html>
    """


def generate_report_feedback_content(user: User, simulation: Simulation) -> str:
    """Generate feedback content for users who reported simulation email."""
    return f"""
    <html>
    <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background-color: #d4edda; border: 1px solid #c3e6cb; border-radius: 8px; padding: 20px; margin-bottom: 20px;">
            <h2 style="color: #155724; margin-top: 0;">✅ Excellent work!</h2>
            <p>Hi {user.first_name or 'there'},</p>
            <p>You correctly identified and reported a simulated phishing email. Well done!</p>
        </div>
        
        <h3>Why this was the right action:</h3>
        <ul>
            <li>You recognized suspicious elements in the email</li>
            <li>You didn't click on potentially dangerous links</li>
            <li>You reported it to help protect others</li>
            <li>You followed security best practices</li>
        </ul>
        
        <h3>Keep up the good work by:</h3>
        <ol>
            <li><strong>Staying vigilant</strong> - Continue to scrutinize unexpected emails</li>
            <li><strong>Sharing knowledge</strong> - Help colleagues recognize threats</li>
            <li><strong>Staying updated</strong> - Keep learning about new attack methods</li>
            <li><strong>Reporting threats</strong> - Always report suspicious emails</li>
        </ol>
        
        <div style="background-color: #cce5ff; border: 1px solid #99d6ff; border-radius: 8px; padding: 15px; margin: 20px 0;">
            <p style="margin: 0;"><strong>Your security awareness helps protect our entire organization!</strong></p>
        </div>
        
        <p>Continue your security training at our <a href="{settings.FRONTEND_URL}/training">Security Training Portal</a>.</p>
        
        <p>Thank you for being security-conscious!<br>The Security Team</p>
    </body>
    </html>
    """


def generate_credentials_feedback_content(user: User, simulation: Simulation) -> str:
    """Generate feedback content for users who entered credentials in simulation."""
    return f"""
    <html>
    <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background-color: #f8d7da; border: 1px solid #f5c6cb; border-radius: 8px; padding: 20px; margin-bottom: 20px;">
            <h2 style="color: #721c24; margin-top: 0;">⚠️ Security Alert: Credentials Entered</h2>
            <p>Hi {user.first_name or 'there'},</p>
            <p>You entered your credentials on a simulated phishing website. This was part of our security training, but in a real attack, your account could have been compromised.</p>
        </div>
        
        <h3>What this means:</h3>
        <ul>
            <li>Your actual credentials were not stolen (this was a simulation)</li>
            <li>In a real attack, criminals would now have your username and password</li>
            <li>Your accounts could be accessed and misused</li>
            <li>Sensitive company data could be at risk</li>
        </ul>
        
        <h3>Important security measures:</h3>
        <ol>
            <li><strong>Never enter credentials from email links</strong> - Always type URLs directly</li>
            <li><strong>Check website URLs carefully</strong> - Look for misspellings or unusual domains</li>
            <li><strong>Use multi-factor authentication</strong> - It provides an extra layer of security</li>
            <li><strong>Use a password manager</strong> - It can detect fake websites</li>
        </ol>
        
        <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 8px; padding: 15px; margin: 20px 0;">
            <p style="margin: 0;"><strong>Immediate action required:</strong> Please complete additional security training and consider changing your passwords as a precaution.</p>
        </div>
        
        <p>Schedule mandatory security training: <a href="{settings.FRONTEND_URL}/training/mandatory">Security Training</a></p>
        
        <p>If you have any questions or concerns, please contact the IT Security team immediately.</p>
        
        <p>Stay safe,<br>The Security Team</p>
    </body>
    </html>
    """


def generate_simulation_recommendations(
    click_rate: float, report_rate: float, credentials_rate: float
) -> List[str]:
    """Generate recommendations based on simulation results."""
    recommendations = []

    if click_rate > 30:
        recommendations.append(
            "High click rate indicates need for additional phishing awareness training"
        )

    if report_rate < 10:
        recommendations.append(
            "Low report rate suggests users need training on reporting procedures"
        )

    if credentials_rate > 5:
        recommendations.append(
            "Credentials entered rate is concerning - implement mandatory security training"
        )

    if click_rate > 20 and report_rate < 15:
        recommendations.append(
            "Consider implementing more frequent simulations and training sessions"
        )

    if credentials_rate > 0:
        recommendations.append(
            "Review and strengthen password policies and multi-factor authentication"
        )

    if not recommendations:
        recommendations.append(
            "Good security awareness levels - maintain regular training and simulations"
        )

    return recommendations


# Configure periodic tasks for simulations
celery_app.conf.beat_schedule.update(
    {
        "generate-simulation-reports": {
            "task": "tasks.simulation_tasks.check_completed_simulations",
            "schedule": 3600.0,  # Every hour
        },
    }
)


@celery_app.task
def check_completed_simulations() -> Dict[str, Any]:
    """Check for completed simulations and generate reports."""
    try:
        db = next(get_db())

        # Find simulations that should be completed
        completed_simulations = (
            db.query(Simulation)
            .filter(
                Simulation.status == "active", Simulation.end_date <= datetime.utcnow()
            )
            .all()
        )

        reports_generated = 0
        for simulation in completed_simulations:
            try:
                generate_simulation_report.delay(simulation.id)
                reports_generated += 1
            except Exception as exc:
                logger.error(
                    f"Failed to generate report for simulation {simulation.id}: {str(exc)}"
                )

        return {
            "status": "completed",
            "simulations_checked": len(completed_simulations),
            "reports_generated": reports_generated,
            "checked_at": datetime.utcnow().isoformat(),
        }

    except Exception as exc:
        logger.error(f"Error checking completed simulations: {str(exc)}")
        return {
            "status": "failed",
            "error": str(exc),
            "checked_at": datetime.utcnow().isoformat(),
        }
    finally:
        if "db" in locals():
            db.close()


if __name__ == "__main__":
    # For testing individual tasks
    pass

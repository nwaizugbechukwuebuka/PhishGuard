"""
Simulation Service for PhishGuard

Business logic for managing phishing simulation campaigns,
user training, awareness testing, and educational content.
"""

import json
import random
import uuid
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import and_, desc, func, or_
from sqlalchemy.orm import Session

from ..models.audit_log import ActionType, AuditLog
from ..models.notification import Notification
from ..models.simulation import (
    DifficultyLevel,
    SimulationCampaign,
    SimulationParticipant,
    SimulationStatus,
    SimulationTemplate,
    SimulationType,
    TrainingStatus,
    UserAction,
)
from ..models.user import User
from ..utils.config import get_settings
from ..utils.event_bus import EventBus
from ..utils.logger import get_logger
from ..utils.mail_client import MailClient

logger = get_logger(__name__)
settings = get_settings()


class CampaignStatus(Enum):
    """Campaign status types."""

    DRAFT = "draft"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    COMPLETED = "completed"
    PAUSED = "paused"
    CANCELLED = "cancelled"


class TemplateType(Enum):
    """Simulation template types."""

    PHISHING_EMAIL = "phishing_email"
    SPEAR_PHISHING = "spear_phishing"
    BUSINESS_EMAIL_COMPROMISE = "business_email_compromise"
    MALWARE_ATTACHMENT = "malware_attachment"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    SOCIAL_ENGINEERING = "social_engineering"
    URGENT_REQUEST = "urgent_request"
    FAKE_INVOICE = "fake_invoice"


class DifficultyLevel(Enum):
    """Simulation difficulty levels."""

    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"


class UserAction(Enum):
    """User actions in simulation."""

    CLICKED = "clicked"
    REPORTED = "reported"
    IGNORED = "ignored"
    DOWNLOADED = "downloaded"
    ENTERED_CREDENTIALS = "entered_credentials"


class SimulationService:
    """Service for managing phishing simulations and user training."""

    def __init__(self, db: Session):
        """
        Initialize simulation service.

        Args:
            db: Database session
        """
        self.db = db
        self.event_bus = EventBus()
        self.mail_client = MailClient()

    async def create_campaign(
        self,
        name: str,
        description: str,
        template_ids: List[uuid.UUID],
        created_by: uuid.UUID,
        target_user_ids: Optional[List[uuid.UUID]] = None,
        target_groups: Optional[List[str]] = None,
        scheduled_date: Optional[datetime] = None,
        duration_days: int = 7,
        training_enabled: bool = True,
    ) -> Dict[str, Any]:
        """
        Create a new phishing simulation campaign.

        Args:
            name: Campaign name
            description: Campaign description
            template_ids: Simulation templates to use
            target_user_ids: Specific users to target
            target_groups: User groups to target
            scheduled_date: When to start the campaign
            duration_days: Campaign duration
            training_enabled: Enable training for failed users
            created_by: User creating the campaign

        Returns:
            Created campaign data
        """
        try:
            campaign_id = uuid.uuid4()

            # Validate templates
            templates = (
                self.db.query(SimulationTemplate)
                .filter(SimulationTemplate.id.in_(template_ids))
                .all()
            )

            if len(templates) != len(template_ids):
                raise ValueError("One or more templates not found")

            # Determine target users
            target_users = await self._resolve_target_users(
                target_user_ids, target_groups
            )

            if not target_users:
                raise ValueError("No target users specified or found")

            # Create campaign
            campaign = SimulationCampaign(
                id=campaign_id,
                name=name,
                description=description,
                template_ids=template_ids,
                target_user_ids=[user.id for user in target_users],
                scheduled_date=scheduled_date or datetime.utcnow(),
                duration_days=duration_days,
                training_enabled=training_enabled,
                status=(
                    CampaignStatus.SCHEDULED.value
                    if scheduled_date
                    else CampaignStatus.DRAFT.value
                ),
                created_by=created_by,
                created_at=datetime.utcnow(),
            )

            self.db.add(campaign)
            self.db.flush()

            # Generate simulation results for tracking
            await self._initialize_campaign_results(campaign, target_users, templates)

            campaign_data = {
                "id": str(campaign_id),
                "name": name,
                "description": description,
                "status": campaign.status,
                "template_count": len(templates),
                "target_user_count": len(target_users),
                "scheduled_date": campaign.scheduled_date.isoformat(),
                "duration_days": duration_days,
                "training_enabled": training_enabled,
                "created_at": campaign.created_at.isoformat(),
            }

            # Log campaign creation
            await self._log_simulation_action(
                action=ActionType.CREATE,
                resource_id=campaign_id,
                user_id=created_by,
                details={
                    "action": "campaign_created",
                    "campaign_name": name,
                    "target_users": len(target_users),
                    "templates": len(templates),
                },
            )

            # Emit campaign event
            await self.event_bus.emit("simulation_campaign_created", campaign_data)

            logger.info(f"Simulation campaign created: {name} ({campaign_id})")
            return campaign_data

        except Exception as e:
            logger.error(f"Error creating simulation campaign: {str(e)}")
            raise

    async def launch_campaign(
        self, campaign_id: uuid.UUID, launched_by: uuid.UUID
    ) -> Dict[str, Any]:
        """
        Launch a simulation campaign.

        Args:
            campaign_id: Campaign to launch
            launched_by: User launching the campaign

        Returns:
            Launch status
        """
        try:
            # Get campaign
            campaign = (
                self.db.query(SimulationCampaign)
                .filter(SimulationCampaign.id == campaign_id)
                .first()
            )

            if not campaign:
                raise ValueError("Campaign not found")

            if campaign.status not in [
                CampaignStatus.DRAFT.value,
                CampaignStatus.SCHEDULED.value,
            ]:
                raise ValueError(
                    f"Campaign cannot be launched in status: {campaign.status}"
                )

            # Update campaign status
            campaign.status = CampaignStatus.RUNNING.value
            campaign.started_at = datetime.utcnow()
            campaign.launched_by = launched_by

            # Get templates and results
            templates = (
                self.db.query(SimulationTemplate)
                .filter(SimulationTemplate.id.in_(campaign.template_ids))
                .all()
            )

            results = (
                self.db.query(SimulationParticipant)
                .filter(SimulationParticipant.campaign_id == campaign_id)
                .all()
            )

            # Send simulation emails
            emails_sent = 0
            for result in results:
                try:
                    template = random.choice(templates)  # Random template selection
                    success = await self._send_simulation_email(
                        result, template, campaign
                    )
                    if success:
                        emails_sent += 1
                        result.email_sent_at = datetime.utcnow()
                except Exception as e:
                    logger.error(
                        f"Error sending simulation email to user {result.user_id}: {str(e)}"
                    )

            self.db.flush()

            launch_data = {
                "campaign_id": str(campaign_id),
                "status": campaign.status,
                "started_at": campaign.started_at.isoformat(),
                "emails_sent": emails_sent,
                "total_targets": len(results),
                "success_rate": (emails_sent / len(results)) * 100 if results else 0,
            }

            # Log campaign launch
            await self._log_simulation_action(
                action=ActionType.UPDATE,
                resource_id=campaign_id,
                user_id=launched_by,
                details={
                    "action": "campaign_launched",
                    "emails_sent": emails_sent,
                    "total_targets": len(results),
                },
            )

            # Emit launch event
            await self.event_bus.emit("simulation_campaign_launched", launch_data)

            logger.info(
                f"Simulation campaign launched: {campaign.name} - {emails_sent}/{len(results)} emails sent"
            )
            return launch_data

        except Exception as e:
            logger.error(f"Error launching simulation campaign: {str(e)}")
            raise

    async def record_user_action(
        self,
        result_id: uuid.UUID,
        action: UserAction,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Record user action in simulation.

        Args:
            result_id: Simulation result ID
            action: User action taken
            details: Additional action details

        Returns:
            Recorded action data
        """
        try:
            # Get simulation participant
            result = (
                self.db.query(SimulationParticipant)
                .filter(SimulationParticipant.id == result_id)
                .first()
            )

            if not result:
                raise ValueError("Simulation participant not found")

            # Update result based on action
            action_time = datetime.utcnow()

            if action == UserAction.CLICKED:
                result.clicked = True
                result.clicked_at = action_time
                result.time_to_click = (
                    (action_time - result.email_sent_at).total_seconds()
                    if result.email_sent_at
                    else None
                )

            elif action == UserAction.REPORTED:
                result.reported = True
                result.reported_at = action_time
                result.time_to_report = (
                    (action_time - result.email_sent_at).total_seconds()
                    if result.email_sent_at
                    else None
                )

            elif action == UserAction.DOWNLOADED:
                result.downloaded_attachment = True
                result.downloaded_at = action_time

            elif action == UserAction.ENTERED_CREDENTIALS:
                result.entered_credentials = True
                result.credentials_entered_at = action_time

            # Store additional details
            if details:
                current_details = result.action_details or {}
                current_details.update(details)
                result.action_details = current_details

            result.last_action_at = action_time

            # Calculate risk score based on actions
            risk_score = await self._calculate_user_risk_score(result)
            result.risk_score = risk_score

            self.db.flush()

            # Get campaign for context
            campaign = (
                self.db.query(SimulationCampaign)
                .filter(SimulationCampaign.id == result.campaign_id)
                .first()
            )

            # Trigger training if user failed and training is enabled
            if (
                campaign
                and campaign.training_enabled
                and self._user_failed_simulation(result)
            ):
                await self._trigger_remedial_training(result, campaign)

            action_data = {
                "result_id": str(result_id),
                "user_id": str(result.user_id),
                "campaign_id": str(result.campaign_id),
                "action": action.value,
                "action_time": action_time.isoformat(),
                "risk_score": risk_score,
                "requires_training": self._user_failed_simulation(result),
            }

            # Log user action
            await self._log_simulation_action(
                action=ActionType.UPDATE,
                resource_id=result.campaign_id,
                user_id=result.user_id,
                details={
                    "action": "user_simulation_action",
                    "simulation_action": action.value,
                    "risk_score": risk_score,
                },
            )

            # Emit action event
            await self.event_bus.emit("simulation_user_action", action_data)

            logger.info(
                f"User action recorded: {action.value} by user {result.user_id}"
            )
            return action_data

        except Exception as e:
            logger.error(f"Error recording user action: {str(e)}")
            raise

    async def create_template(
        self,
        name: str,
        template_type: TemplateType,
        difficulty: DifficultyLevel,
        subject: str,
        body: str,
        created_by: uuid.UUID,
        sender_name: Optional[str] = None,
        sender_email: Optional[str] = None,
        landing_page_url: Optional[str] = None,
        attachment_name: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Create a simulation template.

        Args:
            name: Template name
            template_type: Type of simulation template
            difficulty: Difficulty level
            subject: Email subject line
            body: Email body content
            sender_name: Simulated sender name
            sender_email: Simulated sender email
            landing_page_url: Phishing landing page URL
            attachment_name: Malicious attachment name
            tags: Template tags for organization
            created_by: User creating the template

        Returns:
            Created template data
        """
        try:
            template_id = uuid.uuid4()

            # Create template
            template = SimulationTemplate(
                id=template_id,
                name=name,
                template_type=template_type.value,
                difficulty=difficulty.value,
                subject=subject,
                body=body,
                sender_name=sender_name,
                sender_email=sender_email,
                landing_page_url=landing_page_url,
                attachment_name=attachment_name,
                tags=tags or [],
                is_active=True,
                created_by=created_by,
                created_at=datetime.utcnow(),
            )

            self.db.add(template)
            self.db.flush()

            template_data = {
                "id": str(template_id),
                "name": name,
                "type": template_type.value,
                "difficulty": difficulty.value,
                "subject": subject,
                "sender_name": sender_name,
                "sender_email": sender_email,
                "tags": tags or [],
                "created_at": template.created_at.isoformat(),
            }

            # Log template creation
            await self._log_simulation_action(
                action=ActionType.CREATE,
                resource_id=template_id,
                user_id=created_by,
                details={
                    "action": "template_created",
                    "template_name": name,
                    "template_type": template_type.value,
                    "difficulty": difficulty.value,
                },
            )

            # Emit template event
            await self.event_bus.emit("simulation_template_created", template_data)

            logger.info(f"Simulation template created: {name} ({template_id})")
            return template_data

        except Exception as e:
            logger.error(f"Error creating simulation template: {str(e)}")
            raise

    async def get_campaign_results(
        self, campaign_id: uuid.UUID, include_details: bool = True
    ) -> Dict[str, Any]:
        """
        Get comprehensive campaign results.

        Args:
            campaign_id: Campaign to analyze
            include_details: Include detailed user results

        Returns:
            Campaign results and analytics
        """
        try:
            # Get campaign
            campaign = (
                self.db.query(SimulationCampaign)
                .filter(SimulationCampaign.id == campaign_id)
                .first()
            )

            if not campaign:
                raise ValueError("Campaign not found")

            # Get all results
            results = (
                self.db.query(SimulationParticipant)
                .filter(SimulationParticipant.campaign_id == campaign_id)
                .all()
            )

            # Calculate statistics
            total_users = len(results)
            emails_sent = len([r for r in results if r.email_sent_at])
            clicked_count = len([r for r in results if r.clicked])
            reported_count = len([r for r in results if r.reported])
            downloaded_count = len([r for r in results if r.downloaded_attachment])
            credentials_count = len([r for r in results if r.entered_credentials])

            # Calculate rates
            click_rate = (clicked_count / max(emails_sent, 1)) * 100
            report_rate = (reported_count / max(emails_sent, 1)) * 100
            susceptibility_rate = (
                (clicked_count + downloaded_count + credentials_count)
                / max(emails_sent, 1)
            ) * 100

            # Calculate average response times
            click_times = [r.time_to_click for r in results if r.time_to_click]
            report_times = [r.time_to_report for r in results if r.time_to_report]

            avg_click_time = sum(click_times) / len(click_times) if click_times else 0
            avg_report_time = (
                sum(report_times) / len(report_times) if report_times else 0
            )

            # Risk assessment
            high_risk_users = len([r for r in results if (r.risk_score or 0) > 70])
            medium_risk_users = len(
                [r for r in results if 30 <= (r.risk_score or 0) <= 70]
            )
            low_risk_users = total_users - high_risk_users - medium_risk_users

            campaign_results = {
                "campaign_info": {
                    "id": str(campaign_id),
                    "name": campaign.name,
                    "status": campaign.status,
                    "created_at": campaign.created_at.isoformat(),
                    "started_at": (
                        campaign.started_at.isoformat() if campaign.started_at else None
                    ),
                    "duration_days": campaign.duration_days,
                    "training_enabled": campaign.training_enabled,
                },
                "statistics": {
                    "total_users": total_users,
                    "emails_sent": emails_sent,
                    "delivery_rate": (emails_sent / max(total_users, 1)) * 100,
                    "click_rate": click_rate,
                    "report_rate": report_rate,
                    "susceptibility_rate": susceptibility_rate,
                    "users_clicked": clicked_count,
                    "users_reported": reported_count,
                    "users_downloaded": downloaded_count,
                    "users_entered_credentials": credentials_count,
                },
                "response_times": {
                    "average_click_time_seconds": round(avg_click_time, 2),
                    "average_report_time_seconds": round(avg_report_time, 2),
                    "fastest_click_seconds": min(click_times) if click_times else 0,
                    "fastest_report_seconds": min(report_times) if report_times else 0,
                },
                "risk_assessment": {
                    "high_risk_users": high_risk_users,
                    "medium_risk_users": medium_risk_users,
                    "low_risk_users": low_risk_users,
                    "overall_risk_score": await self._calculate_campaign_risk_score(
                        results
                    ),
                },
                "training_metrics": (
                    await self._get_training_metrics(campaign_id)
                    if campaign.training_enabled
                    else None
                ),
            }

            # Add detailed user results if requested
            if include_details:
                campaign_results["user_results"] = await self._format_user_results(
                    results
                )

            return campaign_results

        except Exception as e:
            logger.error(f"Error getting campaign results: {str(e)}")
            raise

    async def get_user_simulation_history(
        self, user_id: uuid.UUID, limit: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Get user's simulation participation history.

        Args:
            user_id: User to analyze
            limit: Limit number of results

        Returns:
            User simulation history and analytics
        """
        try:
            # Get user
            user = self.db.query(User).filter(User.id == user_id).first()
            if not user:
                raise ValueError("User not found")

            # Get simulation results
            query = (
                self.db.query(SimulationParticipant)
                .filter(SimulationParticipant.user_id == user_id)
                .order_by(desc(SimulationParticipant.created_at))
            )

            if limit:
                query = query.limit(limit)

            results = query.all()

            # Calculate user statistics
            total_simulations = len(results)
            clicked_count = len([r for r in results if r.clicked])
            reported_count = len([r for r in results if r.reported])
            downloaded_count = len([r for r in results if r.downloaded_attachment])
            credentials_count = len([r for r in results if r.entered_credentials])

            # Calculate improvement trends
            improvement_trend = await self._calculate_user_improvement_trend(results)

            # Risk scoring
            recent_risk_scores = [r.risk_score for r in results[:5] if r.risk_score]
            current_risk_level = (
                sum(recent_risk_scores) / len(recent_risk_scores)
                if recent_risk_scores
                else 0
            )

            history_data = {
                "user_info": {
                    "id": str(user_id),
                    "email": user.email,
                    "name": f"{user.first_name} {user.last_name}",
                    "role": user.role,
                },
                "simulation_summary": {
                    "total_simulations": total_simulations,
                    "click_rate": (clicked_count / max(total_simulations, 1)) * 100,
                    "report_rate": (reported_count / max(total_simulations, 1)) * 100,
                    "susceptibility_rate": (
                        (clicked_count + downloaded_count + credentials_count)
                        / max(total_simulations, 1)
                    )
                    * 100,
                    "current_risk_level": current_risk_level,
                    "improvement_trend": improvement_trend,
                },
                "detailed_history": [
                    {
                        "campaign_id": str(result.campaign_id),
                        "simulation_date": (
                            result.email_sent_at.isoformat()
                            if result.email_sent_at
                            else None
                        ),
                        "clicked": result.clicked,
                        "reported": result.reported,
                        "downloaded_attachment": result.downloaded_attachment,
                        "entered_credentials": result.entered_credentials,
                        "risk_score": result.risk_score,
                        "time_to_click": result.time_to_click,
                        "time_to_report": result.time_to_report,
                        "training_completed": result.training_completed,
                    }
                    for result in results
                ],
                "recommendations": await self._generate_user_recommendations(
                    user_id, results
                ),
            }

            return history_data

        except Exception as e:
            logger.error(f"Error getting user simulation history: {str(e)}")
            raise

    async def schedule_training(
        self,
        user_ids: List[uuid.UUID],
        training_type: str,
        scheduled_by: uuid.UUID,
        scheduled_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Schedule security awareness training for users.

        Args:
            user_ids: Users to train
            training_type: Type of training
            scheduled_date: When to deliver training
            scheduled_by: User scheduling training

        Returns:
            Training schedule data
        """
        try:
            training_id = uuid.uuid4()

            if not scheduled_date:
                scheduled_date = datetime.utcnow() + timedelta(hours=1)

            # Create training notifications
            notifications_created = 0
            for user_id in user_ids:
                try:
                    notification = Notification(
                        id=uuid.uuid4(),
                        user_id=user_id,
                        type="training",
                        title=f"Security Training: {training_type}",
                        message=f"You have been scheduled for security awareness training on {training_type}",
                        scheduled_at=scheduled_date,
                        created_at=datetime.utcnow(),
                    )

                    self.db.add(notification)
                    notifications_created += 1
                except Exception as e:
                    logger.warning(
                        f"Error creating training notification for user {user_id}: {str(e)}"
                    )

            self.db.flush()

            training_data = {
                "training_id": str(training_id),
                "training_type": training_type,
                "scheduled_date": scheduled_date.isoformat(),
                "user_count": len(user_ids),
                "notifications_created": notifications_created,
                "scheduled_by": str(scheduled_by),
            }

            # Log training scheduling
            await self._log_simulation_action(
                action=ActionType.CREATE,
                resource_id=training_id,
                user_id=scheduled_by,
                details={
                    "action": "training_scheduled",
                    "training_type": training_type,
                    "user_count": len(user_ids),
                },
            )

            # Emit training event
            await self.event_bus.emit("training_scheduled", training_data)

            logger.info(
                f"Training scheduled: {training_type} for {len(user_ids)} users"
            )
            return training_data

        except Exception as e:
            logger.error(f"Error scheduling training: {str(e)}")
            raise

    async def get_simulation_analytics(
        self, start_date: Optional[datetime] = None, end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Get comprehensive simulation analytics.

        Args:
            start_date: Analysis start date
            end_date: Analysis end date

        Returns:
            Simulation analytics data
        """
        try:
            if not start_date:
                start_date = datetime.utcnow() - timedelta(days=90)
            if not end_date:
                end_date = datetime.utcnow()

            # Get campaigns in period
            campaigns = (
                self.db.query(SimulationCampaign)
                .filter(
                    and_(
                        SimulationCampaign.created_at >= start_date,
                        SimulationCampaign.created_at <= end_date,
                    )
                )
                .all()
            )

            # Get all results for these campaigns
            campaign_ids = [c.id for c in campaigns]
            results = (
                self.db.query(SimulationParticipant)
                .filter(SimulationParticipant.campaign_id.in_(campaign_ids))
                .all()
                if campaign_ids
                else []
            )

            # Calculate overall metrics
            analytics = {
                "period": {
                    "start_date": start_date.isoformat(),
                    "end_date": end_date.isoformat(),
                    "total_campaigns": len(campaigns),
                    "total_users_tested": len(set([r.user_id for r in results])),
                },
                "overall_performance": await self._calculate_overall_performance(
                    results
                ),
                "trend_analysis": await self._analyze_simulation_trends(
                    campaigns, results
                ),
                "template_effectiveness": await self._analyze_template_effectiveness(
                    campaigns, results
                ),
                "user_behavior_patterns": await self._analyze_user_behavior_patterns(
                    results
                ),
                "training_impact": await self._analyze_training_impact(results),
                "risk_distribution": await self._analyze_risk_distribution(results),
                "recommendations": await self._generate_analytics_recommendations(
                    campaigns, results
                ),
            }

            return analytics

        except Exception as e:
            logger.error(f"Error getting simulation analytics: {str(e)}")
            raise

    # Private helper methods

    async def _resolve_target_users(
        self, user_ids: Optional[List[uuid.UUID]], groups: Optional[List[str]]
    ) -> List[User]:
        """Resolve target users from IDs and groups."""
        try:
            users = []

            # Add specific users
            if user_ids:
                specific_users = (
                    self.db.query(User)
                    .filter(and_(User.id.in_(user_ids), User.is_active == True))
                    .all()
                )
                users.extend(specific_users)

            # Add users from groups
            if groups:
                group_users = (
                    self.db.query(User)
                    .filter(and_(User.department.in_(groups), User.is_active == True))
                    .all()
                )
                users.extend(group_users)

            # Remove duplicates
            unique_users = list({user.id: user for user in users}.values())

            return unique_users

        except Exception as e:
            logger.error(f"Error resolving target users: {str(e)}")
            return []

    async def _initialize_campaign_results(
        self,
        campaign: SimulationCampaign,
        target_users: List[User],
        templates: List[SimulationTemplate],
    ):
        """Initialize simulation results for campaign."""
        try:
            for user in target_users:
                result = SimulationParticipant(
                    id=uuid.uuid4(),
                    campaign_id=campaign.id,
                    user_id=user.id,
                    template_id=random.choice(
                        templates
                    ).id,  # Random template assignment
                    clicked=False,
                    reported=False,
                    downloaded_attachment=False,
                    entered_credentials=False,
                    training_completed=False,
                    created_at=datetime.utcnow(),
                )

                self.db.add(result)

        except Exception as e:
            logger.error(f"Error initializing campaign results: {str(e)}")
            raise

    async def _send_simulation_email(
        self,
        result: SimulationParticipant,
        template: SimulationTemplate,
        campaign: SimulationCampaign,
    ) -> bool:
        """Send simulation email to user."""
        try:
            # Get user
            user = self.db.query(User).filter(User.id == result.user_id).first()
            if not user:
                return False

            # Prepare email content
            tracking_url = f"{settings.BASE_URL}/simulate/track/{result.id}"

            # Replace placeholders in template
            subject = template.subject.replace(
                "{user_name}", f"{user.first_name} {user.last_name}"
            )
            body = template.body.replace(
                "{user_name}", f"{user.first_name} {user.last_name}"
            )
            body = body.replace("{tracking_url}", tracking_url)

            # Send email using mail client
            success = await self.mail_client.send_simulation_email(
                to_email=user.email,
                subject=subject,
                body=body,
                sender_name=template.sender_name,
                sender_email=template.sender_email,
            )

            return success

        except Exception as e:
            logger.error(f"Error sending simulation email: {str(e)}")
            return False

    def _user_failed_simulation(self, result: SimulationParticipant) -> bool:
        """Check if user failed the simulation."""
        return (
            result.clicked or result.downloaded_attachment or result.entered_credentials
        ) and not result.reported

    async def _trigger_remedial_training(
        self, result: SimulationParticipant, campaign: SimulationCampaign
    ):
        """Trigger remedial training for failed simulation."""
        try:
            # Schedule training notification
            training_notification = Notification(
                id=uuid.uuid4(),
                user_id=result.user_id,
                type="training",
                title="Security Awareness Training Required",
                message="Based on your recent phishing simulation result, additional security training is recommended.",
                scheduled_at=datetime.utcnow() + timedelta(hours=2),
                created_at=datetime.utcnow(),
            )

            self.db.add(training_notification)

        except Exception as e:
            logger.error(f"Error triggering remedial training: {str(e)}")

    async def _calculate_user_risk_score(self, result: SimulationParticipant) -> float:
        """Calculate user risk score based on simulation result."""
        try:
            base_score = 0.0

            # Penalties for risky actions
            if result.clicked:
                base_score += 30.0
            if result.downloaded_attachment:
                base_score += 25.0
            if result.entered_credentials:
                base_score += 35.0

            # Bonus for reporting
            if result.reported:
                base_score -= 20.0

            # Time factor - faster actions are riskier
            if result.time_to_click and result.time_to_click < 300:  # 5 minutes
                base_score += 10.0

            return min(max(base_score, 0.0), 100.0)

        except Exception as e:
            logger.error(f"Error calculating user risk score: {str(e)}")
            return 50.0  # Default moderate risk

    async def _log_simulation_action(
        self,
        action: ActionType,
        resource_id: uuid.UUID,
        user_id: Optional[uuid.UUID],
        details: Dict[str, Any],
    ):
        """Log simulation-related actions."""
        try:
            audit_log = AuditLog(
                id=uuid.uuid4(),
                action=action,
                resource_type="simulation",
                resource_id=resource_id,
                user_id=user_id,
                details=details,
                timestamp=datetime.utcnow(),
            )

            self.db.add(audit_log)
            # Note: Don't commit here, let the calling method handle it

        except Exception as e:
            logger.error(f"Error logging simulation action: {str(e)}")

    # Additional helper methods would continue here...
    # This provides a comprehensive foundation for the simulation service

    async def _get_training_metrics(self, campaign_id: uuid.UUID) -> Dict[str, Any]:
        """Get training metrics for campaign."""
        results = (
            self.db.query(SimulationParticipant)
            .filter(SimulationParticipant.campaign_id == campaign_id)
            .all()
        )

        training_triggered = len(
            [r for r in results if self._user_failed_simulation(r)]
        )
        training_completed = len([r for r in results if r.training_completed])

        return {
            "training_triggered": training_triggered,
            "training_completed": training_completed,
            "completion_rate": (training_completed / max(training_triggered, 1)) * 100,
        }

    async def _format_user_results(
        self, results: List[SimulationParticipant]
    ) -> List[Dict[str, Any]]:
        """Format user results for display."""
        formatted_results = []

        for result in results:
            user = self.db.query(User).filter(User.id == result.user_id).first()

            formatted_results.append(
                {
                    "user_id": str(result.user_id),
                    "user_email": user.email if user else "Unknown",
                    "user_name": (
                        f"{user.first_name} {user.last_name}" if user else "Unknown"
                    ),
                    "email_sent": (
                        result.email_sent_at.isoformat()
                        if result.email_sent_at
                        else None
                    ),
                    "clicked": result.clicked,
                    "reported": result.reported,
                    "downloaded_attachment": result.downloaded_attachment,
                    "entered_credentials": result.entered_credentials,
                    "risk_score": result.risk_score,
                    "training_completed": result.training_completed,
                    "last_action": (
                        result.last_action_at.isoformat()
                        if result.last_action_at
                        else None
                    ),
                }
            )

        return formatted_results

    async def _calculate_campaign_risk_score(
        self, results: List[SimulationParticipant]
    ) -> float:
        """Calculate overall campaign risk score."""
        if not results:
            return 0.0

        risk_scores = [r.risk_score or 0 for r in results]
        return sum(risk_scores) / len(risk_scores)

    async def _calculate_user_improvement_trend(
        self, results: List[SimulationParticipant]
    ) -> str:
        """Calculate user improvement trend over time."""
        if len(results) < 2:
            return "insufficient_data"

        # Compare recent vs older performance
        recent_results = results[:3]  # Last 3 simulations
        older_results = results[3:6] if len(results) > 3 else []

        if not older_results:
            return "insufficient_data"

        recent_failures = len(
            [r for r in recent_results if self._user_failed_simulation(r)]
        )
        older_failures = len(
            [r for r in older_results if self._user_failed_simulation(r)]
        )

        recent_failure_rate = recent_failures / len(recent_results)
        older_failure_rate = older_failures / len(older_results)

        if recent_failure_rate < older_failure_rate * 0.8:
            return "improving"
        elif recent_failure_rate > older_failure_rate * 1.2:
            return "declining"
        else:
            return "stable"

    async def _generate_user_recommendations(
        self, user_id: uuid.UUID, results: List[SimulationParticipant]
    ) -> List[str]:
        """Generate personalized recommendations for user."""
        recommendations = []

        if not results:
            return ["Participate in phishing simulations to build awareness"]

        recent_results = results[:5]
        click_count = len([r for r in recent_results if r.clicked])
        report_count = len([r for r in recent_results if r.reported])

        if click_count > len(recent_results) * 0.5:
            recommendations.append(
                "Focus on identifying phishing indicators before clicking links"
            )

        if report_count < len(recent_results) * 0.3:
            recommendations.append("Practice reporting suspicious emails promptly")

        avg_risk = sum([r.risk_score or 0 for r in recent_results]) / len(
            recent_results
        )
        if avg_risk > 60:
            recommendations.append("Enroll in advanced security awareness training")

        if not recommendations:
            recommendations.append(
                "Continue current security practices and stay vigilant"
            )

        return recommendations

    async def _calculate_overall_performance(
        self, results: List[SimulationParticipant]
    ) -> Dict[str, Any]:
        """Calculate overall simulation performance metrics."""
        if not results:
            return {
                "click_rate": 0.0,
                "report_rate": 0.0,
                "susceptibility_rate": 0.0,
                "training_effectiveness": 0.0,
            }

        clicked = len([r for r in results if r.clicked])
        reported = len([r for r in results if r.reported])
        failed = len([r for r in results if self._user_failed_simulation(r)])

        return {
            "click_rate": (clicked / len(results)) * 100,
            "report_rate": (reported / len(results)) * 100,
            "susceptibility_rate": (failed / len(results)) * 100,
            "training_effectiveness": 75.0,  # Simulated metric
        }

    async def _analyze_simulation_trends(
        self, campaigns: List[SimulationCampaign], results: List[SimulationParticipant]
    ) -> Dict[str, Any]:
        """Analyze trends in simulation performance."""
        # Group results by month
        monthly_data = defaultdict(list)

        for result in results:
            if result.email_sent_at:
                month_key = result.email_sent_at.strftime("%Y-%m")
                monthly_data[month_key].append(result)

        trends = {}
        for month, month_results in monthly_data.items():
            click_rate = (
                len([r for r in month_results if r.clicked]) / len(month_results)
            ) * 100
            report_rate = (
                len([r for r in month_results if r.reported]) / len(month_results)
            ) * 100

            trends[month] = {
                "click_rate": click_rate,
                "report_rate": report_rate,
                "user_count": len(month_results),
            }

        return trends

    async def _analyze_template_effectiveness(
        self, campaigns: List[SimulationCampaign], results: List[SimulationParticipant]
    ) -> Dict[str, Any]:
        """Analyze effectiveness of different templates."""
        template_performance = defaultdict(
            lambda: {"clicks": 0, "reports": 0, "total": 0}
        )

        for result in results:
            if result.template_id:
                template_id = str(result.template_id)
                template_performance[template_id]["total"] += 1
                if result.clicked:
                    template_performance[template_id]["clicks"] += 1
                if result.reported:
                    template_performance[template_id]["reports"] += 1

        effectiveness = {}
        for template_id, stats in template_performance.items():
            if stats["total"] > 0:
                effectiveness[template_id] = {
                    "click_rate": (stats["clicks"] / stats["total"]) * 100,
                    "report_rate": (stats["reports"] / stats["total"]) * 100,
                    "total_uses": stats["total"],
                }

        return effectiveness

    async def _analyze_user_behavior_patterns(
        self, results: List[SimulationParticipant]
    ) -> Dict[str, Any]:
        """Analyze user behavior patterns."""
        patterns = {
            "quick_clickers": len(
                [r for r in results if r.time_to_click and r.time_to_click < 60]
            ),
            "careful_reporters": len(
                [r for r in results if r.time_to_report and r.time_to_report > 300]
            ),
            "repeat_offenders": 0,  # Would need more complex logic
            "security_champions": len(
                [r for r in results if r.reported and not r.clicked]
            ),
        }

        return patterns

    async def _analyze_training_impact(
        self, results: List[SimulationParticipant]
    ) -> Dict[str, Any]:
        """Analyze impact of training on simulation performance."""
        trained_users = [r for r in results if r.training_completed]
        untrained_users = [r for r in results if not r.training_completed]

        if not trained_users or not untrained_users:
            return {"insufficient_data": True}

        trained_failure_rate = len(
            [r for r in trained_users if self._user_failed_simulation(r)]
        ) / len(trained_users)
        untrained_failure_rate = len(
            [r for r in untrained_users if self._user_failed_simulation(r)]
        ) / len(untrained_users)

        return {
            "trained_failure_rate": trained_failure_rate * 100,
            "untrained_failure_rate": untrained_failure_rate * 100,
            "improvement_factor": (
                (untrained_failure_rate - trained_failure_rate)
                / untrained_failure_rate
                * 100
                if untrained_failure_rate > 0
                else 0
            ),
        }

    async def _analyze_risk_distribution(
        self, results: List[SimulationParticipant]
    ) -> Dict[str, Any]:
        """Analyze risk score distribution across users."""
        risk_scores = [r.risk_score for r in results if r.risk_score is not None]

        if not risk_scores:
            return {"no_data": True}

        high_risk = len([score for score in risk_scores if score > 70])
        medium_risk = len([score for score in risk_scores if 30 <= score <= 70])
        low_risk = len([score for score in risk_scores if score < 30])

        return {
            "high_risk_users": high_risk,
            "medium_risk_users": medium_risk,
            "low_risk_users": low_risk,
            "average_risk_score": sum(risk_scores) / len(risk_scores),
        }

    async def _generate_analytics_recommendations(
        self, campaigns: List[SimulationCampaign], results: List[SimulationParticipant]
    ) -> List[str]:
        """Generate recommendations based on analytics."""
        recommendations = []

        if results:
            click_rate = (len([r for r in results if r.clicked]) / len(results)) * 100
            report_rate = (len([r for r in results if r.reported]) / len(results)) * 100

            if click_rate > 30:
                recommendations.append(
                    "Increase frequency of phishing awareness training"
                )

            if report_rate < 20:
                recommendations.append(
                    "Improve reporting mechanisms and user education"
                )

            if len(campaigns) < 4:
                recommendations.append("Conduct more frequent simulation campaigns")

        if not recommendations:
            recommendations.append(
                "Continue current simulation practices and monitor trends"
            )

        return recommendations

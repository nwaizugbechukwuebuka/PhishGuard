"""
Simulation Routes for PhishGuard API

Comprehensive phishing simulation management endpoints including
campaign creation, participant management, analytics, and results.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request, Query, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import desc, and_, or_, func
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, validator, EmailStr
import uuid
import json
from enum import Enum

from ..database import get_db
from ..models.simulation import (
    SimulationCampaign, SimulationParticipant, SimulationTemplate,
    SimulationType, ParticipantStatus, CampaignStatus, DifficultyLevel
)
from ..models.user import User
from ..models.audit_log import AuditLog, ActionType
from ..middleware.auth_middleware import get_current_user, get_current_admin_user
from ..services.simulation_service import SimulationService
from ..utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/simulations", tags=["simulations"])

# Pydantic models for request/response
class SimulationTemplateRequest(BaseModel):
    name: str
    description: str
    simulation_type: SimulationType
    difficulty_level: DifficultyLevel
    email_subject: str
    email_content: str
    sender_name: str
    sender_email: EmailStr
    landing_page_url: Optional[str] = None
    attachment_url: Optional[str] = None
    phishing_indicators: List[str] = []
    learning_objectives: List[str] = []

class SimulationCampaignRequest(BaseModel):
    name: str
    description: str
    template_id: uuid.UUID
    target_groups: List[str] = []  # departments, roles, or specific user groups
    participant_emails: List[EmailStr] = []  # specific email addresses
    start_date: datetime
    end_date: datetime
    send_reminders: bool = True
    reminder_schedule: List[int] = [24, 72]  # hours before deadline
    track_clicks: bool = True
    track_data_entry: bool = True
    auto_remediation: bool = True
    custom_settings: Optional[Dict[str, Any]] = None

class BulkParticipantRequest(BaseModel):
    campaign_id: uuid.UUID
    participants: List[Dict[str, Any]]  # user_id, email, department, etc.
    send_immediately: bool = False
    custom_timing: Optional[Dict[str, datetime]] = None

class SimulationResultsRequest(BaseModel):
    campaign_id: uuid.UUID
    include_details: bool = True
    include_analytics: bool = True
    export_format: str = "json"  # json, csv, pdf

class SimulationTemplateResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    simulation_type: SimulationType
    difficulty_level: DifficultyLevel
    email_subject: str
    sender_name: str
    sender_email: str
    phishing_indicators: List[str]
    learning_objectives: List[str]
    usage_count: int
    success_rate: Optional[float]
    created_at: datetime
    updated_at: datetime

class SimulationCampaignResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    template: SimulationTemplateResponse
    status: CampaignStatus
    start_date: datetime
    end_date: datetime
    total_participants: int
    emails_sent: int
    emails_opened: int
    links_clicked: int
    data_entered: int
    reported_phishing: int
    completion_rate: float
    click_rate: float
    report_rate: float
    created_by: str
    created_at: datetime
    updated_at: datetime

class SimulationParticipantResponse(BaseModel):
    id: uuid.UUID
    user_email: str
    user_name: str
    department: str
    status: ParticipantStatus
    email_sent_at: Optional[datetime]
    email_opened_at: Optional[datetime]
    link_clicked_at: Optional[datetime]
    data_entered_at: Optional[datetime]
    reported_at: Optional[datetime]
    completed_training: bool
    risk_score: float
    response_time: Optional[int]  # seconds
    ip_address: Optional[str]
    user_agent: Optional[str]

class SimulationAnalyticsResponse(BaseModel):
    campaign_summary: Dict[str, Any]
    participant_statistics: Dict[str, Any]
    department_breakdown: List[Dict[str, Any]]
    time_series_data: List[Dict[str, Any]]
    risk_assessment: Dict[str, Any]
    improvement_recommendations: List[str]


@router.post("/templates", response_model=SimulationTemplateResponse)
async def create_simulation_template(
    template_request: SimulationTemplateRequest,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Create a new simulation template.
    
    Args:
        template_request: Template creation data
        current_user: Current authenticated admin user
        db: Database session
        
    Returns:
        Created simulation template
    """
    try:
        simulation_service = SimulationService(db)
        
        # Create simulation template
        template = await simulation_service.create_template(
            name=template_request.name,
            description=template_request.description,
            simulation_type=template_request.simulation_type,
            difficulty_level=template_request.difficulty_level,
            email_subject=template_request.email_subject,
            email_content=template_request.email_content,
            sender_name=template_request.sender_name,
            sender_email=template_request.sender_email,
            landing_page_url=template_request.landing_page_url,
            attachment_url=template_request.attachment_url,
            phishing_indicators=template_request.phishing_indicators,
            learning_objectives=template_request.learning_objectives,
            created_by=current_user.id
        )
        
        # Log template creation
        await simulation_service.log_action(
            action=ActionType.CREATE,
            resource_type="simulation_template",
            resource_id=template.id,
            user_id=current_user.id,
            details={"template_name": template.name}
        )
        
        return SimulationTemplateResponse(
            id=template.id,
            name=template.name,
            description=template.description,
            simulation_type=template.simulation_type,
            difficulty_level=template.difficulty_level,
            email_subject=template.email_subject,
            sender_name=template.sender_name,
            sender_email=template.sender_email,
            phishing_indicators=template.phishing_indicators,
            learning_objectives=template.learning_objectives,
            usage_count=0,
            success_rate=None,
            created_at=template.created_at,
            updated_at=template.updated_at
        )
        
    except Exception as e:
        logger.error(f"Error creating simulation template: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create simulation template"
        )


@router.get("/templates", response_model=List[SimulationTemplateResponse])
async def get_simulation_templates(
    simulation_type: Optional[SimulationType] = Query(None, description="Filter by simulation type"),
    difficulty_level: Optional[DifficultyLevel] = Query(None, description="Filter by difficulty level"),
    skip: int = Query(0, ge=0, description="Number of templates to skip"),
    limit: int = Query(100, ge=1, le=100, description="Number of templates to return"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get simulation templates with optional filtering.
    
    Args:
        simulation_type: Optional simulation type filter
        difficulty_level: Optional difficulty level filter
        skip: Number of templates to skip
        limit: Number of templates to return
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        List of simulation templates
    """
    try:
        simulation_service = SimulationService(db)
        
        # Get templates
        templates = await simulation_service.get_templates(
            simulation_type=simulation_type,
            difficulty_level=difficulty_level,
            skip=skip,
            limit=limit
        )
        
        return [
            SimulationTemplateResponse(
                id=template.id,
                name=template.name,
                description=template.description,
                simulation_type=template.simulation_type,
                difficulty_level=template.difficulty_level,
                email_subject=template.email_subject,
                sender_name=template.sender_name,
                sender_email=template.sender_email,
                phishing_indicators=template.phishing_indicators,
                learning_objectives=template.learning_objectives,
                usage_count=template.usage_count,
                success_rate=template.success_rate,
                created_at=template.created_at,
                updated_at=template.updated_at
            )
            for template in templates
        ]
        
    except Exception as e:
        logger.error(f"Error getting simulation templates: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get simulation templates"
        )


@router.post("/campaigns", response_model=SimulationCampaignResponse)
async def create_simulation_campaign(
    campaign_request: SimulationCampaignRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Create a new simulation campaign.
    
    Args:
        campaign_request: Campaign creation data
        background_tasks: Background task handler
        current_user: Current authenticated admin user
        db: Database session
        
    Returns:
        Created simulation campaign
    """
    try:
        simulation_service = SimulationService(db)
        
        # Validate template exists
        template = await simulation_service.get_template_by_id(campaign_request.template_id)
        if not template:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Simulation template not found"
            )
        
        # Create campaign
        campaign = await simulation_service.create_campaign(
            name=campaign_request.name,
            description=campaign_request.description,
            template_id=campaign_request.template_id,
            target_groups=campaign_request.target_groups,
            participant_emails=campaign_request.participant_emails,
            start_date=campaign_request.start_date,
            end_date=campaign_request.end_date,
            send_reminders=campaign_request.send_reminders,
            reminder_schedule=campaign_request.reminder_schedule,
            track_clicks=campaign_request.track_clicks,
            track_data_entry=campaign_request.track_data_entry,
            auto_remediation=campaign_request.auto_remediation,
            custom_settings=campaign_request.custom_settings,
            created_by=current_user.id
        )
        
        # Schedule campaign start if needed
        if campaign_request.start_date <= datetime.utcnow():
            background_tasks.add_task(
                start_simulation_campaign,
                campaign.id,
                db
            )
        else:
            background_tasks.add_task(
                schedule_simulation_campaign,
                campaign.id,
                campaign_request.start_date,
                db
            )
        
        # Log campaign creation
        await simulation_service.log_action(
            action=ActionType.CREATE,
            resource_type="simulation_campaign",
            resource_id=campaign.id,
            user_id=current_user.id,
            details={"campaign_name": campaign.name}
        )
        
        return SimulationCampaignResponse(
            id=campaign.id,
            name=campaign.name,
            description=campaign.description,
            template=SimulationTemplateResponse(
                id=template.id,
                name=template.name,
                description=template.description,
                simulation_type=template.simulation_type,
                difficulty_level=template.difficulty_level,
                email_subject=template.email_subject,
                sender_name=template.sender_name,
                sender_email=template.sender_email,
                phishing_indicators=template.phishing_indicators,
                learning_objectives=template.learning_objectives,
                usage_count=template.usage_count,
                success_rate=template.success_rate,
                created_at=template.created_at,
                updated_at=template.updated_at
            ),
            status=campaign.status,
            start_date=campaign.start_date,
            end_date=campaign.end_date,
            total_participants=0,
            emails_sent=0,
            emails_opened=0,
            links_clicked=0,
            data_entered=0,
            reported_phishing=0,
            completion_rate=0.0,
            click_rate=0.0,
            report_rate=0.0,
            created_by=current_user.email,
            created_at=campaign.created_at,
            updated_at=campaign.updated_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating simulation campaign: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create simulation campaign"
        )


@router.get("/campaigns", response_model=List[SimulationCampaignResponse])
async def get_simulation_campaigns(
    status: Optional[CampaignStatus] = Query(None, description="Filter by campaign status"),
    template_id: Optional[uuid.UUID] = Query(None, description="Filter by template ID"),
    skip: int = Query(0, ge=0, description="Number of campaigns to skip"),
    limit: int = Query(100, ge=1, le=100, description="Number of campaigns to return"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get simulation campaigns with optional filtering.
    
    Args:
        status: Optional campaign status filter
        template_id: Optional template ID filter
        skip: Number of campaigns to skip
        limit: Number of campaigns to return
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        List of simulation campaigns
    """
    try:
        simulation_service = SimulationService(db)
        
        # Get campaigns
        campaigns = await simulation_service.get_campaigns(
            status=status,
            template_id=template_id,
            skip=skip,
            limit=limit
        )
        
        result = []
        for campaign in campaigns:
            # Get campaign statistics
            stats = await simulation_service.get_campaign_statistics(campaign.id)
            
            result.append(SimulationCampaignResponse(
                id=campaign.id,
                name=campaign.name,
                description=campaign.description,
                template=SimulationTemplateResponse(
                    id=campaign.template.id,
                    name=campaign.template.name,
                    description=campaign.template.description,
                    simulation_type=campaign.template.simulation_type,
                    difficulty_level=campaign.template.difficulty_level,
                    email_subject=campaign.template.email_subject,
                    sender_name=campaign.template.sender_name,
                    sender_email=campaign.template.sender_email,
                    phishing_indicators=campaign.template.phishing_indicators,
                    learning_objectives=campaign.template.learning_objectives,
                    usage_count=campaign.template.usage_count,
                    success_rate=campaign.template.success_rate,
                    created_at=campaign.template.created_at,
                    updated_at=campaign.template.updated_at
                ),
                status=campaign.status,
                start_date=campaign.start_date,
                end_date=campaign.end_date,
                total_participants=stats.get("total_participants", 0),
                emails_sent=stats.get("emails_sent", 0),
                emails_opened=stats.get("emails_opened", 0),
                links_clicked=stats.get("links_clicked", 0),
                data_entered=stats.get("data_entered", 0),
                reported_phishing=stats.get("reported_phishing", 0),
                completion_rate=stats.get("completion_rate", 0.0),
                click_rate=stats.get("click_rate", 0.0),
                report_rate=stats.get("report_rate", 0.0),
                created_by=campaign.created_by_user.email if campaign.created_by_user else "Unknown",
                created_at=campaign.created_at,
                updated_at=campaign.updated_at
            ))
        
        return result
        
    except Exception as e:
        logger.error(f"Error getting simulation campaigns: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get simulation campaigns"
        )


@router.get("/campaigns/{campaign_id}", response_model=SimulationCampaignResponse)
async def get_simulation_campaign(
    campaign_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get a specific simulation campaign.
    
    Args:
        campaign_id: Campaign ID
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        Simulation campaign details
    """
    try:
        simulation_service = SimulationService(db)
        
        # Get campaign
        campaign = await simulation_service.get_campaign_by_id(campaign_id)
        if not campaign:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Simulation campaign not found"
            )
        
        # Get campaign statistics
        stats = await simulation_service.get_campaign_statistics(campaign_id)
        
        return SimulationCampaignResponse(
            id=campaign.id,
            name=campaign.name,
            description=campaign.description,
            template=SimulationTemplateResponse(
                id=campaign.template.id,
                name=campaign.template.name,
                description=campaign.template.description,
                simulation_type=campaign.template.simulation_type,
                difficulty_level=campaign.template.difficulty_level,
                email_subject=campaign.template.email_subject,
                sender_name=campaign.template.sender_name,
                sender_email=campaign.template.sender_email,
                phishing_indicators=campaign.template.phishing_indicators,
                learning_objectives=campaign.template.learning_objectives,
                usage_count=campaign.template.usage_count,
                success_rate=campaign.template.success_rate,
                created_at=campaign.template.created_at,
                updated_at=campaign.template.updated_at
            ),
            status=campaign.status,
            start_date=campaign.start_date,
            end_date=campaign.end_date,
            total_participants=stats.get("total_participants", 0),
            emails_sent=stats.get("emails_sent", 0),
            emails_opened=stats.get("emails_opened", 0),
            links_clicked=stats.get("links_clicked", 0),
            data_entered=stats.get("data_entered", 0),
            reported_phishing=stats.get("reported_phishing", 0),
            completion_rate=stats.get("completion_rate", 0.0),
            click_rate=stats.get("click_rate", 0.0),
            report_rate=stats.get("report_rate", 0.0),
            created_by=campaign.created_by_user.email if campaign.created_by_user else "Unknown",
            created_at=campaign.created_at,
            updated_at=campaign.updated_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting simulation campaign: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get simulation campaign"
        )


@router.post("/campaigns/{campaign_id}/participants")
async def add_campaign_participants(
    campaign_id: uuid.UUID,
    participant_request: BulkParticipantRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Add participants to a simulation campaign.
    
    Args:
        campaign_id: Campaign ID
        participant_request: Participant addition data
        background_tasks: Background task handler
        current_user: Current authenticated admin user
        db: Database session
        
    Returns:
        Participant addition status
    """
    try:
        simulation_service = SimulationService(db)
        
        # Validate campaign exists
        campaign = await simulation_service.get_campaign_by_id(campaign_id)
        if not campaign:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Simulation campaign not found"
            )
        
        # Add participants
        added_participants = await simulation_service.add_campaign_participants(
            campaign_id=campaign_id,
            participants=participant_request.participants,
            added_by=current_user.id
        )
        
        # Send emails if requested
        if participant_request.send_immediately:
            background_tasks.add_task(
                send_simulation_emails,
                campaign_id,
                [p.id for p in added_participants],
                db
            )
        elif participant_request.custom_timing:
            background_tasks.add_task(
                schedule_simulation_emails,
                campaign_id,
                participant_request.custom_timing,
                db
            )
        
        # Log participant addition
        await simulation_service.log_action(
            action=ActionType.UPDATE,
            resource_type="simulation_campaign",
            resource_id=campaign_id,
            user_id=current_user.id,
            details={
                "participants_added": len(added_participants),
                "send_immediately": participant_request.send_immediately
            }
        )
        
        return {
            "message": f"Added {len(added_participants)} participants to campaign",
            "campaign_id": campaign_id,
            "participants_added": len(added_participants),
            "emails_queued": participant_request.send_immediately
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error adding campaign participants: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to add campaign participants"
        )


@router.get("/campaigns/{campaign_id}/participants", response_model=List[SimulationParticipantResponse])
async def get_campaign_participants(
    campaign_id: uuid.UUID,
    status: Optional[ParticipantStatus] = Query(None, description="Filter by participant status"),
    department: Optional[str] = Query(None, description="Filter by department"),
    skip: int = Query(0, ge=0, description="Number of participants to skip"),
    limit: int = Query(100, ge=1, le=100, description="Number of participants to return"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get campaign participants with optional filtering.
    
    Args:
        campaign_id: Campaign ID
        status: Optional participant status filter
        department: Optional department filter
        skip: Number of participants to skip
        limit: Number of participants to return
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        List of campaign participants
    """
    try:
        simulation_service = SimulationService(db)
        
        # Validate campaign exists
        campaign = await simulation_service.get_campaign_by_id(campaign_id)
        if not campaign:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Simulation campaign not found"
            )
        
        # Get participants
        participants = await simulation_service.get_campaign_participants(
            campaign_id=campaign_id,
            status=status,
            department=department,
            skip=skip,
            limit=limit
        )
        
        return [
            SimulationParticipantResponse(
                id=participant.id,
                user_email=participant.user_email,
                user_name=participant.user_name,
                department=participant.department or "Unknown",
                status=participant.status,
                email_sent_at=participant.email_sent_at,
                email_opened_at=participant.email_opened_at,
                link_clicked_at=participant.link_clicked_at,
                data_entered_at=participant.data_entered_at,
                reported_at=participant.reported_at,
                completed_training=participant.completed_training,
                risk_score=participant.risk_score,
                response_time=participant.response_time,
                ip_address=participant.ip_address,
                user_agent=participant.user_agent
            )
            for participant in participants
        ]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting campaign participants: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get campaign participants"
        )


@router.get("/campaigns/{campaign_id}/analytics", response_model=SimulationAnalyticsResponse)
async def get_campaign_analytics(
    campaign_id: uuid.UUID,
    include_detailed: bool = Query(True, description="Include detailed analytics"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get comprehensive analytics for a simulation campaign.
    
    Args:
        campaign_id: Campaign ID
        include_detailed: Include detailed analytics
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        Campaign analytics data
    """
    try:
        simulation_service = SimulationService(db)
        
        # Validate campaign exists
        campaign = await simulation_service.get_campaign_by_id(campaign_id)
        if not campaign:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Simulation campaign not found"
            )
        
        # Generate analytics
        analytics = await simulation_service.generate_campaign_analytics(
            campaign_id=campaign_id,
            include_detailed=include_detailed
        )
        
        return SimulationAnalyticsResponse(**analytics)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting campaign analytics: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get campaign analytics"
        )


@router.post("/campaigns/{campaign_id}/start")
async def start_simulation_campaign(
    campaign_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Manually start a simulation campaign.
    
    Args:
        campaign_id: Campaign ID
        background_tasks: Background task handler
        current_user: Current authenticated admin user
        db: Database session
        
    Returns:
        Campaign start status
    """
    try:
        simulation_service = SimulationService(db)
        
        # Start campaign
        campaign = await simulation_service.start_campaign(campaign_id)
        
        # Queue email sending
        background_tasks.add_task(
            send_campaign_emails,
            campaign_id,
            db
        )
        
        # Log campaign start
        await simulation_service.log_action(
            action=ActionType.UPDATE,
            resource_type="simulation_campaign",
            resource_id=campaign_id,
            user_id=current_user.id,
            details={"action": "campaign_started"}
        )
        
        return {
            "message": "Simulation campaign started successfully",
            "campaign_id": campaign_id,
            "status": campaign.status,
            "emails_queued": True
        }
        
    except Exception as e:
        logger.error(f"Error starting simulation campaign: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start simulation campaign"
        )


@router.post("/campaigns/{campaign_id}/stop")
async def stop_simulation_campaign(
    campaign_id: uuid.UUID,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """
    Stop a running simulation campaign.
    
    Args:
        campaign_id: Campaign ID
        current_user: Current authenticated admin user
        db: Database session
        
    Returns:
        Campaign stop status
    """
    try:
        simulation_service = SimulationService(db)
        
        # Stop campaign
        campaign = await simulation_service.stop_campaign(campaign_id)
        
        # Log campaign stop
        await simulation_service.log_action(
            action=ActionType.UPDATE,
            resource_type="simulation_campaign",
            resource_id=campaign_id,
            user_id=current_user.id,
            details={"action": "campaign_stopped"}
        )
        
        return {
            "message": "Simulation campaign stopped successfully",
            "campaign_id": campaign_id,
            "status": campaign.status
        }
        
    except Exception as e:
        logger.error(f"Error stopping simulation campaign: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to stop simulation campaign"
        )


# Background task functions
async def start_simulation_campaign(campaign_id: uuid.UUID, db: Session):
    """Background task to start a simulation campaign."""
    try:
        simulation_service = SimulationService(db)
        await simulation_service.start_campaign(campaign_id)
        logger.info(f"Simulation campaign {campaign_id} started successfully")
    except Exception as e:
        logger.error(f"Error starting simulation campaign {campaign_id}: {str(e)}")


async def schedule_simulation_campaign(campaign_id: uuid.UUID, start_date: datetime, db: Session):
    """Background task to schedule a simulation campaign."""
    try:
        # In a real implementation, you would use a task scheduler like Celery
        # For now, we'll just log the scheduling
        logger.info(f"Simulation campaign {campaign_id} scheduled to start at {start_date}")
    except Exception as e:
        logger.error(f"Error scheduling simulation campaign {campaign_id}: {str(e)}")


async def send_simulation_emails(campaign_id: uuid.UUID, participant_ids: List[uuid.UUID], db: Session):
    """Background task to send simulation emails to participants."""
    try:
        simulation_service = SimulationService(db)
        await simulation_service.send_simulation_emails(campaign_id, participant_ids)
        logger.info(f"Simulation emails sent for campaign {campaign_id}")
    except Exception as e:
        logger.error(f"Error sending simulation emails for campaign {campaign_id}: {str(e)}")


async def schedule_simulation_emails(campaign_id: uuid.UUID, timing: Dict[str, datetime], db: Session):
    """Background task to schedule simulation emails."""
    try:
        # In a real implementation, you would schedule emails based on the timing dictionary
        logger.info(f"Simulation emails scheduled for campaign {campaign_id}")
    except Exception as e:
        logger.error(f"Error scheduling simulation emails for campaign {campaign_id}: {str(e)}")


async def send_campaign_emails(campaign_id: uuid.UUID, db: Session):
    """Background task to send all emails for a campaign."""
    try:
        simulation_service = SimulationService(db)
        await simulation_service.send_all_campaign_emails(campaign_id)
        logger.info(f"All campaign emails sent for campaign {campaign_id}")
    except Exception as e:
        logger.error(f"Error sending campaign emails for campaign {campaign_id}: {str(e)}")

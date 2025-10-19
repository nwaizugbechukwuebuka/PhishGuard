"""
Quarantine Routes for PhishGuard API

Comprehensive quarantine management endpoints including email storage,
threat analysis, release/delete operations, and bulk management.
"""

import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Query,
    status,
)
from pydantic import BaseModel, EmailStr
from sqlalchemy import and_, desc, func, or_
from sqlalchemy.orm import Session

from ..database import get_db
from ..middleware.auth_middleware import get_current_admin_user, get_current_user
from ..models.audit_log import ActionType, AuditLog, SeverityLevel, StatusType
from ..models.quarantine import (
    QuarantinedEmail,
    QuarantineReason,
    QuarantineStatus,
    ThreatLevel,
)
from ..models.user import User
from ..services.detection_engine import DetectionEngine
from ..services.notification_service import NotificationService
from ..services.quarantine_service import QuarantineService
from ..utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/quarantine", tags=["quarantine"])


# Pydantic models for request/response
class QuarantineEmailRequest(BaseModel):
    sender_email: EmailStr
    recipient_email: EmailStr
    subject: str
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    quarantine_reason: QuarantineReason
    threat_level: ThreatLevel = ThreatLevel.MEDIUM
    quarantine_days: int = 30
    analysis_results: Optional[Dict[str, Any]] = None
    message_id: Optional[str] = None


class QuarantineEmailResponse(BaseModel):
    id: str
    sender_email: str
    recipient_email: str
    subject: str
    quarantine_reason: str
    threat_level: str
    status: str
    quarantined_at: str
    expires_at: str
    has_attachments: bool
    attachment_count: int
    confidence_score: Optional[int]


class QuarantineListResponse(BaseModel):
    quarantined_emails: List[QuarantineEmailResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class QuarantineStatsResponse(BaseModel):
    total_quarantined: int
    active_quarantines: int
    expired_quarantines: int
    released_emails: int
    deleted_emails: int
    threat_level_breakdown: Dict[str, int]
    reason_breakdown: Dict[str, int]
    weekly_trends: List[Dict[str, Any]]


class ReleaseEmailRequest(BaseModel):
    reason: Optional[str] = None
    notify_recipient: bool = True
    add_sender_to_whitelist: bool = False


class BulkActionRequest(BaseModel):
    email_ids: List[str]
    action: str  # "release", "delete", "extend"
    reason: Optional[str] = None
    extension_days: Optional[int] = None


class EmailAnalysisResponse(BaseModel):
    threat_score: int
    threat_level: str
    detected_threats: List[str]
    urls_found: List[Dict[str, Any]]
    attachments_analysis: List[Dict[str, Any]]
    sender_reputation: Dict[str, Any]
    content_analysis: Dict[str, Any]


@router.post("/", response_model=QuarantineEmailResponse)
async def quarantine_email(
    request: QuarantineEmailRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Quarantine an email.

    Args:
        request: Quarantine request data
        background_tasks: Background task handler
        current_user: Current authenticated user
        db: Database session

    Returns:
        Quarantined email details

    Raises:
        HTTPException: If quarantine operation fails
    """
    try:
        quarantine_service = QuarantineService(db)

        # Create quarantine entry
        quarantined_email = await quarantine_service.quarantine_email(
            sender_email=request.sender_email,
            recipient_email=request.recipient_email,
            subject=request.subject,
            body_text=request.body_text,
            body_html=request.body_html,
            headers=request.headers,
            quarantine_reason=request.quarantine_reason,
            threat_level=request.threat_level,
            quarantine_days=request.quarantine_days,
            analysis_results=request.analysis_results,
            message_id=request.message_id,
            quarantined_by=current_user.id,
        )

        # Log quarantine action
        background_tasks.add_task(
            log_quarantine_action,
            db,
            ActionType.EMAIL_QUARANTINE,
            current_user.id,
            str(quarantined_email.id),
            f"Email quarantined: {request.quarantine_reason.value}",
        )

        # Send notification to recipient
        background_tasks.add_task(
            notify_quarantine_action, db, quarantined_email.id, "quarantined"
        )

        return QuarantineEmailResponse(**quarantined_email.to_dict())

    except Exception as e:
        logger.error(f"Error quarantining email: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to quarantine email",
        )


@router.get("/", response_model=QuarantineListResponse)
async def list_quarantined_emails(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    status: Optional[QuarantineStatus] = Query(None, description="Filter by status"),
    threat_level: Optional[ThreatLevel] = Query(
        None, description="Filter by threat level"
    ),
    reason: Optional[QuarantineReason] = Query(
        None, description="Filter by quarantine reason"
    ),
    sender_email: Optional[str] = Query(None, description="Filter by sender email"),
    recipient_email: Optional[str] = Query(
        None, description="Filter by recipient email"
    ),
    start_date: Optional[datetime] = Query(None, description="Filter from this date"),
    end_date: Optional[datetime] = Query(None, description="Filter until this date"),
    needs_review: bool = Query(False, description="Show only emails needing review"),
    expired: bool = Query(False, description="Show only expired quarantines"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    List quarantined emails with filtering and pagination.

    Args:
        page: Page number
        page_size: Items per page
        status: Filter by quarantine status
        threat_level: Filter by threat level
        reason: Filter by quarantine reason
        sender_email: Filter by sender email
        recipient_email: Filter by recipient email
        start_date: Filter from date
        end_date: Filter until date
        needs_review: Show only emails needing review
        expired: Show only expired quarantines
        current_user: Current authenticated user
        db: Database session

    Returns:
        Paginated list of quarantined emails
    """
    try:
        # Build query
        query = db.query(QuarantinedEmail)

        # Apply filters
        if status:
            query = query.filter(QuarantinedEmail.status == status)
        if threat_level:
            query = query.filter(QuarantinedEmail.threat_level == threat_level)
        if reason:
            query = query.filter(QuarantinedEmail.quarantine_reason == reason)
        if sender_email:
            query = query.filter(
                QuarantinedEmail.sender_email.ilike(f"%{sender_email}%")
            )
        if recipient_email:
            query = query.filter(
                QuarantinedEmail.recipient_email.ilike(f"%{recipient_email}%")
            )
        if start_date:
            query = query.filter(QuarantinedEmail.quarantined_at >= start_date)
        if end_date:
            query = query.filter(QuarantinedEmail.quarantined_at <= end_date)

        if needs_review:
            query = query.filter(
                or_(
                    QuarantinedEmail.status == QuarantineStatus.PENDING_REVIEW,
                    and_(
                        QuarantinedEmail.threat_level == ThreatLevel.CRITICAL,
                        QuarantinedEmail.reviewed_at.is_(None),
                    ),
                )
            )

        if expired:
            query = query.filter(
                and_(
                    QuarantinedEmail.expires_at <= func.now(),
                    QuarantinedEmail.status == QuarantineStatus.ACTIVE,
                )
            )

        # Non-admin users can only see quarantines for their organization
        if not current_user.is_admin:
            # You might want to add organization-based filtering here
            pass

        # Get total count
        total = query.count()

        # Apply pagination and ordering
        quarantined_emails = (
            query.order_by(desc(QuarantinedEmail.quarantined_at))
            .offset((page - 1) * page_size)
            .limit(page_size)
            .all()
        )

        # Convert to response format
        email_responses = [
            QuarantineEmailResponse(**email.to_dict()) for email in quarantined_emails
        ]

        total_pages = (total + page_size - 1) // page_size

        return QuarantineListResponse(
            quarantined_emails=email_responses,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
        )

    except Exception as e:
        logger.error(f"Error listing quarantined emails: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list quarantined emails",
        )


@router.get("/{email_id}")
async def get_quarantined_email(
    email_id: str,
    include_content: bool = Query(True, description="Include email content"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get quarantined email details by ID.

    Args:
        email_id: Quarantined email ID
        include_content: Whether to include email content
        current_user: Current authenticated user
        db: Database session

    Returns:
        Quarantined email details

    Raises:
        HTTPException: If email not found
    """
    try:
        quarantined_email = (
            db.query(QuarantinedEmail).filter(QuarantinedEmail.id == email_id).first()
        )

        if not quarantined_email:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Quarantined email not found",
            )

        # Mark as reviewed if this is the first time an admin views it
        if current_user.is_admin and not quarantined_email.reviewed_at:
            quarantined_email.reviewed_at = datetime.utcnow()
            quarantined_email.reviewed_by = current_user.id
            db.commit()

        return quarantined_email.to_dict(
            include_content=include_content, include_sensitive=current_user.is_admin
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting quarantined email {email_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get quarantined email",
        )


@router.post("/{email_id}/release")
async def release_quarantined_email(
    email_id: str,
    request: ReleaseEmailRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
):
    """
    Release an email from quarantine.

    Args:
        email_id: Quarantined email ID
        request: Release request data
        background_tasks: Background task handler
        current_user: Current authenticated admin user
        db: Database session

    Returns:
        Release confirmation

    Raises:
        HTTPException: If email not found or cannot be released
    """
    try:
        quarantined_email = (
            db.query(QuarantinedEmail).filter(QuarantinedEmail.id == email_id).first()
        )

        if not quarantined_email:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Quarantined email not found",
            )

        if not quarantined_email.can_be_released():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email cannot be released from quarantine",
            )

        quarantine_service = QuarantineService(db)

        # Release the email
        await quarantine_service.release_email(
            email_id=email_id,
            user_id=str(current_user.id),
            reason=request.reason,
            notify_recipient=request.notify_recipient,
            add_sender_to_whitelist=request.add_sender_to_whitelist,
        )

        # Log release action
        background_tasks.add_task(
            log_quarantine_action,
            db,
            ActionType.EMAIL_RELEASE,
            current_user.id,
            email_id,
            f"Email released: {request.reason or 'No reason provided'}",
        )

        # Send notification
        if request.notify_recipient:
            background_tasks.add_task(
                notify_quarantine_action, db, email_id, "released"
            )

        return {"message": "Email released from quarantine successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error releasing quarantined email {email_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to release quarantined email",
        )


@router.delete("/{email_id}")
async def delete_quarantined_email(
    email_id: str,
    background_tasks: BackgroundTasks,
    reason: Optional[str] = Query(None, description="Reason for deletion"),
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
):
    """
    Delete an email from quarantine.

    Args:
        email_id: Quarantined email ID
        reason: Reason for deletion
        background_tasks: Background task handler
        current_user: Current authenticated admin user
        db: Database session

    Returns:
        Deletion confirmation

    Raises:
        HTTPException: If email not found or cannot be deleted
    """
    try:
        quarantined_email = (
            db.query(QuarantinedEmail).filter(QuarantinedEmail.id == email_id).first()
        )

        if not quarantined_email:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Quarantined email not found",
            )

        if not quarantined_email.can_be_deleted():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email cannot be deleted from quarantine",
            )

        quarantine_service = QuarantineService(db)

        # Delete the email
        await quarantine_service.delete_email(
            email_id=email_id, user_id=str(current_user.id), reason=reason
        )

        # Log deletion action
        background_tasks.add_task(
            log_quarantine_action,
            db,
            ActionType.EMAIL_DELETE,
            current_user.id,
            email_id,
            f"Email deleted: {reason or 'No reason provided'}",
        )

        return {"message": "Email deleted from quarantine successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting quarantined email {email_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete quarantined email",
        )


@router.post("/{email_id}/extend")
async def extend_quarantine(
    email_id: str,
    background_tasks: BackgroundTasks,
    days: int = Query(..., ge=1, le=365, description="Number of days to extend"),
    reason: Optional[str] = Query(None, description="Reason for extension"),
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
):
    """
    Extend quarantine period for an email.

    Args:
        email_id: Quarantined email ID
        days: Number of days to extend
        reason: Reason for extension
        background_tasks: Background task handler
        current_user: Current authenticated admin user
        db: Database session

    Returns:
        Extension confirmation

    Raises:
        HTTPException: If email not found
    """
    try:
        quarantined_email = (
            db.query(QuarantinedEmail).filter(QuarantinedEmail.id == email_id).first()
        )

        if not quarantined_email:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Quarantined email not found",
            )

        # Extend quarantine
        quarantined_email.extend_quarantine(
            days=days, user_id=str(current_user.id), reason=reason
        )

        db.commit()

        # Log extension action
        background_tasks.add_task(
            log_quarantine_action,
            db,
            ActionType.EMAIL_QUARANTINE,
            current_user.id,
            email_id,
            f"Quarantine extended by {days} days: {reason or 'No reason provided'}",
        )

        return {
            "message": f"Quarantine extended by {days} days",
            "new_expiry": quarantined_email.expires_at.isoformat(),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error extending quarantine for email {email_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to extend quarantine",
        )


@router.post("/bulk-action")
async def bulk_quarantine_action(
    request: BulkActionRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
):
    """
    Perform bulk actions on quarantined emails.

    Args:
        request: Bulk action request
        background_tasks: Background task handler
        current_user: Current authenticated admin user
        db: Database session

    Returns:
        Bulk action results

    Raises:
        HTTPException: If bulk action fails
    """
    try:
        quarantine_service = QuarantineService(db)

        successful_actions = []
        failed_actions = []

        for email_id in request.email_ids:
            try:
                quarantined_email = (
                    db.query(QuarantinedEmail)
                    .filter(QuarantinedEmail.id == email_id)
                    .first()
                )

                if not quarantined_email:
                    failed_actions.append(
                        {"email_id": email_id, "error": "Email not found"}
                    )
                    continue

                if request.action == "release":
                    if quarantined_email.can_be_released():
                        await quarantine_service.release_email(
                            email_id=email_id,
                            user_id=str(current_user.id),
                            reason=request.reason,
                        )
                        successful_actions.append(email_id)
                    else:
                        failed_actions.append(
                            {"email_id": email_id, "error": "Cannot be released"}
                        )

                elif request.action == "delete":
                    if quarantined_email.can_be_deleted():
                        await quarantine_service.delete_email(
                            email_id=email_id,
                            user_id=str(current_user.id),
                            reason=request.reason,
                        )
                        successful_actions.append(email_id)
                    else:
                        failed_actions.append(
                            {"email_id": email_id, "error": "Cannot be deleted"}
                        )

                elif request.action == "extend":
                    if request.extension_days:
                        quarantined_email.extend_quarantine(
                            days=request.extension_days,
                            user_id=str(current_user.id),
                            reason=request.reason,
                        )
                        successful_actions.append(email_id)
                    else:
                        failed_actions.append(
                            {
                                "email_id": email_id,
                                "error": "Extension days not specified",
                            }
                        )

                else:
                    failed_actions.append(
                        {"email_id": email_id, "error": "Invalid action"}
                    )

            except Exception as e:
                failed_actions.append({"email_id": email_id, "error": str(e)})

        db.commit()

        # Log bulk action
        background_tasks.add_task(
            log_quarantine_action,
            db,
            ActionType.EMAIL_QUARANTINE,
            current_user.id,
            "bulk",
            f"Bulk {request.action} performed on {len(successful_actions)} emails",
        )

        return {
            "message": f"Bulk {request.action} completed",
            "successful_count": len(successful_actions),
            "failed_count": len(failed_actions),
            "successful_actions": successful_actions,
            "failed_actions": failed_actions,
        }

    except Exception as e:
        logger.error(f"Error performing bulk quarantine action: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to perform bulk action",
        )


@router.get("/stats/overview", response_model=QuarantineStatsResponse)
async def get_quarantine_stats(
    start_date: Optional[datetime] = Query(None, description="Stats from this date"),
    end_date: Optional[datetime] = Query(None, description="Stats until this date"),
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
):
    """
    Get quarantine statistics and analytics.

    Args:
        start_date: Stats from date
        end_date: Stats until date
        current_user: Current authenticated admin user
        db: Database session

    Returns:
        Quarantine statistics
    """
    try:
        # Build base query
        query = db.query(QuarantinedEmail)

        if start_date:
            query = query.filter(QuarantinedEmail.quarantined_at >= start_date)
        if end_date:
            query = query.filter(QuarantinedEmail.quarantined_at <= end_date)

        quarantined_emails = query.all()

        # Calculate basic statistics
        total_quarantined = len(quarantined_emails)
        active_quarantines = sum(
            1 for e in quarantined_emails if e.status == QuarantineStatus.ACTIVE
        )
        expired_quarantines = sum(1 for e in quarantined_emails if e.is_expired())
        released_emails = sum(
            1 for e in quarantined_emails if e.status == QuarantineStatus.RELEASED
        )
        deleted_emails = sum(
            1 for e in quarantined_emails if e.status == QuarantineStatus.DELETED
        )

        # Threat level breakdown
        threat_level_breakdown = {}
        for email in quarantined_emails:
            level = email.threat_level.value if email.threat_level else "unknown"
            threat_level_breakdown[level] = threat_level_breakdown.get(level, 0) + 1

        # Reason breakdown
        reason_breakdown = {}
        for email in quarantined_emails:
            reason = (
                email.quarantine_reason.value if email.quarantine_reason else "unknown"
            )
            reason_breakdown[reason] = reason_breakdown.get(reason, 0) + 1

        # Weekly trends (last 8 weeks)
        weekly_trends = []
        for i in range(8):
            week_start = datetime.utcnow() - timedelta(weeks=i + 1)
            week_end = datetime.utcnow() - timedelta(weeks=i)

            week_emails = [
                e
                for e in quarantined_emails
                if week_start <= e.quarantined_at <= week_end
            ]

            weekly_trends.append(
                {
                    "week_start": week_start.isoformat(),
                    "week_end": week_end.isoformat(),
                    "count": len(week_emails),
                    "threat_levels": {
                        level.value: sum(
                            1 for e in week_emails if e.threat_level == level
                        )
                        for level in ThreatLevel
                    },
                }
            )

        weekly_trends.reverse()  # Most recent first

        return QuarantineStatsResponse(
            total_quarantined=total_quarantined,
            active_quarantines=active_quarantines,
            expired_quarantines=expired_quarantines,
            released_emails=released_emails,
            deleted_emails=deleted_emails,
            threat_level_breakdown=threat_level_breakdown,
            reason_breakdown=reason_breakdown,
            weekly_trends=weekly_trends,
        )

    except Exception as e:
        logger.error(f"Error getting quarantine stats: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get quarantine statistics",
        )


@router.post("/{email_id}/analyze", response_model=EmailAnalysisResponse)
async def analyze_quarantined_email(
    email_id: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
):
    """
    Perform detailed analysis of a quarantined email.

    Args:
        email_id: Quarantined email ID
        background_tasks: Background task handler
        current_user: Current authenticated admin user
        db: Database session

    Returns:
        Detailed email analysis results

    Raises:
        HTTPException: If email not found or analysis fails
    """
    try:
        quarantined_email = (
            db.query(QuarantinedEmail).filter(QuarantinedEmail.id == email_id).first()
        )

        if not quarantined_email:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Quarantined email not found",
            )

        detection_engine = DetectionEngine()

        # Perform comprehensive analysis
        analysis_results = await detection_engine.analyze_email_comprehensive(
            sender_email=quarantined_email.sender_email,
            recipient_email=quarantined_email.recipient_email,
            subject=quarantined_email.subject,
            body_text=quarantined_email.body_text,
            body_html=quarantined_email.body_html,
            headers=quarantined_email.headers,
            attachments=quarantined_email.attachments,
        )

        # Update quarantined email with new analysis
        quarantined_email.analysis_results = analysis_results
        quarantined_email.confidence_score = analysis_results.get("confidence_score")

        db.commit()

        return EmailAnalysisResponse(
            threat_score=analysis_results.get("threat_score", 0),
            threat_level=analysis_results.get("threat_level", "unknown"),
            detected_threats=analysis_results.get("detected_threats", []),
            urls_found=analysis_results.get("urls_found", []),
            attachments_analysis=analysis_results.get("attachments_analysis", []),
            sender_reputation=analysis_results.get("sender_reputation", {}),
            content_analysis=analysis_results.get("content_analysis", {}),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error analyzing quarantined email {email_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to analyze quarantined email",
        )


# Helper functions
async def log_quarantine_action(
    db: Session, action: ActionType, user_id: uuid.UUID, resource_id: str, details: str
):
    """Log quarantine action to audit log."""
    try:
        audit_log = AuditLog.create_audit_entry(
            action=action,
            user_id=str(user_id),
            resource_type="quarantined_email",
            resource_id=resource_id,
            description=details,
            status=StatusType.SUCCESS,
            severity=SeverityLevel.MEDIUM,
        )

        db.add(audit_log)
        db.commit()
    except Exception as e:
        logger.error(f"Error logging quarantine action: {str(e)}")


async def notify_quarantine_action(db: Session, email_id: str, action: str):
    """Send notification about quarantine action."""
    try:
        notification_service = NotificationService(db)

        quarantined_email = (
            db.query(QuarantinedEmail).filter(QuarantinedEmail.id == email_id).first()
        )

        if quarantined_email:
            await notification_service.send_quarantine_notification(
                quarantined_email, action
            )
    except Exception as e:
        logger.error(f"Error sending quarantine notification: {str(e)}")

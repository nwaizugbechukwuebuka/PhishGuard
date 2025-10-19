"""
Quarantine Service for PhishGuard

Business logic for email quarantine management, threat analysis,
and quarantine operations including storage, retrieval, and cleanup.
"""

import hashlib
import json
import os
import shutil
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import and_, desc, func, or_
from sqlalchemy.orm import Session

from ..models.audit_log import ActionType, AuditLog
from ..models.quarantine import QuarantinedEmail, QuarantineReason, ThreatLevel
from ..models.user import User
from ..utils.config import get_settings
from ..utils.event_bus import EventBus
from ..utils.logger import get_logger

logger = get_logger(__name__)
settings = get_settings()


class QuarantineService:
    """Service for managing quarantined emails and threat analysis."""

    def __init__(self, db: Session):
        """
        Initialize quarantine service.

        Args:
            db: Database session
        """
        self.db = db
        self.event_bus = EventBus()
        self.quarantine_storage_path = Path(settings.QUARANTINE_STORAGE_PATH)
        self.quarantine_storage_path.mkdir(parents=True, exist_ok=True)

    async def quarantine_email(
        self,
        sender_email: str,
        recipient_email: str,
        subject: str,
        content: str,
        headers: Dict[str, str],
        threat_level: ThreatLevel,
        quarantine_reason: QuarantineReason,
        threat_indicators: List[str],
        confidence_score: float,
        original_message_id: Optional[str] = None,
        attachments: Optional[List[Dict[str, Any]]] = None,
        quarantined_by: Optional[uuid.UUID] = None,
    ) -> QuarantinedEmail:
        """
        Quarantine an email with threat analysis.

        Args:
            sender_email: Email sender
            recipient_email: Email recipient
            subject: Email subject
            content: Email content
            headers: Email headers
            threat_level: Assessed threat level
            quarantine_reason: Reason for quarantine
            threat_indicators: List of threat indicators
            confidence_score: AI confidence score
            original_message_id: Original email message ID
            attachments: Email attachments
            quarantined_by: User who quarantined the email

        Returns:
            Created quarantined email record
        """
        try:
            # Generate unique quarantine ID
            quarantine_id = str(uuid.uuid4())

            # Calculate content hash for deduplication
            content_hash = hashlib.sha256(
                f"{sender_email}{subject}{content}".encode("utf-8")
            ).hexdigest()

            # Check for existing quarantine with same hash
            existing = (
                self.db.query(QuarantinedEmail)
                .filter(
                    QuarantinedEmail.content_hash == content_hash,
                    QuarantinedEmail.is_released == False,
                )
                .first()
            )

            if existing:
                logger.info(f"Email already quarantined: {content_hash}")
                return existing

            # Store email content and attachments
            storage_path = await self._store_email_content(
                quarantine_id=quarantine_id,
                content=content,
                headers=headers,
                attachments=attachments or [],
            )

            # Create quarantine record
            quarantined_email = QuarantinedEmail(
                id=uuid.UUID(quarantine_id),
                sender_email=sender_email,
                recipient_email=recipient_email,
                subject=subject,
                content_preview=content[:500],  # Store preview only
                content_hash=content_hash,
                headers=headers,
                threat_level=threat_level,
                quarantine_reason=quarantine_reason,
                threat_indicators=threat_indicators,
                confidence_score=confidence_score,
                original_message_id=original_message_id,
                attachment_count=len(attachments) if attachments else 0,
                storage_path=str(storage_path),
                quarantined_by=quarantined_by,
                quarantined_at=datetime.utcnow(),
            )

            self.db.add(quarantined_email)
            self.db.commit()
            self.db.refresh(quarantined_email)

            # Log quarantine action
            await self._log_quarantine_action(
                action=ActionType.CREATE,
                quarantine_id=quarantined_email.id,
                user_id=quarantined_by,
                details={
                    "sender": sender_email,
                    "recipient": recipient_email,
                    "threat_level": threat_level.value,
                    "reason": quarantine_reason.value,
                    "confidence": confidence_score,
                },
            )

            # Emit quarantine event
            await self.event_bus.emit(
                "email_quarantined",
                {
                    "quarantine_id": str(quarantined_email.id),
                    "sender": sender_email,
                    "recipient": recipient_email,
                    "threat_level": threat_level.value,
                    "confidence_score": confidence_score,
                },
            )

            logger.info(f"Email quarantined successfully: {quarantine_id}")
            return quarantined_email

        except Exception as e:
            logger.error(f"Error quarantining email: {str(e)}")
            self.db.rollback()
            raise

    async def release_email(
        self,
        quarantine_id: uuid.UUID,
        released_by: uuid.UUID,
        release_reason: str,
        deliver_to_recipient: bool = True,
    ) -> QuarantinedEmail:
        """
        Release a quarantined email.

        Args:
            quarantine_id: Quarantined email ID
            released_by: User releasing the email
            release_reason: Reason for release
            deliver_to_recipient: Whether to deliver to original recipient

        Returns:
            Updated quarantined email record
        """
        try:
            # Get quarantined email
            quarantined_email = (
                self.db.query(QuarantinedEmail)
                .filter(QuarantinedEmail.id == quarantine_id)
                .first()
            )

            if not quarantined_email:
                raise ValueError("Quarantined email not found")

            if quarantined_email.is_released:
                raise ValueError("Email already released")

            # Update quarantine record
            quarantined_email.is_released = True
            quarantined_email.released_at = datetime.utcnow()
            quarantined_email.released_by = released_by
            quarantined_email.release_reason = release_reason

            self.db.commit()
            self.db.refresh(quarantined_email)

            # Deliver email if requested
            if deliver_to_recipient:
                await self._deliver_released_email(quarantined_email)

            # Log release action
            await self._log_quarantine_action(
                action=ActionType.UPDATE,
                quarantine_id=quarantine_id,
                user_id=released_by,
                details={
                    "action": "email_released",
                    "reason": release_reason,
                    "delivered": deliver_to_recipient,
                },
            )

            # Emit release event
            await self.event_bus.emit(
                "email_released",
                {
                    "quarantine_id": str(quarantine_id),
                    "sender": quarantined_email.sender_email,
                    "recipient": quarantined_email.recipient_email,
                    "delivered": deliver_to_recipient,
                },
            )

            logger.info(f"Email released successfully: {quarantine_id}")
            return quarantined_email

        except Exception as e:
            logger.error(f"Error releasing email: {str(e)}")
            self.db.rollback()
            raise

    async def delete_quarantined_email(
        self,
        quarantine_id: uuid.UUID,
        deleted_by: uuid.UUID,
        deletion_reason: str,
        permanent: bool = False,
    ) -> bool:
        """
        Delete a quarantined email.

        Args:
            quarantine_id: Quarantined email ID
            deleted_by: User deleting the email
            deletion_reason: Reason for deletion
            permanent: Whether to permanently delete or soft delete

        Returns:
            True if successful
        """
        try:
            # Get quarantined email
            quarantined_email = (
                self.db.query(QuarantinedEmail)
                .filter(QuarantinedEmail.id == quarantine_id)
                .first()
            )

            if not quarantined_email:
                raise ValueError("Quarantined email not found")

            if permanent:
                # Delete storage files
                await self._delete_email_storage(quarantined_email.storage_path)

                # Permanently delete from database
                self.db.delete(quarantined_email)
            else:
                # Soft delete
                quarantined_email.is_deleted = True
                quarantined_email.deleted_at = datetime.utcnow()
                quarantined_email.deleted_by = deleted_by
                quarantined_email.deletion_reason = deletion_reason

            self.db.commit()

            # Log deletion action
            await self._log_quarantine_action(
                action=ActionType.DELETE,
                quarantine_id=quarantine_id,
                user_id=deleted_by,
                details={
                    "action": "email_deleted",
                    "reason": deletion_reason,
                    "permanent": permanent,
                },
            )

            # Emit deletion event
            await self.event_bus.emit(
                "email_deleted",
                {
                    "quarantine_id": str(quarantine_id),
                    "permanent": permanent,
                    "reason": deletion_reason,
                },
            )

            logger.info(f"Email deleted successfully: {quarantine_id}")
            return True

        except Exception as e:
            logger.error(f"Error deleting quarantined email: {str(e)}")
            self.db.rollback()
            raise

    async def extend_quarantine(
        self,
        quarantine_id: uuid.UUID,
        extension_days: int,
        extended_by: uuid.UUID,
        extension_reason: str,
    ) -> QuarantinedEmail:
        """
        Extend quarantine period for an email.

        Args:
            quarantine_id: Quarantined email ID
            extension_days: Number of days to extend
            extended_by: User extending the quarantine
            extension_reason: Reason for extension

        Returns:
            Updated quarantined email record
        """
        try:
            # Get quarantined email
            quarantined_email = (
                self.db.query(QuarantinedEmail)
                .filter(QuarantinedEmail.id == quarantine_id)
                .first()
            )

            if not quarantined_email:
                raise ValueError("Quarantined email not found")

            if quarantined_email.is_released or quarantined_email.is_deleted:
                raise ValueError("Cannot extend released or deleted email")

            # Calculate new expiry date
            current_expiry = quarantined_email.expires_at or (
                quarantined_email.quarantined_at + timedelta(days=30)
            )
            new_expiry = current_expiry + timedelta(days=extension_days)

            # Update quarantine record
            quarantined_email.expires_at = new_expiry
            quarantined_email.extension_count = (
                quarantined_email.extension_count or 0
            ) + 1
            quarantined_email.last_extended_at = datetime.utcnow()
            quarantined_email.last_extended_by = extended_by

            self.db.commit()
            self.db.refresh(quarantined_email)

            # Log extension action
            await self._log_quarantine_action(
                action=ActionType.UPDATE,
                quarantine_id=quarantine_id,
                user_id=extended_by,
                details={
                    "action": "quarantine_extended",
                    "extension_days": extension_days,
                    "new_expiry": new_expiry.isoformat(),
                    "reason": extension_reason,
                },
            )

            logger.info(f"Quarantine extended successfully: {quarantine_id}")
            return quarantined_email

        except Exception as e:
            logger.error(f"Error extending quarantine: {str(e)}")
            self.db.rollback()
            raise

    async def get_quarantined_emails(
        self,
        threat_level: Optional[ThreatLevel] = None,
        quarantine_reason: Optional[QuarantineReason] = None,
        sender_email: Optional[str] = None,
        recipient_email: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        is_released: Optional[bool] = None,
        is_deleted: Optional[bool] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> Tuple[List[QuarantinedEmail], int]:
        """
        Get quarantined emails with filtering.

        Args:
            threat_level: Filter by threat level
            quarantine_reason: Filter by quarantine reason
            sender_email: Filter by sender email
            recipient_email: Filter by recipient email
            start_date: Filter by start date
            end_date: Filter by end date
            is_released: Filter by release status
            is_deleted: Filter by deletion status
            skip: Number of records to skip
            limit: Number of records to return

        Returns:
            Tuple of (quarantined emails list, total count)
        """
        try:
            query = self.db.query(QuarantinedEmail)

            # Apply filters
            if threat_level:
                query = query.filter(QuarantinedEmail.threat_level == threat_level)

            if quarantine_reason:
                query = query.filter(
                    QuarantinedEmail.quarantine_reason == quarantine_reason
                )

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

            if is_released is not None:
                query = query.filter(QuarantinedEmail.is_released == is_released)

            if is_deleted is not None:
                query = query.filter(QuarantinedEmail.is_deleted == is_deleted)

            # Get total count
            total_count = query.count()

            # Apply pagination and ordering
            quarantined_emails = (
                query.order_by(desc(QuarantinedEmail.quarantined_at))
                .offset(skip)
                .limit(limit)
                .all()
            )

            return quarantined_emails, total_count

        except Exception as e:
            logger.error(f"Error getting quarantined emails: {str(e)}")
            raise

    async def get_quarantine_statistics(
        self, start_date: Optional[datetime] = None, end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Get quarantine statistics.

        Args:
            start_date: Start date for statistics
            end_date: End date for statistics

        Returns:
            Dictionary containing statistics
        """
        try:
            query = self.db.query(QuarantinedEmail)

            if start_date:
                query = query.filter(QuarantinedEmail.quarantined_at >= start_date)

            if end_date:
                query = query.filter(QuarantinedEmail.quarantined_at <= end_date)

            # Basic counts
            total_quarantined = query.count()
            released_count = query.filter(QuarantinedEmail.is_released == True).count()
            deleted_count = query.filter(QuarantinedEmail.is_deleted == True).count()
            pending_count = query.filter(
                and_(
                    QuarantinedEmail.is_released == False,
                    QuarantinedEmail.is_deleted == False,
                )
            ).count()

            # Threat level distribution
            threat_levels = (
                self.db.query(
                    QuarantinedEmail.threat_level, func.count(QuarantinedEmail.id)
                )
                .filter(query.whereclause)
                .group_by(QuarantinedEmail.threat_level)
                .all()
            )

            threat_level_dist = {level.value: count for level, count in threat_levels}

            # Quarantine reason distribution
            quarantine_reasons = (
                self.db.query(
                    QuarantinedEmail.quarantine_reason, func.count(QuarantinedEmail.id)
                )
                .filter(query.whereclause)
                .group_by(QuarantinedEmail.quarantine_reason)
                .all()
            )

            reason_dist = {reason.value: count for reason, count in quarantine_reasons}

            # Top senders
            top_senders = (
                self.db.query(
                    QuarantinedEmail.sender_email,
                    func.count(QuarantinedEmail.id).label("count"),
                )
                .filter(query.whereclause)
                .group_by(QuarantinedEmail.sender_email)
                .order_by(desc("count"))
                .limit(10)
                .all()
            )

            # Average confidence score
            avg_confidence = (
                self.db.query(func.avg(QuarantinedEmail.confidence_score))
                .filter(query.whereclause)
                .scalar()
                or 0.0
            )

            return {
                "total_quarantined": total_quarantined,
                "released_count": released_count,
                "deleted_count": deleted_count,
                "pending_count": pending_count,
                "release_rate": (
                    (released_count / total_quarantined * 100)
                    if total_quarantined > 0
                    else 0
                ),
                "threat_level_distribution": threat_level_dist,
                "quarantine_reason_distribution": reason_dist,
                "top_threat_senders": [
                    {"sender": sender, "count": count} for sender, count in top_senders
                ],
                "average_confidence_score": round(avg_confidence, 2),
                "period": {
                    "start_date": start_date.isoformat() if start_date else None,
                    "end_date": end_date.isoformat() if end_date else None,
                },
            }

        except Exception as e:
            logger.error(f"Error getting quarantine statistics: {str(e)}")
            raise

    async def analyze_threat_trends(
        self, days: int = 30, granularity: str = "daily"
    ) -> Dict[str, Any]:
        """
        Analyze threat trends over time.

        Args:
            days: Number of days to analyze
            granularity: Analysis granularity (daily, weekly)

        Returns:
            Threat trend analysis
        """
        try:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)

            # Define date grouping based on granularity
            if granularity == "weekly":
                date_format = "%Y-%W"
                date_trunc = func.date_trunc("week", QuarantinedEmail.quarantined_at)
            else:  # daily
                date_format = "%Y-%m-%d"
                date_trunc = func.date_trunc("day", QuarantinedEmail.quarantined_at)

            # Get threat trends by date
            threat_trends = (
                self.db.query(
                    date_trunc.label("date"),
                    QuarantinedEmail.threat_level,
                    func.count(QuarantinedEmail.id).label("count"),
                )
                .filter(
                    QuarantinedEmail.quarantined_at >= start_date,
                    QuarantinedEmail.quarantined_at <= end_date,
                )
                .group_by("date", QuarantinedEmail.threat_level)
                .order_by("date")
                .all()
            )

            # Format trends data
            trends_data = {}
            for date, threat_level, count in threat_trends:
                date_str = date.strftime(date_format)
                if date_str not in trends_data:
                    trends_data[date_str] = {}
                trends_data[date_str][threat_level.value] = count

            # Get confidence score trends
            confidence_trends = (
                self.db.query(
                    date_trunc.label("date"),
                    func.avg(QuarantinedEmail.confidence_score).label("avg_confidence"),
                    func.count(QuarantinedEmail.id).label("count"),
                )
                .filter(
                    QuarantinedEmail.quarantined_at >= start_date,
                    QuarantinedEmail.quarantined_at <= end_date,
                )
                .group_by("date")
                .order_by("date")
                .all()
            )

            confidence_data = [
                {
                    "date": date.strftime(date_format),
                    "average_confidence": round(avg_confidence, 2),
                    "email_count": count,
                }
                for date, avg_confidence, count in confidence_trends
            ]

            return {
                "threat_trends": trends_data,
                "confidence_trends": confidence_data,
                "analysis_period": {
                    "start_date": start_date.isoformat(),
                    "end_date": end_date.isoformat(),
                    "granularity": granularity,
                    "days": days,
                },
            }

        except Exception as e:
            logger.error(f"Error analyzing threat trends: {str(e)}")
            raise

    async def bulk_release_emails(
        self,
        quarantine_ids: List[uuid.UUID],
        released_by: uuid.UUID,
        release_reason: str,
        deliver_to_recipients: bool = True,
    ) -> Dict[str, Any]:
        """
        Release multiple quarantined emails in bulk.

        Args:
            quarantine_ids: List of quarantine IDs
            released_by: User releasing the emails
            release_reason: Reason for release
            deliver_to_recipients: Whether to deliver to recipients

        Returns:
            Results of bulk operation
        """
        try:
            results = {
                "successful": [],
                "failed": [],
                "total_processed": len(quarantine_ids),
            }

            for quarantine_id in quarantine_ids:
                try:
                    released_email = await self.release_email(
                        quarantine_id=quarantine_id,
                        released_by=released_by,
                        release_reason=release_reason,
                        deliver_to_recipient=deliver_to_recipients,
                    )
                    results["successful"].append(
                        {
                            "quarantine_id": str(quarantine_id),
                            "sender": released_email.sender_email,
                            "recipient": released_email.recipient_email,
                        }
                    )
                except Exception as e:
                    results["failed"].append(
                        {"quarantine_id": str(quarantine_id), "error": str(e)}
                    )

            # Log bulk operation
            await self._log_quarantine_action(
                action=ActionType.UPDATE,
                quarantine_id=None,
                user_id=released_by,
                details={
                    "action": "bulk_release",
                    "total_processed": results["total_processed"],
                    "successful_count": len(results["successful"]),
                    "failed_count": len(results["failed"]),
                    "reason": release_reason,
                },
            )

            return results

        except Exception as e:
            logger.error(f"Error in bulk release operation: {str(e)}")
            raise

    async def bulk_delete_emails(
        self,
        quarantine_ids: List[uuid.UUID],
        deleted_by: uuid.UUID,
        deletion_reason: str,
        permanent: bool = False,
    ) -> Dict[str, Any]:
        """
        Delete multiple quarantined emails in bulk.

        Args:
            quarantine_ids: List of quarantine IDs
            deleted_by: User deleting the emails
            deletion_reason: Reason for deletion
            permanent: Whether to permanently delete

        Returns:
            Results of bulk operation
        """
        try:
            results = {
                "successful": [],
                "failed": [],
                "total_processed": len(quarantine_ids),
            }

            for quarantine_id in quarantine_ids:
                try:
                    await self.delete_quarantined_email(
                        quarantine_id=quarantine_id,
                        deleted_by=deleted_by,
                        deletion_reason=deletion_reason,
                        permanent=permanent,
                    )
                    results["successful"].append(str(quarantine_id))
                except Exception as e:
                    results["failed"].append(
                        {"quarantine_id": str(quarantine_id), "error": str(e)}
                    )

            # Log bulk operation
            await self._log_quarantine_action(
                action=ActionType.DELETE,
                quarantine_id=None,
                user_id=deleted_by,
                details={
                    "action": "bulk_delete",
                    "total_processed": results["total_processed"],
                    "successful_count": len(results["successful"]),
                    "failed_count": len(results["failed"]),
                    "permanent": permanent,
                    "reason": deletion_reason,
                },
            )

            return results

        except Exception as e:
            logger.error(f"Error in bulk delete operation: {str(e)}")
            raise

    async def cleanup_expired_quarantine(self) -> int:
        """
        Clean up expired quarantined emails.

        Returns:
            Number of emails cleaned up
        """
        try:
            current_time = datetime.utcnow()

            # Find expired emails
            expired_emails = (
                self.db.query(QuarantinedEmail)
                .filter(
                    and_(
                        QuarantinedEmail.expires_at <= current_time,
                        QuarantinedEmail.is_released == False,
                        QuarantinedEmail.is_deleted == False,
                    )
                )
                .all()
            )

            cleanup_count = 0
            for email in expired_emails:
                try:
                    # Mark as deleted (soft delete for expired emails)
                    email.is_deleted = True
                    email.deleted_at = current_time
                    email.deletion_reason = "Automatic cleanup - expired"

                    # Delete storage files for very old emails (> 90 days)
                    if email.quarantined_at < current_time - timedelta(days=90):
                        await self._delete_email_storage(email.storage_path)

                    cleanup_count += 1

                except Exception as e:
                    logger.error(f"Error cleaning up email {email.id}: {str(e)}")
                    continue

            if cleanup_count > 0:
                self.db.commit()
                logger.info(f"Cleaned up {cleanup_count} expired quarantined emails")

            return cleanup_count

        except Exception as e:
            logger.error(f"Error during quarantine cleanup: {str(e)}")
            self.db.rollback()
            raise

    async def _store_email_content(
        self,
        quarantine_id: str,
        content: str,
        headers: Dict[str, str],
        attachments: List[Dict[str, Any]],
    ) -> Path:
        """Store email content and attachments to file system."""
        try:
            # Create quarantine directory
            email_dir = self.quarantine_storage_path / "emails" / quarantine_id
            email_dir.mkdir(parents=True, exist_ok=True)

            # Store email content
            content_file = email_dir / "content.txt"
            with open(content_file, "w", encoding="utf-8") as f:
                f.write(content)

            # Store headers
            headers_file = email_dir / "headers.json"
            with open(headers_file, "w", encoding="utf-8") as f:
                json.dump(headers, f, indent=2)

            # Store attachments
            if attachments:
                attachments_dir = email_dir / "attachments"
                attachments_dir.mkdir(exist_ok=True)

                for i, attachment in enumerate(attachments):
                    att_file = (
                        attachments_dir
                        / f"attachment_{i}_{attachment.get('filename', 'unknown')}"
                    )
                    with open(att_file, "wb") as f:
                        f.write(attachment.get("content", b""))

                # Store attachment metadata
                metadata_file = attachments_dir / "metadata.json"
                with open(metadata_file, "w", encoding="utf-8") as f:
                    json.dump(
                        [
                            {
                                "filename": att.get("filename"),
                                "content_type": att.get("content_type"),
                                "size": len(att.get("content", b"")),
                            }
                            for att in attachments
                        ],
                        f,
                        indent=2,
                    )

            return email_dir

        except Exception as e:
            logger.error(f"Error storing email content: {str(e)}")
            raise

    async def _delete_email_storage(self, storage_path: str):
        """Delete email storage files."""
        try:
            storage_dir = Path(storage_path)
            if storage_dir.exists():
                shutil.rmtree(storage_dir)
                logger.debug(f"Deleted email storage: {storage_path}")
        except Exception as e:
            logger.error(f"Error deleting email storage {storage_path}: {str(e)}")

    async def _deliver_released_email(self, quarantined_email: QuarantinedEmail):
        """Deliver released email to recipient."""
        try:
            # In a real implementation, this would integrate with email delivery service
            # For now, we'll emit an event that can be handled by the email service
            await self.event_bus.emit(
                "deliver_released_email",
                {
                    "quarantine_id": str(quarantined_email.id),
                    "recipient": quarantined_email.recipient_email,
                    "sender": quarantined_email.sender_email,
                    "subject": quarantined_email.subject,
                    "storage_path": quarantined_email.storage_path,
                },
            )

            logger.info(f"Delivery queued for released email: {quarantined_email.id}")

        except Exception as e:
            logger.error(f"Error delivering released email: {str(e)}")

    async def _log_quarantine_action(
        self,
        action: ActionType,
        quarantine_id: Optional[uuid.UUID],
        user_id: Optional[uuid.UUID],
        details: Dict[str, Any],
    ):
        """Log quarantine-related actions."""
        try:
            audit_log = AuditLog(
                id=uuid.uuid4(),
                action=action,
                resource_type="quarantined_email",
                resource_id=quarantine_id,
                user_id=user_id,
                details=details,
                timestamp=datetime.utcnow(),
            )

            self.db.add(audit_log)
            # Note: Don't commit here, let the calling method handle it

        except Exception as e:
            logger.error(f"Error logging quarantine action: {str(e)}")

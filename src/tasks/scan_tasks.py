"""
Celery task for scanning emails and detecting threats.
This module handles email processing, threat detection, and quarantine operations.
"""

import os
import sys
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from celery import Celery
from celery.exceptions import MaxRetriesExceededError, Retry
from sqlalchemy.orm import Session

# Add src directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.database import get_db
from api.models.email import Email
from api.models.quarantine import QuarantineItem
from api.services.detection_engine import DetectionEngine
from api.services.quarantine_service import QuarantineService
from api.utils.config import settings
from api.utils.logger import get_logger
from ai_engine.inference import PhishingDetector
from integrations.gmail_api import GmailConnector
from integrations.microsoft365 import Microsoft365Connector

# Initialize Celery app
celery_app = Celery(
    'phishguard_tasks',
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=['tasks.scan_tasks', 'tasks.notify_tasks', 'tasks.simulation_tasks', 'tasks.cleanup_tasks', 'tasks.retrain_tasks']
)

# Celery configuration
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    worker_max_tasks_per_child=1000,
    result_expires=3600,
    task_default_retry_delay=60,
    task_max_retries=3,
    worker_log_level='INFO'
)

logger = get_logger(__name__)

# Initialize services
detection_engine = DetectionEngine()
quarantine_service = QuarantineService()
phishing_detector = PhishingDetector()


@celery_app.task(bind=True, max_retries=3, default_retry_delay=60)
def scan_email(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Scan a single email for threats and quarantine if necessary.
    
    Args:
        email_data: Dictionary containing email information
        
    Returns:
        Dictionary with scan results
    """
    try:
        logger.info(f"Starting email scan for message ID: {email_data.get('message_id')}")
        
        # Create database session
        db = next(get_db())
        
        # Extract email information
        message_id = email_data.get('message_id')
        sender = email_data.get('sender')
        recipient = email_data.get('recipient')
        subject = email_data.get('subject', '')
        body = email_data.get('body', '')
        attachments = email_data.get('attachments', [])
        headers = email_data.get('headers', {})
        
        # Validate required fields
        if not message_id or not sender or not recipient:
            raise ValueError("Missing required email fields: message_id, sender, or recipient")
        
        # Check if email already exists in database
        existing_email = db.query(Email).filter(Email.message_id == message_id).first()
        if existing_email:
            logger.info(f"Email {message_id} already processed")
            return {
                'status': 'already_processed',
                'message_id': message_id,
                'scan_time': datetime.utcnow().isoformat()
            }
        
        # Run threat detection
        detection_start = datetime.utcnow()
        
        # AI-based phishing detection
        ai_score = phishing_detector.predict_single_email(
            subject=subject,
            body=body,
            sender=sender,
            headers=headers
        )
        
        # Rule-based detection
        rule_results = detection_engine.analyze_email(
            sender=sender,
            subject=subject,
            body=body,
            headers=headers,
            attachments=attachments
        )
        
        # Combine detection results
        threat_score = max(ai_score.get('threat_score', 0), rule_results.get('threat_score', 0))
        threat_type = ai_score.get('threat_type') or rule_results.get('threat_type', 'unknown')
        confidence = min(ai_score.get('confidence', 0), rule_results.get('confidence', 0))
        
        detection_time = (datetime.utcnow() - detection_start).total_seconds()
        
        # Determine if email should be quarantined
        quarantine_threshold = settings.QUARANTINE_THRESHOLD
        is_threat = threat_score >= quarantine_threshold
        
        # Create email record
        email_record = Email(
            message_id=message_id,
            sender=sender,
            recipient=recipient,
            subject=subject,
            body=body,
            headers=headers,
            threat_score=threat_score,
            threat_type=threat_type,
            confidence=confidence,
            is_threat=is_threat,
            processed_at=datetime.utcnow(),
            detection_time=detection_time
        )
        
        db.add(email_record)
        db.commit()
        
        # Quarantine if threat detected
        quarantine_id = None
        if is_threat:
            logger.warning(f"Threat detected in email {message_id}: {threat_type} (score: {threat_score})")
            
            quarantine_result = quarantine_service.quarantine_email(
                email_id=email_record.id,
                reason=f"Detected {threat_type} with score {threat_score}",
                metadata={
                    'ai_score': ai_score,
                    'rule_results': rule_results,
                    'detection_time': detection_time
                }
            )
            quarantine_id = quarantine_result.get('quarantine_id')
            
            # Schedule notification task
            from tasks.notify_tasks import send_threat_notification
            send_threat_notification.delay(
                email_id=email_record.id,
                threat_type=threat_type,
                threat_score=threat_score
            )
        
        # Log scan completion
        logger.info(f"Email scan completed for {message_id}: threat={is_threat}, score={threat_score}")
        
        return {
            'status': 'completed',
            'message_id': message_id,
            'email_id': email_record.id,
            'is_threat': is_threat,
            'threat_score': threat_score,
            'threat_type': threat_type,
            'confidence': confidence,
            'quarantine_id': quarantine_id,
            'detection_time': detection_time,
            'scan_time': datetime.utcnow().isoformat()
        }
        
    except Exception as exc:
        logger.error(f"Error scanning email {email_data.get('message_id')}: {str(exc)}")
        
        # Retry on temporary failures
        if isinstance(exc, (ConnectionError, TimeoutError)) and self.request.retries < self.max_retries:
            logger.info(f"Retrying email scan for {email_data.get('message_id')} (attempt {self.request.retries + 1})")
            raise self.retry(exc=exc, countdown=60 * (self.request.retries + 1))
        
        # Log final failure
        logger.error(f"Failed to scan email {email_data.get('message_id')} after {self.request.retries} retries")
        
        return {
            'status': 'failed',
            'message_id': email_data.get('message_id'),
            'error': str(exc),
            'scan_time': datetime.utcnow().isoformat()
        }
    finally:
        if 'db' in locals():
            db.close()


@celery_app.task(bind=True, max_retries=3)
def scan_inbox_batch(self, provider: str, account_id: str, batch_size: int = 50) -> Dict[str, Any]:
    """
    Scan a batch of emails from an inbox provider.
    
    Args:
        provider: Email provider (gmail, outlook, exchange)
        account_id: Account identifier
        batch_size: Number of emails to process in batch
        
    Returns:
        Dictionary with batch scan results
    """
    try:
        logger.info(f"Starting batch inbox scan for {provider} account {account_id}")
        
        # Initialize appropriate connector
        if provider.lower() == 'gmail':
            connector = GmailConnector()
        elif provider.lower() in ['outlook', 'office365']:
            connector = Microsoft365Connector()
        else:
            raise ValueError(f"Unsupported email provider: {provider}")
        
        # Fetch emails from inbox
        emails = connector.fetch_recent_emails(
            account_id=account_id,
            limit=batch_size,
            since=datetime.utcnow() - timedelta(hours=24)  # Last 24 hours
        )
        
        if not emails:
            logger.info(f"No new emails found for {provider} account {account_id}")
            return {
                'status': 'completed',
                'provider': provider,
                'account_id': account_id,
                'emails_processed': 0,
                'threats_detected': 0,
                'scan_time': datetime.utcnow().isoformat()
            }
        
        # Process emails in parallel
        scan_tasks = []
        for email_data in emails:
            task = scan_email.delay(email_data)
            scan_tasks.append(task)
        
        # Wait for all tasks to complete
        results = []
        threats_detected = 0
        
        for task in scan_tasks:
            try:
                result = task.get(timeout=300)  # 5 minute timeout per email
                results.append(result)
                
                if result.get('is_threat'):
                    threats_detected += 1
                    
            except Exception as exc:
                logger.error(f"Email scan task failed: {str(exc)}")
                results.append({
                    'status': 'failed',
                    'error': str(exc)
                })
        
        logger.info(f"Batch scan completed: {len(results)} emails processed, {threats_detected} threats detected")
        
        return {
            'status': 'completed',
            'provider': provider,
            'account_id': account_id,
            'emails_processed': len(results),
            'threats_detected': threats_detected,
            'results': results,
            'scan_time': datetime.utcnow().isoformat()
        }
        
    except Exception as exc:
        logger.error(f"Error in batch inbox scan: {str(exc)}")
        
        if self.request.retries < self.max_retries:
            logger.info(f"Retrying batch scan (attempt {self.request.retries + 1})")
            raise self.retry(exc=exc, countdown=300)  # 5 minute retry delay
        
        return {
            'status': 'failed',
            'provider': provider,
            'account_id': account_id,
            'error': str(exc),
            'scan_time': datetime.utcnow().isoformat()
        }


@celery_app.task
def scan_all_inboxes() -> Dict[str, Any]:
    """
    Scan all configured email inboxes for threats.
    This is typically run as a scheduled task.
    
    Returns:
        Dictionary with overall scan results
    """
    try:
        logger.info("Starting scheduled scan of all inboxes")
        
        db = next(get_db())
        
        # Get all configured email accounts
        # This would typically come from a configuration table
        email_accounts = [
            {'provider': 'gmail', 'account_id': 'admin@company.com'},
            {'provider': 'office365', 'account_id': 'security@company.com'},
            # Add more accounts as configured
        ]
        
        scan_tasks = []
        for account in email_accounts:
            task = scan_inbox_batch.delay(
                provider=account['provider'],
                account_id=account['account_id']
            )
            scan_tasks.append(task)
        
        # Wait for all scans to complete
        total_emails = 0
        total_threats = 0
        failed_accounts = 0
        
        for task in scan_tasks:
            try:
                result = task.get(timeout=1800)  # 30 minute timeout per account
                total_emails += result.get('emails_processed', 0)
                total_threats += result.get('threats_detected', 0)
            except Exception as exc:
                logger.error(f"Account scan failed: {str(exc)}")
                failed_accounts += 1
        
        logger.info(f"All inbox scan completed: {total_emails} emails, {total_threats} threats")
        
        return {
            'status': 'completed',
            'total_emails_processed': total_emails,
            'total_threats_detected': total_threats,
            'failed_accounts': failed_accounts,
            'scan_time': datetime.utcnow().isoformat()
        }
        
    except Exception as exc:
        logger.error(f"Error in scheduled inbox scan: {str(exc)}")
        return {
            'status': 'failed',
            'error': str(exc),
            'scan_time': datetime.utcnow().isoformat()
        }
    finally:
        if 'db' in locals():
            db.close()


@celery_app.task(bind=True, max_retries=3)
def rescan_quarantined_email(self, quarantine_id: int) -> Dict[str, Any]:
    """
    Rescan a quarantined email with updated detection models.
    
    Args:
        quarantine_id: ID of quarantined email to rescan
        
    Returns:
        Dictionary with rescan results
    """
    try:
        logger.info(f"Rescanning quarantined email {quarantine_id}")
        
        db = next(get_db())
        
        # Get quarantined email
        quarantine_item = db.query(QuarantineItem).filter(
            QuarantineItem.id == quarantine_id
        ).first()
        
        if not quarantine_item:
            raise ValueError(f"Quarantine item {quarantine_id} not found")
        
        email = quarantine_item.email
        if not email:
            raise ValueError(f"Email not found for quarantine item {quarantine_id}")
        
        # Re-run detection with current models
        ai_score = phishing_detector.predict_single_email(
            subject=email.subject,
            body=email.body,
            sender=email.sender,
            headers=email.headers
        )
        
        rule_results = detection_engine.analyze_email(
            sender=email.sender,
            subject=email.subject,
            body=email.body,
            headers=email.headers
        )
        
        # Update threat score
        new_threat_score = max(ai_score.get('threat_score', 0), rule_results.get('threat_score', 0))
        old_threat_score = email.threat_score
        
        # Update email record
        email.threat_score = new_threat_score
        email.confidence = min(ai_score.get('confidence', 0), rule_results.get('confidence', 0))
        email.rescanned_at = datetime.utcnow()
        
        # Determine if email should be released
        quarantine_threshold = settings.QUARANTINE_THRESHOLD
        should_release = new_threat_score < quarantine_threshold
        
        if should_release:
            logger.info(f"Releasing email {email.id} after rescan (score: {new_threat_score})")
            quarantine_service.release_email(quarantine_id, reason="Rescan determined not a threat")
        
        db.commit()
        
        logger.info(f"Rescan completed for quarantine {quarantine_id}: {old_threat_score} -> {new_threat_score}")
        
        return {
            'status': 'completed',
            'quarantine_id': quarantine_id,
            'email_id': email.id,
            'old_threat_score': old_threat_score,
            'new_threat_score': new_threat_score,
            'released': should_release,
            'rescan_time': datetime.utcnow().isoformat()
        }
        
    except Exception as exc:
        logger.error(f"Error rescanning quarantined email {quarantine_id}: {str(exc)}")
        
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc, countdown=300)
        
        return {
            'status': 'failed',
            'quarantine_id': quarantine_id,
            'error': str(exc),
            'rescan_time': datetime.utcnow().isoformat()
        }
    finally:
        if 'db' in locals():
            db.close()


@celery_app.task
def update_threat_intelligence() -> Dict[str, Any]:
    """
    Update threat intelligence feeds and detection rules.
    
    Returns:
        Dictionary with update results
    """
    try:
        logger.info("Updating threat intelligence feeds")
        
        # Update detection engine rules
        rules_updated = detection_engine.update_rules()
        
        # Update AI model if new version available
        model_updated = phishing_detector.check_and_update_model()
        
        return {
            'status': 'completed',
            'rules_updated': rules_updated,
            'model_updated': model_updated,
            'update_time': datetime.utcnow().isoformat()
        }
        
    except Exception as exc:
        logger.error(f"Error updating threat intelligence: {str(exc)}")
        return {
            'status': 'failed',
            'error': str(exc),
            'update_time': datetime.utcnow().isoformat()
        }


# Configure periodic tasks
celery_app.conf.beat_schedule = {
    'scan-all-inboxes': {
        'task': 'tasks.scan_tasks.scan_all_inboxes',
        'schedule': 300.0,  # Every 5 minutes
    },
    'update-threat-intelligence': {
        'task': 'tasks.scan_tasks.update_threat_intelligence',
        'schedule': 3600.0,  # Every hour
    },
}

if __name__ == '__main__':
    # For testing individual tasks
    pass

"""
Celery tasks for system cleanup and maintenance operations.
This module handles database cleanup, file management, and system optimization.
"""

import os
import sys
import logging
import shutil
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from celery import Celery
from sqlalchemy.orm import Session
from sqlalchemy import func

# Add src directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.database import get_db
from api.models.email import Email
from api.models.quarantine import QuarantineItem
from api.models.notification import Notification
from api.models.audit_log import AuditLog
from api.models.simulation import SimulationResult
from api.utils.config import settings
from api.utils.logger import get_logger
from tasks.notify_tasks import send_system_alert

# Get Celery app instance
from tasks.scan_tasks import celery_app

logger = get_logger(__name__)


@celery_app.task
def cleanup_old_emails(days_to_keep: int = 90) -> Dict[str, Any]:
    """
    Clean up old email records and associated files.
    
    Args:
        days_to_keep: Number of days to keep email records
        
    Returns:
        Dictionary with cleanup results
    """
    try:
        logger.info(f"Starting cleanup of emails older than {days_to_keep} days")
        
        db = next(get_db())
        
        # Calculate cutoff date
        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
        
        # Get old email records
        old_emails = db.query(Email).filter(
            Email.processed_at < cutoff_date,
            Email.is_threat == False  # Don't delete threat emails too quickly
        ).all()
        
        emails_deleted = 0
        files_deleted = 0
        space_freed = 0
        
        for email in old_emails:
            try:
                # Delete associated files
                if hasattr(email, 'file_path') and email.file_path:
                    if os.path.exists(email.file_path):
                        file_size = os.path.getsize(email.file_path)
                        os.remove(email.file_path)
                        files_deleted += 1
                        space_freed += file_size
                
                # Delete email record
                db.delete(email)
                emails_deleted += 1
                
            except Exception as exc:
                logger.error(f"Error deleting email {email.id}: {str(exc)}")
                continue
        
        db.commit()
        
        logger.info(f"Email cleanup completed: {emails_deleted} emails, {files_deleted} files, {space_freed} bytes freed")
        
        return {
            'status': 'completed',
            'emails_deleted': emails_deleted,
            'files_deleted': files_deleted,
            'space_freed_bytes': space_freed,
            'space_freed_mb': round(space_freed / (1024 * 1024), 2),
            'cutoff_date': cutoff_date.isoformat(),
            'completed_at': datetime.utcnow().isoformat()
        }
        
    except Exception as exc:
        logger.error(f"Error in email cleanup: {str(exc)}")
        return {
            'status': 'failed',
            'error': str(exc),
            'completed_at': datetime.utcnow().isoformat()
        }
    finally:
        if 'db' in locals():
            db.close()


@celery_app.task
def cleanup_quarantine_files(days_to_keep: int = 365) -> Dict[str, Any]:
    """
    Clean up old quarantined email files.
    
    Args:
        days_to_keep: Number of days to keep quarantined files
        
    Returns:
        Dictionary with cleanup results
    """
    try:
        logger.info(f"Starting cleanup of quarantine files older than {days_to_keep} days")
        
        db = next(get_db())
        
        # Calculate cutoff date
        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
        
        # Get old quarantine items that have been released or processed
        old_quarantine_items = db.query(QuarantineItem).filter(
            QuarantineItem.quarantined_at < cutoff_date,
            QuarantineItem.status.in_(['released', 'deleted', 'processed'])
        ).all()
        
        items_processed = 0
        files_deleted = 0
        attachments_deleted = 0
        space_freed = 0
        
        quarantine_storage_path = os.path.join(
            settings.QUARANTINE_STORAGE_PATH, 
            'quarantined_emails'
        )
        
        for item in old_quarantine_items:
            try:
                # Delete email file
                if item.file_path and os.path.exists(item.file_path):
                    file_size = os.path.getsize(item.file_path)
                    os.remove(item.file_path)
                    files_deleted += 1
                    space_freed += file_size
                
                # Delete attachment files
                if item.attachments_path and os.path.exists(item.attachments_path):
                    for root, dirs, files in os.walk(item.attachments_path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            file_size = os.path.getsize(file_path)
                            os.remove(file_path)
                            attachments_deleted += 1
                            space_freed += file_size
                    
                    # Remove directory if empty
                    try:
                        os.rmdir(item.attachments_path)
                    except OSError:
                        pass  # Directory not empty
                
                # Update quarantine item status
                item.files_deleted = True
                items_processed += 1
                
            except Exception as exc:
                logger.error(f"Error processing quarantine item {item.id}: {str(exc)}")
                continue
        
        db.commit()
        
        logger.info(f"Quarantine cleanup completed: {items_processed} items, {files_deleted} files, {attachments_deleted} attachments")
        
        return {
            'status': 'completed',
            'items_processed': items_processed,
            'files_deleted': files_deleted,
            'attachments_deleted': attachments_deleted,
            'space_freed_bytes': space_freed,
            'space_freed_mb': round(space_freed / (1024 * 1024), 2),
            'cutoff_date': cutoff_date.isoformat(),
            'completed_at': datetime.utcnow().isoformat()
        }
        
    except Exception as exc:
        logger.error(f"Error in quarantine cleanup: {str(exc)}")
        return {
            'status': 'failed',
            'error': str(exc),
            'completed_at': datetime.utcnow().isoformat()
        }
    finally:
        if 'db' in locals():
            db.close()


@celery_app.task
def cleanup_old_notifications(days_to_keep: int = 30) -> Dict[str, Any]:
    """
    Clean up old notification records.
    
    Args:
        days_to_keep: Number of days to keep notifications
        
    Returns:
        Dictionary with cleanup results
    """
    try:
        logger.info(f"Starting cleanup of notifications older than {days_to_keep} days")
        
        db = next(get_db())
        
        # Calculate cutoff date
        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
        
        # Delete old notifications (keep critical ones longer)
        old_notifications = db.query(Notification).filter(
            Notification.created_at < cutoff_date,
            Notification.severity.in_(['low', 'medium'])  # Keep high/critical longer
        )
        
        notifications_count = old_notifications.count()
        old_notifications.delete(synchronize_session=False)
        
        db.commit()
        
        logger.info(f"Notification cleanup completed: {notifications_count} notifications deleted")
        
        return {
            'status': 'completed',
            'notifications_deleted': notifications_count,
            'cutoff_date': cutoff_date.isoformat(),
            'completed_at': datetime.utcnow().isoformat()
        }
        
    except Exception as exc:
        logger.error(f"Error in notification cleanup: {str(exc)}")
        return {
            'status': 'failed',
            'error': str(exc),
            'completed_at': datetime.utcnow().isoformat()
        }
    finally:
        if 'db' in locals():
            db.close()


@celery_app.task
def cleanup_audit_logs(days_to_keep: int = 2555) -> Dict[str, Any]:  # ~7 years for compliance
    """
    Clean up old audit log records.
    
    Args:
        days_to_keep: Number of days to keep audit logs
        
    Returns:
        Dictionary with cleanup results
    """
    try:
        logger.info(f"Starting cleanup of audit logs older than {days_to_keep} days")
        
        db = next(get_db())
        
        # Calculate cutoff date
        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
        
        # Archive old audit logs before deletion
        archive_result = archive_audit_logs(db, cutoff_date)
        
        # Delete old audit logs
        old_logs = db.query(AuditLog).filter(
            AuditLog.timestamp < cutoff_date
        )
        
        logs_count = old_logs.count()
        old_logs.delete(synchronize_session=False)
        
        db.commit()
        
        logger.info(f"Audit log cleanup completed: {logs_count} logs deleted")
        
        return {
            'status': 'completed',
            'logs_deleted': logs_count,
            'archived': archive_result.get('archived', 0),
            'cutoff_date': cutoff_date.isoformat(),
            'completed_at': datetime.utcnow().isoformat()
        }
        
    except Exception as exc:
        logger.error(f"Error in audit log cleanup: {str(exc)}")
        return {
            'status': 'failed',
            'error': str(exc),
            'completed_at': datetime.utcnow().isoformat()
        }
    finally:
        if 'db' in locals():
            db.close()


@celery_app.task
def cleanup_simulation_data(days_to_keep: int = 180) -> Dict[str, Any]:
    """
    Clean up old simulation result data.
    
    Args:
        days_to_keep: Number of days to keep simulation data
        
    Returns:
        Dictionary with cleanup results
    """
    try:
        logger.info(f"Starting cleanup of simulation data older than {days_to_keep} days")
        
        db = next(get_db())
        
        # Calculate cutoff date
        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
        
        # Get old simulation results
        old_results = db.query(SimulationResult).filter(
            SimulationResult.created_at < cutoff_date
        )
        
        results_count = old_results.count()
        
        # Archive simulation data before deletion
        archive_file = archive_simulation_data(old_results.all())
        
        # Delete old simulation results
        old_results.delete(synchronize_session=False)
        
        db.commit()
        
        logger.info(f"Simulation data cleanup completed: {results_count} results deleted")
        
        return {
            'status': 'completed',
            'results_deleted': results_count,
            'archive_file': archive_file,
            'cutoff_date': cutoff_date.isoformat(),
            'completed_at': datetime.utcnow().isoformat()
        }
        
    except Exception as exc:
        logger.error(f"Error in simulation data cleanup: {str(exc)}")
        return {
            'status': 'failed',
            'error': str(exc),
            'completed_at': datetime.utcnow().isoformat()
        }
    finally:
        if 'db' in locals():
            db.close()


@celery_app.task
def optimize_database() -> Dict[str, Any]:
    """
    Optimize database performance by running maintenance operations.
    
    Returns:
        Dictionary with optimization results
    """
    try:
        logger.info("Starting database optimization")
        
        db = next(get_db())
        
        optimization_results = {}
        
        # Analyze database statistics
        try:
            db.execute("ANALYZE;")
            optimization_results['analyze'] = 'completed'
        except Exception as exc:
            logger.warning(f"Database analyze failed: {str(exc)}")
            optimization_results['analyze'] = f'failed: {str(exc)}'
        
        # Vacuum database (for PostgreSQL)
        try:
            db.execute("VACUUM;")
            optimization_results['vacuum'] = 'completed'
        except Exception as exc:
            logger.warning(f"Database vacuum failed: {str(exc)}")
            optimization_results['vacuum'] = f'failed: {str(exc)}'
        
        # Update table statistics
        try:
            db.execute("UPDATE pg_stat_user_tables SET reltuples = (SELECT count(*) FROM emails) WHERE relname = 'emails';")
            optimization_results['statistics_update'] = 'completed'
        except Exception as exc:
            logger.warning(f"Statistics update failed: {str(exc)}")
            optimization_results['statistics_update'] = f'failed: {str(exc)}'
        
        db.commit()
        
        logger.info("Database optimization completed")
        
        return {
            'status': 'completed',
            'operations': optimization_results,
            'completed_at': datetime.utcnow().isoformat()
        }
        
    except Exception as exc:
        logger.error(f"Error in database optimization: {str(exc)}")
        return {
            'status': 'failed',
            'error': str(exc),
            'completed_at': datetime.utcnow().isoformat()
        }
    finally:
        if 'db' in locals():
            db.close()


@celery_app.task
def cleanup_temp_files() -> Dict[str, Any]:
    """
    Clean up temporary files and directories.
    
    Returns:
        Dictionary with cleanup results
    """
    try:
        logger.info("Starting temporary file cleanup")
        
        temp_directories = [
            '/tmp/phishguard',
            settings.TEMP_STORAGE_PATH,
            os.path.join(settings.QUARANTINE_STORAGE_PATH, 'temp'),
        ]
        
        files_deleted = 0
        directories_deleted = 0
        space_freed = 0
        
        for temp_dir in temp_directories:
            if not os.path.exists(temp_dir):
                continue
                
            try:
                for root, dirs, files in os.walk(temp_dir):
                    # Delete files older than 24 hours
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            file_stat = os.stat(file_path)
                            file_age = datetime.now() - datetime.fromtimestamp(file_stat.st_mtime)
                            
                            if file_age > timedelta(hours=24):
                                file_size = file_stat.st_size
                                os.remove(file_path)
                                files_deleted += 1
                                space_freed += file_size
                                
                        except Exception as exc:
                            logger.warning(f"Could not delete temp file {file_path}: {str(exc)}")
                            continue
                    
                    # Delete empty directories
                    for dir_name in dirs:
                        dir_path = os.path.join(root, dir_name)
                        try:
                            if not os.listdir(dir_path):  # Directory is empty
                                os.rmdir(dir_path)
                                directories_deleted += 1
                        except Exception as exc:
                            logger.warning(f"Could not delete temp directory {dir_path}: {str(exc)}")
                            continue
                            
            except Exception as exc:
                logger.error(f"Error cleaning temp directory {temp_dir}: {str(exc)}")
                continue
        
        logger.info(f"Temp file cleanup completed: {files_deleted} files, {directories_deleted} directories")
        
        return {
            'status': 'completed',
            'files_deleted': files_deleted,
            'directories_deleted': directories_deleted,
            'space_freed_bytes': space_freed,
            'space_freed_mb': round(space_freed / (1024 * 1024), 2),
            'completed_at': datetime.utcnow().isoformat()
        }
        
    except Exception as exc:
        logger.error(f"Error in temp file cleanup: {str(exc)}")
        return {
            'status': 'failed',
            'error': str(exc),
            'completed_at': datetime.utcnow().isoformat()
        }


@celery_app.task
def check_disk_space() -> Dict[str, Any]:
    """
    Check disk space usage and send alerts if necessary.
    
    Returns:
        Dictionary with disk space information
    """
    try:
        logger.info("Checking disk space usage")
        
        # Check main storage paths
        storage_paths = [
            settings.QUARANTINE_STORAGE_PATH,
            settings.LOG_STORAGE_PATH,
            '/tmp'
        ]
        
        disk_usage = {}
        alerts_sent = 0
        
        for path in storage_paths:
            if not os.path.exists(path):
                continue
                
            try:
                statvfs = os.statvfs(path)
                total_space = statvfs.f_frsize * statvfs.f_blocks
                free_space = statvfs.f_frsize * statvfs.f_available
                used_space = total_space - free_space
                usage_percent = (used_space / total_space) * 100
                
                disk_usage[path] = {
                    'total_gb': round(total_space / (1024**3), 2),
                    'used_gb': round(used_space / (1024**3), 2),
                    'free_gb': round(free_space / (1024**3), 2),
                    'usage_percent': round(usage_percent, 2)
                }
                
                # Send alert if usage is high
                if usage_percent > 90:
                    send_system_alert.delay(
                        alert_type='disk_space_critical',
                        message=f"Disk usage for {path} is at {usage_percent:.1f}%",
                        severity='critical',
                        metadata={'path': path, 'usage_percent': usage_percent}
                    )
                    alerts_sent += 1
                elif usage_percent > 80:
                    send_system_alert.delay(
                        alert_type='disk_space_warning',
                        message=f"Disk usage for {path} is at {usage_percent:.1f}%",
                        severity='high',
                        metadata={'path': path, 'usage_percent': usage_percent}
                    )
                    alerts_sent += 1
                    
            except Exception as exc:
                logger.error(f"Error checking disk space for {path}: {str(exc)}")
                disk_usage[path] = {'error': str(exc)}
        
        logger.info(f"Disk space check completed, {alerts_sent} alerts sent")
        
        return {
            'status': 'completed',
            'disk_usage': disk_usage,
            'alerts_sent': alerts_sent,
            'checked_at': datetime.utcnow().isoformat()
        }
        
    except Exception as exc:
        logger.error(f"Error checking disk space: {str(exc)}")
        return {
            'status': 'failed',
            'error': str(exc),
            'checked_at': datetime.utcnow().isoformat()
        }


@celery_app.task
def generate_system_health_report() -> Dict[str, Any]:
    """
    Generate comprehensive system health report.
    
    Returns:
        Dictionary with system health information
    """
    try:
        logger.info("Generating system health report")
        
        db = next(get_db())
        
        # Database statistics
        email_count = db.query(Email).count()
        threat_count = db.query(Email).filter(Email.is_threat == True).count()
        quarantine_count = db.query(QuarantineItem).filter(
            QuarantineItem.status == 'quarantined'
        ).count()
        
        # Recent activity (last 24 hours)
        yesterday = datetime.utcnow() - timedelta(days=1)
        recent_emails = db.query(Email).filter(Email.processed_at >= yesterday).count()
        recent_threats = db.query(Email).filter(
            Email.processed_at >= yesterday,
            Email.is_threat == True
        ).count()
        
        # System performance metrics
        disk_space_result = check_disk_space()
        
        # Calculate detection rate
        detection_rate = (threat_count / email_count * 100) if email_count > 0 else 0
        
        health_report = {
            'generated_at': datetime.utcnow().isoformat(),
            'database_stats': {
                'total_emails': email_count,
                'total_threats': threat_count,
                'quarantined_items': quarantine_count,
                'detection_rate_percent': round(detection_rate, 2)
            },
            'recent_activity': {
                'emails_last_24h': recent_emails,
                'threats_last_24h': recent_threats,
                'threat_rate_last_24h': round((recent_threats / recent_emails * 100) if recent_emails > 0 else 0, 2)
            },
            'system_performance': {
                'disk_usage': disk_space_result.get('disk_usage', {}),
                'database_size_mb': get_database_size()
            },
            'health_score': calculate_system_health_score(
                detection_rate,
                recent_emails,
                disk_space_result.get('disk_usage', {})
            )
        }
        
        logger.info("System health report generated")
        
        return {
            'status': 'completed',
            'health_report': health_report,
            'generated_at': datetime.utcnow().isoformat()
        }
        
    except Exception as exc:
        logger.error(f"Error generating system health report: {str(exc)}")
        return {
            'status': 'failed',
            'error': str(exc),
            'generated_at': datetime.utcnow().isoformat()
        }
    finally:
        if 'db' in locals():
            db.close()


# Helper functions

def archive_audit_logs(db: Session, cutoff_date: datetime) -> Dict[str, Any]:
    """Archive audit logs before deletion."""
    try:
        logs_to_archive = db.query(AuditLog).filter(
            AuditLog.timestamp < cutoff_date
        ).all()
        
        if not logs_to_archive:
            return {'archived': 0}
        
        # Create archive file
        archive_dir = os.path.join(settings.LOG_STORAGE_PATH, 'archives')
        os.makedirs(archive_dir, exist_ok=True)
        
        archive_filename = f"audit_logs_{cutoff_date.strftime('%Y%m%d')}.csv"
        archive_path = os.path.join(archive_dir, archive_filename)
        
        # Write logs to CSV file
        import csv
        with open(archive_path, 'w', newline='') as csvfile:
            fieldnames = ['timestamp', 'user_id', 'action', 'resource', 'ip_address', 'details']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for log in logs_to_archive:
                writer.writerow({
                    'timestamp': log.timestamp.isoformat(),
                    'user_id': log.user_id,
                    'action': log.action,
                    'resource': log.resource,
                    'ip_address': log.ip_address,
                    'details': log.details
                })
        
        return {'archived': len(logs_to_archive), 'archive_file': archive_path}
        
    except Exception as exc:
        logger.error(f"Error archiving audit logs: {str(exc)}")
        return {'archived': 0, 'error': str(exc)}


def archive_simulation_data(simulation_results: List) -> Optional[str]:
    """Archive simulation results before deletion."""
    try:
        if not simulation_results:
            return None
        
        # Create archive directory
        archive_dir = os.path.join(settings.LOG_STORAGE_PATH, 'simulation_archives')
        os.makedirs(archive_dir, exist_ok=True)
        
        archive_filename = f"simulation_data_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
        archive_path = os.path.join(archive_dir, archive_filename)
        
        # Write simulation data to CSV
        import csv
        with open(archive_path, 'w', newline='') as csvfile:
            fieldnames = [
                'simulation_id', 'user_id', 'email_sent', 'sent_at',
                'clicked', 'clicked_at', 'reported', 'reported_at', 'status'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in simulation_results:
                writer.writerow({
                    'simulation_id': result.simulation_id,
                    'user_id': result.user_id,
                    'email_sent': result.email_sent,
                    'sent_at': result.sent_at.isoformat() if result.sent_at else None,
                    'clicked': result.clicked,
                    'clicked_at': result.clicked_at.isoformat() if result.clicked_at else None,
                    'reported': result.reported,
                    'reported_at': result.reported_at.isoformat() if result.reported_at else None,
                    'status': result.status
                })
        
        return archive_path
        
    except Exception as exc:
        logger.error(f"Error archiving simulation data: {str(exc)}")
        return None


def get_database_size() -> float:
    """Get database size in MB."""
    try:
        # This is PostgreSQL specific - adjust for other databases
        db = next(get_db())
        result = db.execute(
            "SELECT pg_size_pretty(pg_database_size(current_database()));"
        ).fetchone()
        
        if result:
            size_str = result[0]
            # Parse size string (e.g., "123 MB", "1.5 GB")
            if 'MB' in size_str:
                return float(size_str.replace(' MB', ''))
            elif 'GB' in size_str:
                return float(size_str.replace(' GB', '')) * 1024
            elif 'KB' in size_str:
                return float(size_str.replace(' KB', '')) / 1024
        
        return 0.0
        
    except Exception as exc:
        logger.error(f"Error getting database size: {str(exc)}")
        return 0.0


def calculate_system_health_score(
    detection_rate: float,
    recent_activity: int,
    disk_usage: Dict[str, Any]
) -> int:
    """Calculate overall system health score (0-100)."""
    score = 100
    
    # Penalize for low detection accuracy
    if detection_rate < 80:
        score -= 20
    elif detection_rate < 90:
        score -= 10
    
    # Penalize for low activity (system might be down)
    if recent_activity < 10:
        score -= 30
    elif recent_activity < 50:
        score -= 15
    
    # Penalize for high disk usage
    for path, usage in disk_usage.items():
        if isinstance(usage, dict) and 'usage_percent' in usage:
            usage_percent = usage['usage_percent']
            if usage_percent > 90:
                score -= 25
            elif usage_percent > 80:
                score -= 15
            elif usage_percent > 70:
                score -= 5
    
    return max(0, min(100, score))


# Configure periodic cleanup tasks
celery_app.conf.beat_schedule.update({
    'cleanup-old-emails': {
        'task': 'tasks.cleanup_tasks.cleanup_old_emails',
        'schedule': 86400.0,  # Daily
        'kwargs': {'days_to_keep': 90}
    },
    'cleanup-quarantine-files': {
        'task': 'tasks.cleanup_tasks.cleanup_quarantine_files',
        'schedule': 604800.0,  # Weekly
        'kwargs': {'days_to_keep': 365}
    },
    'cleanup-old-notifications': {
        'task': 'tasks.cleanup_tasks.cleanup_old_notifications',
        'schedule': 86400.0,  # Daily
        'kwargs': {'days_to_keep': 30}
    },
    'cleanup-temp-files': {
        'task': 'tasks.cleanup_tasks.cleanup_temp_files',
        'schedule': 3600.0,  # Hourly
    },
    'check-disk-space': {
        'task': 'tasks.cleanup_tasks.check_disk_space',
        'schedule': 1800.0,  # Every 30 minutes
    },
    'optimize-database': {
        'task': 'tasks.cleanup_tasks.optimize_database',
        'schedule': 604800.0,  # Weekly
    },
    'generate-system-health-report': {
        'task': 'tasks.cleanup_tasks.generate_system_health_report',
        'schedule': 21600.0,  # Every 6 hours
    },
})

if __name__ == '__main__':
    # For testing individual tasks
    pass

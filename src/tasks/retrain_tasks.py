"""
Celery tasks for AI model retraining and machine learning operations.
This module handles model updates, training data preparation, and model evaluation.
"""

import os
import sys
import logging
import pickle
import joblib
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from celery import Celery
from sqlalchemy.orm import Session
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# Add src directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.database import get_db
from api.models.email import Email
from api.models.quarantine import QuarantineItem
from api.utils.config import settings
from api.utils.logger import get_logger
from ai_engine.train_model import PhishingModelTrainer
from ai_engine.feature_extraction import FeatureExtractor
from ai_engine.inference import PhishingDetector
from tasks.notify_tasks import send_system_alert

# Get Celery app instance
from tasks.scan_tasks import celery_app

logger = get_logger(__name__)

# Initialize AI components
model_trainer = PhishingModelTrainer()
feature_extractor = FeatureExtractor()


@celery_app.task(bind=True, max_retries=2, default_retry_delay=3600)
def retrain_phishing_model(
    self, 
    min_samples: int = 1000,
    validation_split: float = 0.2,
    force_retrain: bool = False
) -> Dict[str, Any]:
    """
    Retrain the phishing detection model with new data.
    
    Args:
        min_samples: Minimum number of samples required for retraining
        validation_split: Fraction of data to use for validation
        force_retrain: Force retraining even if insufficient new data
        
    Returns:
        Dictionary with retraining results
    """
    try:
        logger.info("Starting phishing model retraining")
        
        db = next(get_db())
        
        # Check if we have enough new data for retraining
        last_training_date = get_last_training_date()
        
        new_emails_query = db.query(Email).filter(
            Email.processed_at > last_training_date,
            Email.is_threat.isnot(None)  # Only labeled data
        )
        
        new_emails_count = new_emails_query.count()
        
        if new_emails_count < min_samples and not force_retrain:
            logger.info(f"Insufficient new data for retraining: {new_emails_count} < {min_samples}")
            return {
                'status': 'skipped',
                'reason': 'insufficient_data',
                'new_samples': new_emails_count,
                'min_required': min_samples,
                'checked_at': datetime.utcnow().isoformat()
            }
        
        # Prepare training data
        logger.info("Preparing training data")
        training_data = prepare_training_data(db, last_training_date)
        
        if len(training_data) < min_samples:
            logger.warning(f"Total training data insufficient: {len(training_data)} < {min_samples}")
            return {
                'status': 'failed',
                'reason': 'insufficient_total_data',
                'total_samples': len(training_data),
                'min_required': min_samples,
                'checked_at': datetime.utcnow().isoformat()
            }
        
        # Extract features
        logger.info("Extracting features")
        features, labels = extract_training_features(training_data)
        
        # Split data
        X_train, X_val, y_train, y_val = train_test_split(
            features, labels, 
            test_size=validation_split, 
            random_state=42, 
            stratify=labels
        )
        
        # Train model
        logger.info("Training new model")
        training_results = model_trainer.train_model(
            X_train, y_train, 
            X_val, y_val
        )
        
        # Evaluate model performance
        evaluation_results = evaluate_model_performance(
            model_trainer.model, X_val, y_val
        )
        
        # Compare with current model
        current_model_path = get_current_model_path()
        comparison_results = compare_model_performance(
            current_model_path, model_trainer.model, X_val, y_val
        )
        
        # Decide whether to deploy new model
        should_deploy = should_deploy_new_model(
            evaluation_results, comparison_results
        )
        
        deployment_result = None
        if should_deploy:
            logger.info("Deploying new model")
            deployment_result = deploy_new_model(model_trainer.model)
        else:
            logger.info("New model performance insufficient, keeping current model")
        
        # Update training metadata
        update_training_metadata(
            training_samples=len(training_data),
            new_samples=new_emails_count,
            evaluation_results=evaluation_results,
            deployed=should_deploy
        )
        
        # Send notification about retraining
        send_retraining_notification(
            evaluation_results, comparison_results, should_deploy
        )
        
        logger.info("Model retraining completed")
        
        return {
            'status': 'completed',
            'training_samples': len(training_data),
            'new_samples': new_emails_count,
            'evaluation_results': evaluation_results,
            'comparison_results': comparison_results,
            'model_deployed': should_deploy,
            'deployment_result': deployment_result,
            'completed_at': datetime.utcnow().isoformat()
        }
        
    except Exception as exc:
        logger.error(f"Error in model retraining: {str(exc)}")
        
        # Send alert about training failure
        send_system_alert.delay(
            alert_type='model_training_failed',
            message=f"Phishing model retraining failed: {str(exc)}",
            severity='high',
            metadata={'error': str(exc), 'attempt': self.request.retries + 1}
        )
        
        if self.request.retries < self.max_retries:
            logger.info(f"Retrying model retraining (attempt {self.request.retries + 1})")
            raise self.retry(exc=exc, countdown=3600)  # Retry in 1 hour
        
        return {
            'status': 'failed',
            'error': str(exc),
            'completed_at': datetime.utcnow().isoformat()
        }
    finally:
        if 'db' in locals():
            db.close()


@celery_app.task
def collect_model_feedback(days_lookback: int = 7) -> Dict[str, Any]:
    """
    Collect feedback on model predictions for continuous learning.
    
    Args:
        days_lookback: Number of days to look back for feedback
        
    Returns:
        Dictionary with feedback collection results
    """
    try:
        logger.info(f"Collecting model feedback for last {days_lookback} days")
        
        db = next(get_db())
        
        # Get emails from the last N days with user feedback
        cutoff_date = datetime.utcnow() - timedelta(days=days_lookback)
        
        # Get false positives (emails marked as threats but released by users)
        false_positives = db.query(Email).join(QuarantineItem).filter(
            Email.processed_at >= cutoff_date,
            Email.is_threat == True,
            QuarantineItem.status == 'released',
            QuarantineItem.release_reason.like('%false_positive%')
        ).all()
        
        # Get false negatives (emails reported by users but not detected)
        false_negatives = db.query(Email).filter(
            Email.processed_at >= cutoff_date,
            Email.is_threat == False,
            Email.user_reported == True
        ).all()
        
        # Update training data with feedback
        feedback_updates = 0
        
        for email in false_positives:
            # Update label to not a threat
            email.feedback_label = False
            email.feedback_confidence = 0.9
            email.feedback_source = 'user_release'
            feedback_updates += 1
        
        for email in false_negatives:
            # Update label to threat
            email.feedback_label = True
            email.feedback_confidence = 0.8
            email.feedback_source = 'user_report'
            feedback_updates += 1
        
        db.commit()
        
        # Calculate feedback statistics
        total_feedback = len(false_positives) + len(false_negatives)
        false_positive_rate = len(false_positives) / max(1, total_feedback) * 100
        false_negative_rate = len(false_negatives) / max(1, total_feedback) * 100
        
        logger.info(f"Feedback collection completed: {feedback_updates} updates")
        
        return {
            'status': 'completed',
            'feedback_updates': feedback_updates,
            'false_positives': len(false_positives),
            'false_negatives': len(false_negatives),
            'false_positive_rate': round(false_positive_rate, 2),
            'false_negative_rate': round(false_negative_rate, 2),
            'cutoff_date': cutoff_date.isoformat(),
            'collected_at': datetime.utcnow().isoformat()
        }
        
    except Exception as exc:
        logger.error(f"Error collecting model feedback: {str(exc)}")
        return {
            'status': 'failed',
            'error': str(exc),
            'collected_at': datetime.utcnow().isoformat()
        }
    finally:
        if 'db' in locals():
            db.close()


@celery_app.task
def update_feature_importance() -> Dict[str, Any]:
    """
    Analyze and update feature importance for the model.
    
    Returns:
        Dictionary with feature importance analysis results
    """
    try:
        logger.info("Updating feature importance analysis")
        
        # Load current model
        current_model_path = get_current_model_path()
        if not os.path.exists(current_model_path):
            raise FileNotFoundError("Current model not found")
        
        model = joblib.load(current_model_path)
        
        # Get feature names
        feature_names = feature_extractor.get_feature_names()
        
        # Extract feature importance
        if hasattr(model, 'feature_importances_'):
            # Tree-based models
            importance_scores = model.feature_importances_
        elif hasattr(model, 'coef_'):
            # Linear models
            importance_scores = np.abs(model.coef_[0])
        else:
            # For other models, use permutation importance
            importance_scores = calculate_permutation_importance(model)
        
        # Create feature importance ranking
        feature_importance = list(zip(feature_names, importance_scores))
        feature_importance.sort(key=lambda x: x[1], reverse=True)
        
        # Save feature importance data
        importance_data = {
            'updated_at': datetime.utcnow().isoformat(),
            'feature_importance': [
                {'feature': name, 'importance': float(score)}
                for name, score in feature_importance
            ],
            'top_features': [name for name, _ in feature_importance[:10]]
        }
        
        # Save to file
        importance_file = os.path.join(
            settings.MODEL_STORAGE_PATH, 
            'feature_importance.json'
        )
        
        import json
        with open(importance_file, 'w') as f:
            json.dump(importance_data, f, indent=2)
        
        logger.info("Feature importance analysis completed")
        
        return {
            'status': 'completed',
            'total_features': len(feature_names),
            'top_features': importance_data['top_features'],
            'importance_file': importance_file,
            'updated_at': datetime.utcnow().isoformat()
        }
        
    except Exception as exc:
        logger.error(f"Error updating feature importance: {str(exc)}")
        return {
            'status': 'failed',
            'error': str(exc),
            'updated_at': datetime.utcnow().isoformat()
        }


@celery_app.task
def validate_model_performance() -> Dict[str, Any]:
    """
    Validate current model performance on recent data.
    
    Returns:
        Dictionary with validation results
    """
    try:
        logger.info("Validating current model performance")
        
        db = next(get_db())
        
        # Get recent labeled data for validation
        validation_cutoff = datetime.utcnow() - timedelta(days=30)
        recent_emails = db.query(Email).filter(
            Email.processed_at >= validation_cutoff,
            Email.is_threat.isnot(None),
            Email.feedback_label.isnot(None)  # Has user feedback
        ).all()
        
        if len(recent_emails) < 100:
            logger.warning(f"Insufficient validation data: {len(recent_emails)} samples")
            return {
                'status': 'insufficient_data',
                'validation_samples': len(recent_emails),
                'min_required': 100,
                'validated_at': datetime.utcnow().isoformat()
            }
        
        # Load current model
        detector = PhishingDetector()
        
        # Prepare validation data
        validation_features = []
        true_labels = []
        
        for email in recent_emails:
            features = feature_extractor.extract_features(
                email.subject, email.body, email.sender, email.headers
            )
            validation_features.append(features)
            # Use feedback label if available, otherwise original label
            true_labels.append(email.feedback_label if email.feedback_label is not None else email.is_threat)
        
        # Make predictions
        predictions = []
        for features in validation_features:
            result = detector.predict(features)
            predictions.append(result['is_threat'])
        
        # Calculate metrics
        accuracy = accuracy_score(true_labels, predictions)
        precision = precision_score(true_labels, predictions, average='binary')
        recall = recall_score(true_labels, predictions, average='binary')
        f1 = f1_score(true_labels, predictions, average='binary')
        
        # Calculate confusion matrix components
        true_positives = sum(1 for t, p in zip(true_labels, predictions) if t and p)
        false_positives = sum(1 for t, p in zip(true_labels, predictions) if not t and p)
        true_negatives = sum(1 for t, p in zip(true_labels, predictions) if not t and not p)
        false_negatives = sum(1 for t, p in zip(true_labels, predictions) if t and not p)
        
        validation_results = {
            'validation_samples': len(recent_emails),
            'accuracy': round(accuracy, 4),
            'precision': round(precision, 4),
            'recall': round(recall, 4),
            'f1_score': round(f1, 4),
            'confusion_matrix': {
                'true_positives': true_positives,
                'false_positives': false_positives,
                'true_negatives': true_negatives,
                'false_negatives': false_negatives
            },
            'false_positive_rate': round(false_positives / max(1, false_positives + true_negatives), 4),
            'false_negative_rate': round(false_negatives / max(1, false_negatives + true_positives), 4)
        }
        
        # Check if performance has degraded
        performance_alerts = []
        if accuracy < 0.85:
            performance_alerts.append("Low accuracy detected")
        if precision < 0.80:
            performance_alerts.append("Low precision detected")
        if recall < 0.90:
            performance_alerts.append("Low recall detected")
        
        # Send alerts if performance is poor
        if performance_alerts:
            send_system_alert.delay(
                alert_type='model_performance_degraded',
                message=f"Model performance issues detected: {', '.join(performance_alerts)}",
                severity='high',
                metadata=validation_results
            )
        
        logger.info("Model validation completed")
        
        return {
            'status': 'completed',
            'validation_results': validation_results,
            'performance_alerts': performance_alerts,
            'validated_at': datetime.utcnow().isoformat()
        }
        
    except Exception as exc:
        logger.error(f"Error validating model performance: {str(exc)}")
        return {
            'status': 'failed',
            'error': str(exc),
            'validated_at': datetime.utcnow().isoformat()
        }
    finally:
        if 'db' in locals():
            db.close()


@celery_app.task
def backup_model_artifacts() -> Dict[str, Any]:
    """
    Backup current model and training artifacts.
    
    Returns:
        Dictionary with backup results
    """
    try:
        logger.info("Backing up model artifacts")
        
        model_dir = settings.MODEL_STORAGE_PATH
        backup_dir = os.path.join(model_dir, 'backups')
        os.makedirs(backup_dir, exist_ok=True)
        
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        backup_path = os.path.join(backup_dir, f'model_backup_{timestamp}')
        os.makedirs(backup_path, exist_ok=True)
        
        # Files to backup
        files_to_backup = [
            'phishing_model.pkl',
            'feature_extractor.pkl',
            'model_metadata.json',
            'feature_importance.json',
            'training_history.json'
        ]
        
        backed_up_files = []
        for filename in files_to_backup:
            source_path = os.path.join(model_dir, filename)
            if os.path.exists(source_path):
                dest_path = os.path.join(backup_path, filename)
                shutil.copy2(source_path, dest_path)
                backed_up_files.append(filename)
        
        # Create backup manifest
        manifest = {
            'backup_timestamp': timestamp,
            'backup_path': backup_path,
            'files': backed_up_files,
            'created_at': datetime.utcnow().isoformat()
        }
        
        manifest_path = os.path.join(backup_path, 'backup_manifest.json')
        import json
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)
        
        # Clean up old backups (keep last 10)
        cleanup_old_backups(backup_dir, keep_count=10)
        
        logger.info(f"Model backup completed: {len(backed_up_files)} files backed up")
        
        return {
            'status': 'completed',
            'backup_path': backup_path,
            'files_backed_up': backed_up_files,
            'backup_timestamp': timestamp,
            'completed_at': datetime.utcnow().isoformat()
        }
        
    except Exception as exc:
        logger.error(f"Error backing up model artifacts: {str(exc)}")
        return {
            'status': 'failed',
            'error': str(exc),
            'completed_at': datetime.utcnow().isoformat()
        }


# Helper functions

def get_last_training_date() -> datetime:
    """Get the date of the last model training."""
    try:
        metadata_file = os.path.join(settings.MODEL_STORAGE_PATH, 'model_metadata.json')
        if os.path.exists(metadata_file):
            import json
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            return datetime.fromisoformat(metadata.get('last_training_date', '2023-01-01T00:00:00'))
        return datetime.utcnow() - timedelta(days=365)  # Default to 1 year ago
    except Exception:
        return datetime.utcnow() - timedelta(days=365)


def prepare_training_data(db: Session, since_date: datetime) -> List[Email]:
    """Prepare training data from database."""
    # Get all labeled emails since the last training
    emails = db.query(Email).filter(
        Email.processed_at >= since_date,
        Email.is_threat.isnot(None)
    ).all()
    
    # Include feedback-labeled emails
    feedback_emails = db.query(Email).filter(
        Email.feedback_label.isnot(None)
    ).all()
    
    # Combine and deduplicate
    all_emails = {email.id: email for email in emails + feedback_emails}
    return list(all_emails.values())


def extract_training_features(emails: List[Email]) -> Tuple[np.ndarray, np.ndarray]:
    """Extract features and labels from email data."""
    features = []
    labels = []
    
    for email in emails:
        # Extract features
        email_features = feature_extractor.extract_features(
            email.subject or '',
            email.body or '',
            email.sender or '',
            email.headers or {}
        )
        features.append(email_features)
        
        # Use feedback label if available, otherwise original label
        label = email.feedback_label if email.feedback_label is not None else email.is_threat
        labels.append(label)
    
    return np.array(features), np.array(labels)


def evaluate_model_performance(model, X_val: np.ndarray, y_val: np.ndarray) -> Dict[str, float]:
    """Evaluate model performance on validation data."""
    predictions = model.predict(X_val)
    
    return {
        'accuracy': float(accuracy_score(y_val, predictions)),
        'precision': float(precision_score(y_val, predictions, average='binary')),
        'recall': float(recall_score(y_val, predictions, average='binary')),
        'f1_score': float(f1_score(y_val, predictions, average='binary'))
    }


def get_current_model_path() -> str:
    """Get path to current model file."""
    return os.path.join(settings.MODEL_STORAGE_PATH, 'phishing_model.pkl')


def compare_model_performance(
    current_model_path: str, 
    new_model, 
    X_val: np.ndarray, 
    y_val: np.ndarray
) -> Dict[str, Any]:
    """Compare new model performance with current model."""
    try:
        if not os.path.exists(current_model_path):
            return {'current_model_available': False}
        
        current_model = joblib.load(current_model_path)
        
        # Evaluate both models
        current_predictions = current_model.predict(X_val)
        new_predictions = new_model.predict(X_val)
        
        current_metrics = {
            'accuracy': accuracy_score(y_val, current_predictions),
            'precision': precision_score(y_val, current_predictions, average='binary'),
            'recall': recall_score(y_val, current_predictions, average='binary'),
            'f1_score': f1_score(y_val, current_predictions, average='binary')
        }
        
        new_metrics = {
            'accuracy': accuracy_score(y_val, new_predictions),
            'precision': precision_score(y_val, new_predictions, average='binary'),
            'recall': recall_score(y_val, new_predictions, average='binary'),
            'f1_score': f1_score(y_val, new_predictions, average='binary')
        }
        
        # Calculate improvements
        improvements = {
            metric: new_metrics[metric] - current_metrics[metric]
            for metric in current_metrics
        }
        
        return {
            'current_model_available': True,
            'current_metrics': current_metrics,
            'new_metrics': new_metrics,
            'improvements': improvements
        }
        
    except Exception as exc:
        logger.error(f"Error comparing model performance: {str(exc)}")
        return {'current_model_available': False, 'error': str(exc)}


def should_deploy_new_model(
    evaluation_results: Dict[str, float], 
    comparison_results: Dict[str, Any]
) -> bool:
    """Determine if new model should be deployed."""
    # Minimum performance thresholds
    min_accuracy = 0.85
    min_precision = 0.80
    min_recall = 0.90
    min_f1 = 0.85
    
    # Check if new model meets minimum requirements
    meets_requirements = (
        evaluation_results['accuracy'] >= min_accuracy and
        evaluation_results['precision'] >= min_precision and
        evaluation_results['recall'] >= min_recall and
        evaluation_results['f1_score'] >= min_f1
    )
    
    if not meets_requirements:
        return False
    
    # If no current model, deploy new one
    if not comparison_results.get('current_model_available', False):
        return True
    
    # Check for improvements
    improvements = comparison_results.get('improvements', {})
    
    # Deploy if there's significant improvement in any metric
    significant_improvement = any(
        improvement > 0.02 for improvement in improvements.values()
    )
    
    # Or if F1 score improves by any amount
    f1_improvement = improvements.get('f1_score', 0) > 0
    
    return significant_improvement or f1_improvement


def deploy_new_model(model) -> Dict[str, Any]:
    """Deploy new model to production."""
    try:
        model_path = get_current_model_path()
        
        # Backup current model
        if os.path.exists(model_path):
            backup_path = model_path + f'.backup_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}'
            shutil.copy2(model_path, backup_path)
        
        # Save new model
        joblib.dump(model, model_path)
        
        # Update metadata
        metadata = {
            'deployed_at': datetime.utcnow().isoformat(),
            'model_version': datetime.utcnow().strftime('%Y%m%d_%H%M%S'),
            'last_training_date': datetime.utcnow().isoformat()
        }
        
        metadata_file = os.path.join(settings.MODEL_STORAGE_PATH, 'model_metadata.json')
        import json
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        return {
            'status': 'deployed',
            'model_path': model_path,
            'deployed_at': metadata['deployed_at']
        }
        
    except Exception as exc:
        logger.error(f"Error deploying new model: {str(exc)}")
        return {
            'status': 'failed',
            'error': str(exc)
        }


def update_training_metadata(
    training_samples: int,
    new_samples: int,
    evaluation_results: Dict[str, float],
    deployed: bool
) -> None:
    """Update training metadata file."""
    try:
        metadata_file = os.path.join(settings.MODEL_STORAGE_PATH, 'training_history.json')
        
        # Load existing history
        history = []
        if os.path.exists(metadata_file):
            import json
            with open(metadata_file, 'r') as f:
                history = json.load(f)
        
        # Add new training record
        training_record = {
            'timestamp': datetime.utcnow().isoformat(),
            'training_samples': training_samples,
            'new_samples': new_samples,
            'evaluation_results': evaluation_results,
            'model_deployed': deployed
        }
        
        history.append(training_record)
        
        # Keep only last 50 training records
        if len(history) > 50:
            history = history[-50:]
        
        # Save updated history
        import json
        with open(metadata_file, 'w') as f:
            json.dump(history, f, indent=2)
            
    except Exception as exc:
        logger.error(f"Error updating training metadata: {str(exc)}")


def send_retraining_notification(
    evaluation_results: Dict[str, float],
    comparison_results: Dict[str, Any],
    deployed: bool
) -> None:
    """Send notification about model retraining."""
    try:
        if deployed:
            message = f"New phishing detection model deployed. Performance: Accuracy={evaluation_results['accuracy']:.3f}, F1={evaluation_results['f1_score']:.3f}"
            severity = 'medium'
        else:
            message = f"Model retraining completed but not deployed. Performance: Accuracy={evaluation_results['accuracy']:.3f}, F1={evaluation_results['f1_score']:.3f}"
            severity = 'low'
        
        send_system_alert.delay(
            alert_type='model_retrained',
            message=message,
            severity=severity,
            metadata={
                'evaluation_results': evaluation_results,
                'comparison_results': comparison_results,
                'deployed': deployed
            }
        )
        
    except Exception as exc:
        logger.error(f"Error sending retraining notification: {str(exc)}")


def calculate_permutation_importance(model) -> np.ndarray:
    """Calculate permutation importance for models without built-in feature importance."""
    # This is a simplified version - in practice, you'd use the full validation set
    # For now, return uniform importance
    feature_count = len(feature_extractor.get_feature_names())
    return np.ones(feature_count) / feature_count


def cleanup_old_backups(backup_dir: str, keep_count: int = 10) -> None:
    """Clean up old model backups, keeping only the most recent ones."""
    try:
        # Get all backup directories
        backup_dirs = [
            d for d in os.listdir(backup_dir)
            if os.path.isdir(os.path.join(backup_dir, d)) and d.startswith('model_backup_')
        ]
        
        # Sort by timestamp (newest first)
        backup_dirs.sort(reverse=True)
        
        # Remove old backups
        for old_backup in backup_dirs[keep_count:]:
            old_backup_path = os.path.join(backup_dir, old_backup)
            shutil.rmtree(old_backup_path)
            logger.info(f"Removed old backup: {old_backup}")
            
    except Exception as exc:
        logger.error(f"Error cleaning up old backups: {str(exc)}")


# Configure periodic retraining tasks
celery_app.conf.beat_schedule.update({
    'collect-model-feedback': {
        'task': 'tasks.retrain_tasks.collect_model_feedback',
        'schedule': 86400.0,  # Daily
        'kwargs': {'days_lookback': 7}
    },
    'validate-model-performance': {
        'task': 'tasks.retrain_tasks.validate_model_performance',
        'schedule': 604800.0,  # Weekly
    },
    'retrain-phishing-model': {
        'task': 'tasks.retrain_tasks.retrain_phishing_model',
        'schedule': 604800.0,  # Weekly
        'kwargs': {'min_samples': 500, 'force_retrain': False}
    },
    'update-feature-importance': {
        'task': 'tasks.retrain_tasks.update_feature_importance',
        'schedule': 604800.0,  # Weekly
    },
    'backup-model-artifacts': {
        'task': 'tasks.retrain_tasks.backup_model_artifacts',
        'schedule': 86400.0,  # Daily
    },
})

if __name__ == '__main__':
    # For testing individual tasks
    pass

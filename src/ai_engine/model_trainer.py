#!/usr/bin/env python3
"""
PhishGuard AI Model Training Script
Creates a production-ready phishing classifier model
"""

import logging
import os
import pickle
import sys
from datetime import datetime
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import GridSearchCV, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PhishingModelTrainer:
    """Advanced phishing detection model trainer"""

    def __init__(self):
        self.feature_names = []
        self.trained_models = {}
        self.best_model = None
        self.feature_importance = {}

    def generate_synthetic_training_data(
        self, n_samples: int = 10000
    ) -> Tuple[pd.DataFrame, np.ndarray]:
        """Generate synthetic training data for phishing detection"""

        logger.info(f"Generating {n_samples} synthetic training samples...")

        # Phishing indicators and patterns
        phishing_patterns = {
            "urgent_keywords": [
                "urgent",
                "immediate",
                "expires",
                "act now",
                "limited time",
                "verify account",
            ],
            "suspicious_phrases": [
                "click here",
                "update payment",
                "suspended account",
                "verify identity",
            ],
            "credential_requests": [
                "enter password",
                "login required",
                "confirm details",
                "update billing",
            ],
            "financial_terms": [
                "bank",
                "paypal",
                "credit card",
                "billing",
                "payment",
                "refund",
            ],
            "authority_claims": [
                "security team",
                "IT department",
                "administrator",
                "official",
            ],
            "fear_tactics": [
                "account closed",
                "legal action",
                "fraud detected",
                "security breach",
            ],
        }

        legitimate_patterns = {
            "business_terms": [
                "quarterly report",
                "meeting",
                "project update",
                "team sync",
                "deadline",
            ],
            "casual_communication": [
                "how are you",
                "catch up",
                "thanks",
                "please find attached",
                "best regards",
            ],
            "informational": [
                "newsletter",
                "announcement",
                "update",
                "information",
                "notice",
            ],
        }

        samples = []
        labels = []

        # Generate phishing samples (50% of dataset)
        for i in range(n_samples // 2):
            sample = self._generate_phishing_sample(phishing_patterns)
            samples.append(sample)
            labels.append(1)  # Phishing

        # Generate legitimate samples (50% of dataset)
        for i in range(n_samples // 2):
            sample = self._generate_legitimate_sample(legitimate_patterns)
            samples.append(sample)
            labels.append(0)  # Legitimate

        # Convert to DataFrame
        df = pd.DataFrame(samples)
        labels = np.array(labels)

        logger.info(
            f"Generated dataset with {len(df)} samples, {sum(labels)} phishing, {len(labels) - sum(labels)} legitimate"
        )

        return df, labels

    def _generate_phishing_sample(
        self, patterns: Dict[str, List[str]]
    ) -> Dict[str, Any]:
        """Generate a single phishing email sample"""

        # Random feature generation for phishing emails
        sample = {
            # Content features
            "urgency_keywords": np.random.randint(1, 5),
            "suspicious_phrases": np.random.randint(1, 4),
            "credential_requests": np.random.randint(0, 3),
            "financial_terms": np.random.randint(0, 4),
            "spelling_errors": np.random.randint(1, 8),
            "grammar_errors": np.random.randint(0, 5),
            # URL features
            "suspicious_urls": np.random.randint(1, 6),
            "url_shorteners": np.random.randint(0, 3),
            "suspicious_domains": np.random.randint(0, 4),
            "ip_addresses": np.random.randint(0, 2),
            # Header features
            "sender_reputation": np.random.uniform(0.1, 0.4),  # Low reputation
            "spf_pass": np.random.choice([0, 1], p=[0.7, 0.3]),  # Often fails
            "dkim_pass": np.random.choice([0, 1], p=[0.6, 0.4]),
            "dmarc_pass": np.random.choice([0, 1], p=[0.8, 0.2]),
            # Behavioral features
            "sender_frequency": np.random.uniform(0.0, 0.2),  # Infrequent sender
            "unusual_time": np.random.choice(
                [0, 1], p=[0.4, 0.6]
            ),  # Often unusual timing
            "mass_mailing": np.random.choice([0, 1], p=[0.3, 0.7]),  # Often mass mailed
            # Attachment features
            "suspicious_attachments": np.random.randint(0, 3),
            "executable_attachments": np.random.randint(0, 2),
            # Content structure
            "html_complexity": np.random.uniform(0.6, 1.0),  # High complexity
            "image_text_ratio": np.random.uniform(0.3, 0.9),
            "link_density": np.random.uniform(0.2, 0.8),
            # Language features
            "language_inconsistency": np.random.choice([0, 1], p=[0.4, 0.6]),
            "translation_artifacts": np.random.choice([0, 1], p=[0.7, 0.3]),
            # Content text (for TF-IDF)
            "email_content": self._generate_phishing_content(patterns),
        }

        return sample

    def _generate_legitimate_sample(
        self, patterns: Dict[str, List[str]]
    ) -> Dict[str, Any]:
        """Generate a single legitimate email sample"""

        sample = {
            # Content features
            "urgency_keywords": np.random.randint(0, 2),
            "suspicious_phrases": np.random.randint(0, 1),
            "credential_requests": np.random.randint(0, 1),
            "financial_terms": np.random.randint(0, 2),
            "spelling_errors": np.random.randint(0, 3),
            "grammar_errors": np.random.randint(0, 2),
            # URL features
            "suspicious_urls": np.random.randint(0, 2),
            "url_shorteners": np.random.randint(0, 1),
            "suspicious_domains": np.random.randint(0, 1),
            "ip_addresses": np.random.randint(0, 1),
            # Header features
            "sender_reputation": np.random.uniform(0.6, 1.0),  # High reputation
            "spf_pass": np.random.choice([0, 1], p=[0.2, 0.8]),  # Usually passes
            "dkim_pass": np.random.choice([0, 1], p=[0.3, 0.7]),
            "dmarc_pass": np.random.choice([0, 1], p=[0.3, 0.7]),
            # Behavioral features
            "sender_frequency": np.random.uniform(0.3, 1.0),  # Frequent sender
            "unusual_time": np.random.choice([0, 1], p=[0.8, 0.2]),  # Normal timing
            "mass_mailing": np.random.choice([0, 1], p=[0.7, 0.3]),  # Not mass mailed
            # Attachment features
            "suspicious_attachments": np.random.randint(0, 1),
            "executable_attachments": np.random.randint(0, 1),
            # Content structure
            "html_complexity": np.random.uniform(0.1, 0.5),  # Low complexity
            "image_text_ratio": np.random.uniform(0.0, 0.4),
            "link_density": np.random.uniform(0.0, 0.3),
            # Language features
            "language_inconsistency": np.random.choice([0, 1], p=[0.9, 0.1]),
            "translation_artifacts": np.random.choice([0, 1], p=[0.95, 0.05]),
            # Content text (for TF-IDF)
            "email_content": self._generate_legitimate_content(patterns),
        }

        return sample

    def _generate_phishing_content(self, patterns: Dict[str, List[str]]) -> str:
        """Generate phishing email content"""

        templates = [
            f"URGENT: Your account will be {np.random.choice(['suspended', 'closed', 'terminated'])} in 24 hours. {np.random.choice(patterns['credential_requests'])} to prevent this action. Click here to verify your identity immediately.",
            f"Security Alert: We detected {np.random.choice(['suspicious activity', 'unauthorized access', 'fraud'])} on your account. Please {np.random.choice(patterns['credential_requests'])} to secure your account.",
            f"Payment Required: Your {np.random.choice(['subscription', 'service', 'account'])} will expire today. Update your {np.random.choice(['billing information', 'payment method', 'credit card'])} to continue service.",
            f"Account Verification: We need to verify your account details. Please click here and {np.random.choice(patterns['credential_requests'])} to complete verification.",
            f"Limited Time Offer: Special discount expires in {np.random.choice(['1 hour', '2 hours', 'today'])}. Act now to secure this deal before it's gone forever.",
        ]

        return np.random.choice(templates)

    def _generate_legitimate_content(self, patterns: Dict[str, List[str]]) -> str:
        """Generate legitimate email content"""

        templates = [
            f"Hi there, hope you're doing well. I wanted to follow up on our {np.random.choice(['meeting', 'project', 'discussion'])} from last week. Please let me know your thoughts.",
            f"Thank you for your email. I've attached the {np.random.choice(['quarterly report', 'project update', 'meeting notes'])} you requested. Please review and let me know if you have questions.",
            f"Just a reminder that we have a {np.random.choice(['team meeting', 'project deadline', 'presentation'])} coming up next week. Looking forward to seeing everyone there.",
            f"Newsletter: Here's our monthly update with the latest {np.random.choice(['company news', 'product updates', 'industry insights'])}. Thank you for your continued interest.",
            f"Congratulations on completing the {np.random.choice(['project', 'milestone', 'training'])}. Your hard work and dedication are greatly appreciated by the entire team.",
        ]

        return np.random.choice(templates)

    def prepare_features(self, df: pd.DataFrame) -> Tuple[np.ndarray, List[str]]:
        """Prepare features for machine learning"""

        logger.info("Preparing features for training...")

        # Separate text content for TF-IDF
        text_content = df["email_content"].values

        # Numerical features
        numerical_features = [col for col in df.columns if col != "email_content"]
        numerical_data = df[numerical_features].values

        # TF-IDF vectorization for text content
        tfidf_vectorizer = TfidfVectorizer(
            max_features=1000,
            stop_words="english",
            ngram_range=(1, 2),
            min_df=2,
            max_df=0.95,
        )

        text_features = tfidf_vectorizer.fit_transform(text_content).toarray()

        # Combine numerical and text features
        combined_features = np.hstack([numerical_data, text_features])

        # Feature names
        feature_names = numerical_features + [
            f"tfidf_{i}" for i in range(text_features.shape[1])
        ]
        self.feature_names = feature_names

        # Save the TF-IDF vectorizer
        joblib.dump(tfidf_vectorizer, "phishing_tfidf_vectorizer.pkl")

        logger.info(f"Prepared {combined_features.shape[1]} features for training")

        return combined_features, feature_names

    def train_models(self, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
        """Train multiple models and select the best one"""

        logger.info("Training multiple machine learning models...")

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)

        # Save the scaler
        joblib.dump(scaler, "phishing_feature_scaler.pkl")

        # Define models to train
        models = {
            "random_forest": RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                random_state=42,
                n_jobs=-1,
            ),
            "gradient_boosting": GradientBoostingClassifier(
                n_estimators=100, learning_rate=0.1, max_depth=6, random_state=42
            ),
            "logistic_regression": LogisticRegression(
                random_state=42, max_iter=1000, C=1.0
            ),
        }

        # Train and evaluate models
        model_results = {}

        for model_name, model in models.items():
            logger.info(f"Training {model_name}...")

            # Train model
            model.fit(X_train_scaled, y_train)

            # Evaluate model
            train_score = model.score(X_train_scaled, y_train)
            test_score = model.score(X_test_scaled, y_test)

            # Cross-validation
            cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=5)

            # Predictions for detailed metrics
            y_pred = model.predict(X_test_scaled)
            y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]

            # Calculate metrics
            auc_score = roc_auc_score(y_test, y_pred_proba)

            model_results[model_name] = {
                "model": model,
                "train_score": train_score,
                "test_score": test_score,
                "cv_mean": cv_scores.mean(),
                "cv_std": cv_scores.std(),
                "auc_score": auc_score,
                "classification_report": classification_report(y_test, y_pred),
                "confusion_matrix": confusion_matrix(y_test, y_pred),
            }

            logger.info(
                f"{model_name} - Test Score: {test_score:.4f}, AUC: {auc_score:.4f}"
            )

        # Select best model based on AUC score
        best_model_name = max(
            model_results.keys(), key=lambda k: model_results[k]["auc_score"]
        )
        self.best_model = model_results[best_model_name]["model"]

        logger.info(
            f"Best model: {best_model_name} with AUC: {model_results[best_model_name]['auc_score']:.4f}"
        )

        self.trained_models = model_results

        return model_results

    def calculate_feature_importance(self):
        """Calculate feature importance for the best model"""

        if self.best_model is None:
            logger.error(
                "No trained model available for feature importance calculation"
            )
            return

        if hasattr(self.best_model, "feature_importances_"):
            importance_scores = self.best_model.feature_importances_

            # Create feature importance dictionary
            self.feature_importance = dict(zip(self.feature_names, importance_scores))

            # Sort by importance
            sorted_importance = sorted(
                self.feature_importance.items(), key=lambda x: x[1], reverse=True
            )

            logger.info("Top 10 Most Important Features:")
            for feature, importance in sorted_importance[:10]:
                logger.info(f"  {feature}: {importance:.4f}")

    def save_model(self, model_path: str = "phishing_classifier.pkl"):
        """Save the trained model and metadata"""

        if self.best_model is None:
            logger.error("No trained model to save")
            return

        # Create model package
        model_package = {
            "model": self.best_model,
            "feature_names": self.feature_names,
            "feature_importance": self.feature_importance,
            "model_metadata": {
                "training_date": datetime.now().isoformat(),
                "model_type": type(self.best_model).__name__,
                "num_features": len(self.feature_names),
                "version": "1.0.0",
            },
            "performance_metrics": self.trained_models,
        }

        # Save model
        with open(model_path, "wb") as f:
            pickle.dump(model_package, f)

        logger.info(f"Model saved to {model_path}")

        # Also save with joblib for better performance
        joblib_path = model_path.replace(".pkl", "_joblib.pkl")
        joblib.dump(model_package, joblib_path)
        logger.info(f"Model also saved to {joblib_path}")

    def create_production_model(self):
        """Create a production-ready phishing classification model"""

        logger.info("Creating production-ready phishing classification model...")

        # Generate training data
        X_df, y = self.generate_synthetic_training_data(n_samples=20000)

        # Prepare features
        X, feature_names = self.prepare_features(X_df)

        # Train models
        model_results = self.train_models(X, y)

        # Calculate feature importance
        self.calculate_feature_importance()

        # Save the model
        self.save_model()

        logger.info("Production model training completed successfully!")

        return model_results


def main():
    """Main function to create the phishing classifier model"""

    logger.info("Starting PhishGuard AI Model Training...")

    # Create trainer instance
    trainer = PhishingModelTrainer()

    # Create production model
    model_results = trainer.create_production_model()

    # Print final results
    print("\n" + "=" * 60)
    print("PHISHGUARD AI MODEL TRAINING COMPLETE")
    print("=" * 60)

    for model_name, results in model_results.items():
        print(f"\n{model_name.upper()} RESULTS:")
        print(f"  Test Accuracy: {results['test_score']:.4f}")
        print(f"  AUC Score: {results['auc_score']:.4f}")
        print(f"  CV Mean ± Std: {results['cv_mean']:.4f} ± {results['cv_std']:.4f}")

    print(f"\nBest Model: {type(trainer.best_model).__name__}")
    print(f"Model saved as: phishing_classifier.pkl")
    print("\nModel is ready for production use!")


if __name__ == "__main__":
    main()

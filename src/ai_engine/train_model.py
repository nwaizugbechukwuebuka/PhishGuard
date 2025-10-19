"""
PhishGuard AI Engine - Machine Learning Model Training

This module provides comprehensive training capabilities for phishing detection models
using state-of-the-art machine learning techniques and feature engineering.
"""

import asyncio
import json
import logging
import pickle
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GridSearchCV, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from ..utils.config import settings
from ..utils.logger import logger
from .feature_extraction import EmailFeatureExtractor


class PhishingModelTrainer:
    """
    Advanced phishing detection model trainer with ensemble methods and
    comprehensive evaluation metrics.
    """

    def __init__(self):
        """Initialize the model trainer with configuration."""
        self.models_dir = Path(settings.ML_MODEL_PATH).parent
        self.models_dir.mkdir(parents=True, exist_ok=True)

        self.feature_extractor = EmailFeatureExtractor()
        self.scaler = StandardScaler()
        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            stop_words="english",
            ngram_range=(1, 2),
            lowercase=True,
            strip_accents="unicode",
        )

        self.models = {
            "random_forest": RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1,
            ),
            "gradient_boosting": GradientBoostingClassifier(
                n_estimators=100, learning_rate=0.1, max_depth=6, random_state=42
            ),
            "logistic_regression": LogisticRegression(
                max_iter=1000, random_state=42, n_jobs=-1
            ),
        }

        self.best_model = None
        self.training_metrics = {}

    async def load_training_data(self, data_path: Optional[str] = None) -> pd.DataFrame:
        """
        Load and prepare training data from various sources.

        Args:
            data_path: Optional path to training data file

        Returns:
            pd.DataFrame: Prepared training dataset
        """
        try:
            logger.info("📊 Loading training data...")

            if data_path and Path(data_path).exists():
                # Load from provided file
                df = pd.read_csv(data_path)
                logger.info(f"Loaded {len(df)} samples from {data_path}")
            else:
                # Generate synthetic training data for demonstration
                df = await self._generate_synthetic_data()
                logger.info(f"Generated {len(df)} synthetic training samples")

            # Validate required columns
            required_columns = ["email_content", "subject", "sender", "is_phishing"]
            missing_columns = [col for col in required_columns if col not in df.columns]

            if missing_columns:
                raise ValueError(f"Missing required columns: {missing_columns}")

            # Clean and preprocess data
            df = self._preprocess_data(df)

            logger.info(f"✅ Training data prepared: {len(df)} samples")
            return df

        except Exception as e:
            logger.error(f"❌ Failed to load training data: {str(e)}")
            raise

    async def _generate_synthetic_data(self) -> pd.DataFrame:
        """
        Generate synthetic training data for demonstration purposes.

        Returns:
            pd.DataFrame: Synthetic training dataset
        """
        # Phishing examples
        phishing_samples = [
            {
                "email_content": "Your account has been suspended. Click here to verify: http://fake-bank.com/verify",
                "subject": "URGENT: Account Verification Required",
                "sender": "security@fake-bank.com",
                "is_phishing": 1,
            },
            {
                "email_content": "You have won $1,000,000! Click to claim your prize now!",
                "subject": "Congratulations! You Won!",
                "sender": "winner@lottery-scam.com",
                "is_phishing": 1,
            },
            {
                "email_content": "Your password will expire soon. Update it here: http://evil-site.com/login",
                "subject": "Password Expiration Notice",
                "sender": "admin@company-fake.com",
                "is_phishing": 1,
            },
        ]

        # Legitimate examples
        legitimate_samples = [
            {
                "email_content": "Thank you for your recent purchase. Your order #12345 will be shipped soon.",
                "subject": "Order Confirmation #12345",
                "sender": "orders@legitimate-store.com",
                "is_phishing": 0,
            },
            {
                "email_content": "Your monthly statement is now available in your account dashboard.",
                "subject": "Monthly Statement Available",
                "sender": "statements@realbank.com",
                "is_phishing": 0,
            },
            {
                "email_content": "Team meeting scheduled for tomorrow at 2 PM in conference room A.",
                "subject": "Team Meeting Tomorrow",
                "sender": "manager@company.com",
                "is_phishing": 0,
            },
        ]

        # Combine and expand dataset
        all_samples = phishing_samples + legitimate_samples
        expanded_samples = []

        # Generate variations for more training data
        for _ in range(1000):
            base_sample = np.random.choice(all_samples)
            sample = base_sample.copy()

            # Add slight variations
            if np.random.random() > 0.5:
                sample["email_content"] = self._add_text_variation(
                    sample["email_content"]
                )

            expanded_samples.append(sample)

        return pd.DataFrame(expanded_samples)

    def _add_text_variation(self, text: str) -> str:
        """Add slight variations to text for data augmentation."""
        variations = [
            text.replace("click", "Click"),
            text.replace("here", "HERE"),
            text + " Thank you.",
            text.replace(".", "!"),
        ]
        return np.random.choice(variations)

    def _preprocess_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Preprocess training data for optimal model performance.

        Args:
            df: Raw training data

        Returns:
            pd.DataFrame: Preprocessed training data
        """
        logger.info("🔄 Preprocessing training data...")

        # Remove duplicates
        df = df.drop_duplicates()

        # Handle missing values
        df["email_content"] = df["email_content"].fillna("")
        df["subject"] = df["subject"].fillna("")
        df["sender"] = df["sender"].fillna("")

        # Convert labels to binary
        df["is_phishing"] = df["is_phishing"].astype(int)

        # Remove very short emails
        df = df[df["email_content"].str.len() > 10]

        # Balance dataset if needed
        phishing_count = df[df["is_phishing"] == 1].shape[0]
        legitimate_count = df[df["is_phishing"] == 0].shape[0]

        logger.info(
            f"Dataset balance - Phishing: {phishing_count}, Legitimate: {legitimate_count}"
        )

        return df

    async def extract_features(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """
        Extract comprehensive features from email data.

        Args:
            df: Training dataframe

        Returns:
            Tuple[np.ndarray, np.ndarray]: Features and labels
        """
        logger.info("🔍 Extracting features from emails...")

        all_features = []
        labels = df["is_phishing"].values

        for idx, row in df.iterrows():
            email_data = {
                "content": row["email_content"],
                "subject": row["subject"],
                "sender": row["sender"],
            }

            # Extract features using feature extractor
            features = await self.feature_extractor.extract_all_features(email_data)
            all_features.append(list(features.values()))

        # Convert to numpy array
        X = np.array(all_features)

        # Scale numerical features
        X = self.scaler.fit_transform(X)

        logger.info(f"✅ Extracted {X.shape[1]} features from {X.shape[0]} samples")
        return X, labels

    async def train_models(self, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
        """
        Train multiple models and select the best performer.

        Args:
            X: Feature matrix
            y: Labels

        Returns:
            Dict[str, Any]: Training results and metrics
        """
        logger.info("🤖 Training phishing detection models...")

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        results = {}
        best_score = 0

        for model_name, model in self.models.items():
            logger.info(f"Training {model_name}...")

            try:
                # Train model
                model.fit(X_train, y_train)

                # Predictions
                y_pred = model.predict(X_test)
                y_pred_proba = model.predict_proba(X_test)[:, 1]

                # Calculate metrics
                metrics = {
                    "accuracy": accuracy_score(y_test, y_pred),
                    "precision": precision_score(y_test, y_pred),
                    "recall": recall_score(y_test, y_pred),
                    "f1_score": f1_score(y_test, y_pred),
                    "roc_auc": roc_auc_score(y_test, y_pred_proba),
                }

                # Cross-validation
                cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring="f1")
                metrics["cv_f1_mean"] = cv_scores.mean()
                metrics["cv_f1_std"] = cv_scores.std()

                results[model_name] = {
                    "model": model,
                    "metrics": metrics,
                    "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
                    "classification_report": classification_report(
                        y_test, y_pred, output_dict=True
                    ),
                }

                # Track best model
                if metrics["f1_score"] > best_score:
                    best_score = metrics["f1_score"]
                    self.best_model = model
                    self.best_model_name = model_name

                logger.info(
                    f"✅ {model_name} - F1: {metrics['f1_score']:.4f}, Accuracy: {metrics['accuracy']:.4f}"
                )

            except Exception as e:
                logger.error(f"❌ Failed to train {model_name}: {str(e)}")
                results[model_name] = {"error": str(e)}

        self.training_metrics = results
        logger.info(f"🏆 Best model: {self.best_model_name} (F1: {best_score:.4f})")

        return results

    async def hyperparameter_tuning(
        self, X: np.ndarray, y: np.ndarray
    ) -> Dict[str, Any]:
        """
        Perform hyperparameter tuning for the best model.

        Args:
            X: Feature matrix
            y: Labels

        Returns:
            Dict[str, Any]: Tuning results
        """
        if not self.best_model:
            raise ValueError("No best model found. Run train_models first.")

        logger.info(
            f"🔧 Performing hyperparameter tuning for {self.best_model_name}..."
        )

        # Define parameter grids
        param_grids = {
            "random_forest": {
                "n_estimators": [50, 100, 200],
                "max_depth": [5, 10, 15, None],
                "min_samples_split": [2, 5, 10],
                "min_samples_leaf": [1, 2, 4],
            },
            "gradient_boosting": {
                "n_estimators": [50, 100, 200],
                "learning_rate": [0.01, 0.1, 0.2],
                "max_depth": [3, 6, 9],
            },
            "logistic_regression": {
                "C": [0.1, 1, 10, 100],
                "penalty": ["l1", "l2"],
                "solver": ["liblinear", "lbfgs"],
            },
        }

        param_grid = param_grids.get(self.best_model_name, {})

        if not param_grid:
            logger.warning(f"No parameter grid defined for {self.best_model_name}")
            return {}

        try:
            # Grid search with cross-validation
            grid_search = GridSearchCV(
                self.best_model, param_grid, cv=5, scoring="f1", n_jobs=-1, verbose=1
            )

            grid_search.fit(X, y)

            # Update best model
            self.best_model = grid_search.best_estimator_

            tuning_results = {
                "best_params": grid_search.best_params_,
                "best_score": grid_search.best_score_,
                "cv_results": grid_search.cv_results_,
            }

            logger.info(
                f"✅ Hyperparameter tuning complete. Best F1: {grid_search.best_score_:.4f}"
            )
            logger.info(f"Best parameters: {grid_search.best_params_}")

            return tuning_results

        except Exception as e:
            logger.error(f"❌ Hyperparameter tuning failed: {str(e)}")
            return {"error": str(e)}

    async def save_model(self, model_path: Optional[str] = None) -> str:
        """
        Save the trained model and associated artifacts.

        Args:
            model_path: Optional custom path for model

        Returns:
            str: Path where model was saved
        """
        if not self.best_model:
            raise ValueError("No trained model to save")

        try:
            # Determine save path
            if model_path:
                save_path = Path(model_path)
            else:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                save_path = self.models_dir / f"phishing_model_{timestamp}.pkl"

            save_path.parent.mkdir(parents=True, exist_ok=True)

            # Prepare model package
            model_package = {
                "model": self.best_model,
                "model_name": self.best_model_name,
                "scaler": self.scaler,
                "feature_extractor": self.feature_extractor,
                "training_metrics": self.training_metrics,
                "timestamp": datetime.now().isoformat(),
                "version": settings.APP_VERSION,
            }

            # Save model
            with open(save_path, "wb") as f:
                pickle.dump(model_package, f)

            # Save human-readable metrics
            metrics_path = save_path.with_suffix(".json")
            with open(metrics_path, "w") as f:
                json.dump(self.training_metrics, f, indent=2, default=str)

            # Update main model file
            main_model_path = self.models_dir / "phishing_classifier.pkl"
            joblib.dump(model_package, main_model_path)

            logger.info(f"✅ Model saved to {save_path}")
            logger.info(f"📊 Metrics saved to {metrics_path}")

            return str(save_path)

        except Exception as e:
            logger.error(f"❌ Failed to save model: {str(e)}")
            raise

    async def evaluate_model(self, test_data: pd.DataFrame) -> Dict[str, Any]:
        """
        Evaluate model performance on test data.

        Args:
            test_data: Test dataset

        Returns:
            Dict[str, Any]: Evaluation metrics
        """
        if not self.best_model:
            raise ValueError("No trained model to evaluate")

        logger.info("📊 Evaluating model performance...")

        try:
            # Extract features from test data
            X_test, y_test = await self.extract_features(test_data)

            # Predictions
            y_pred = self.best_model.predict(X_test)
            y_pred_proba = self.best_model.predict_proba(X_test)[:, 1]

            # Calculate comprehensive metrics
            evaluation_metrics = {
                "accuracy": accuracy_score(y_test, y_pred),
                "precision": precision_score(y_test, y_pred),
                "recall": recall_score(y_test, y_pred),
                "f1_score": f1_score(y_test, y_pred),
                "roc_auc": roc_auc_score(y_test, y_pred_proba),
                "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
                "classification_report": classification_report(
                    y_test, y_pred, output_dict=True
                ),
                "test_samples": len(test_data),
            }

            logger.info(f"✅ Model evaluation complete")
            logger.info(f"Test Accuracy: {evaluation_metrics['accuracy']:.4f}")
            logger.info(f"Test F1 Score: {evaluation_metrics['f1_score']:.4f}")

            return evaluation_metrics

        except Exception as e:
            logger.error(f"❌ Model evaluation failed: {str(e)}")
            raise


async def main():
    """Main training pipeline execution."""
    try:
        logger.info("🚀 Starting PhishGuard AI model training pipeline...")

        # Initialize trainer
        trainer = PhishingModelTrainer()

        # Load training data
        training_data = await trainer.load_training_data()

        # Extract features
        X, y = await trainer.extract_features(training_data)

        # Train models
        training_results = await trainer.train_models(X, y)

        # Hyperparameter tuning
        tuning_results = await trainer.hyperparameter_tuning(X, y)

        # Save best model
        model_path = await trainer.save_model()

        logger.info("🎉 Training pipeline completed successfully!")
        logger.info(f"Model saved at: {model_path}")

        return {
            "training_results": training_results,
            "tuning_results": tuning_results,
            "model_path": model_path,
        }

    except Exception as e:
        logger.error(f"❌ Training pipeline failed: {str(e)}")
        raise


if __name__ == "__main__":
    asyncio.run(main())

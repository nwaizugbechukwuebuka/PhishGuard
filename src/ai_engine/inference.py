"""
PhishGuard AI Engine - Inference and Prediction

This module provides real-time phishing detection using trained machine learning models
with comprehensive threat analysis and confidence scoring.
"""

import asyncio
import logging
import pickle
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np

from ..utils.config import settings
from ..utils.logger import logger
from .feature_extraction import EmailFeatureExtractor


class PhishingDetector:
    """
    Real-time phishing detection engine with confidence scoring and threat analysis.

    Provides fast, accurate phishing detection using pre-trained ML models with
    comprehensive threat assessment and explainable AI features.
    """

    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the phishing detector.

        Args:
            model_path: Optional path to trained model file
        """
        self.model_path = model_path or settings.ML_MODEL_PATH
        self.model = None
        self.scaler = None
        self.feature_extractor = None
        self.model_metadata = {}
        self.is_loaded = False

        # Confidence thresholds
        self.high_confidence_threshold = settings.ML_CONFIDENCE_THRESHOLD
        self.medium_confidence_threshold = 0.6

        # Feature names for interpretation
        self.feature_names = []

    async def load_model(self) -> bool:
        """
        Load the trained phishing detection model.

        Returns:
            bool: True if model loaded successfully, False otherwise
        """
        try:
            if not Path(self.model_path).exists():
                logger.error(f"Model file not found: {self.model_path}")
                return False

            logger.info(
                f"🤖 Loading phishing detection model from {self.model_path}..."
            )

            # Load model package
            with open(self.model_path, "rb") as f:
                model_package = pickle.load(f)

            # Extract components
            self.model = model_package.get("model")
            self.scaler = model_package.get("scaler")
            self.feature_extractor = model_package.get(
                "feature_extractor", EmailFeatureExtractor()
            )
            self.model_metadata = {
                "model_name": model_package.get("model_name", "unknown"),
                "training_metrics": model_package.get("training_metrics", {}),
                "timestamp": model_package.get("timestamp"),
                "version": model_package.get("version", "1.0.0"),
            }

            if not self.model or not self.scaler:
                raise ValueError("Invalid model package: missing model or scaler")

            self.is_loaded = True
            logger.info(
                f"✅ Model loaded successfully: {self.model_metadata['model_name']}"
            )
            logger.info(f"Model version: {self.model_metadata['version']}")

            return True

        except Exception as e:
            logger.error(f"❌ Failed to load model: {str(e)}")
            self.is_loaded = False
            return False

    async def predict_phishing(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predict if an email is phishing with confidence scoring.

        Args:
            email_data: Dictionary containing email content, subject, sender, etc.

        Returns:
            Dict[str, Any]: Prediction results with confidence and threat analysis
        """
        try:
            if not self.is_loaded:
                await self.load_model()
                if not self.is_loaded:
                    return self._get_error_prediction("Model not available")

            # Extract features
            features = await self.feature_extractor.extract_all_features(email_data)
            feature_vector = np.array(list(features.values())).reshape(1, -1)

            # Scale features
            feature_vector_scaled = self.scaler.transform(feature_vector)

            # Make prediction
            prediction = self.model.predict(feature_vector_scaled)[0]
            prediction_proba = self.model.predict_proba(feature_vector_scaled)[0]

            # Calculate confidence scores
            phishing_confidence = prediction_proba[1]
            legitimate_confidence = prediction_proba[0]

            # Determine threat level
            threat_level = self._determine_threat_level(phishing_confidence)

            # Generate explanation
            explanation = await self._explain_prediction(features, phishing_confidence)

            result = {
                "is_phishing": bool(prediction),
                "phishing_confidence": float(phishing_confidence),
                "legitimate_confidence": float(legitimate_confidence),
                "threat_level": threat_level,
                "risk_score": float(phishing_confidence * 100),
                "explanation": explanation,
                "features_analyzed": len(features),
                "model_version": self.model_metadata.get("version", "1.0.0"),
                "timestamp": datetime.now().isoformat(),
            }

            logger.info(
                f"🔍 Phishing detection complete - Risk Score: {result['risk_score']:.1f}%"
            )
            return result

        except Exception as e:
            logger.error(f"❌ Phishing prediction failed: {str(e)}")
            return self._get_error_prediction(str(e))

    async def batch_predict(
        self, email_batch: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Batch prediction for multiple emails (more efficient for bulk processing).

        Args:
            email_batch: List of email data dictionaries

        Returns:
            List[Dict[str, Any]]: List of prediction results
        """
        try:
            if not self.is_loaded:
                await self.load_model()
                if not self.is_loaded:
                    return [
                        self._get_error_prediction("Model not available")
                        for _ in email_batch
                    ]

            logger.info(f"🔄 Processing batch of {len(email_batch)} emails...")

            # Extract features for all emails
            all_features = []
            for email_data in email_batch:
                features = await self.feature_extractor.extract_all_features(email_data)
                all_features.append(list(features.values()))

            # Convert to numpy array and scale
            feature_matrix = np.array(all_features)
            feature_matrix_scaled = self.scaler.transform(feature_matrix)

            # Batch prediction
            predictions = self.model.predict(feature_matrix_scaled)
            predictions_proba = self.model.predict_proba(feature_matrix_scaled)

            # Process results
            results = []
            for i, (email_data, prediction, proba) in enumerate(
                zip(email_batch, predictions, predictions_proba)
            ):
                phishing_confidence = proba[1]
                threat_level = self._determine_threat_level(phishing_confidence)

                result = {
                    "is_phishing": bool(prediction),
                    "phishing_confidence": float(phishing_confidence),
                    "legitimate_confidence": float(proba[0]),
                    "threat_level": threat_level,
                    "risk_score": float(phishing_confidence * 100),
                    "timestamp": datetime.now().isoformat(),
                }
                results.append(result)

            logger.info(
                f"✅ Batch processing complete - {len(results)} emails analyzed"
            )
            return results

        except Exception as e:
            logger.error(f"❌ Batch prediction failed: {str(e)}")
            return [self._get_error_prediction(str(e)) for _ in email_batch]

    def _determine_threat_level(self, confidence: float) -> str:
        """
        Determine threat level based on confidence score.

        Args:
            confidence: Phishing confidence score (0-1)

        Returns:
            str: Threat level (low, medium, high, critical)
        """
        if confidence >= 0.9:
            return "critical"
        elif confidence >= self.high_confidence_threshold:
            return "high"
        elif confidence >= self.medium_confidence_threshold:
            return "medium"
        else:
            return "low"

    async def _explain_prediction(
        self, features: Dict[str, Any], confidence: float
    ) -> Dict[str, Any]:
        """
        Generate explanation for the prediction using feature importance.

        Args:
            features: Extracted features
            confidence: Prediction confidence

        Returns:
            Dict[str, Any]: Explanation of the prediction
        """
        try:
            # Get feature importance if available
            feature_importance = []
            if hasattr(self.model, "feature_importances_"):
                feature_names = list(features.keys())
                importances = self.model.feature_importances_
                feature_importance = list(zip(feature_names, importances))
                feature_importance.sort(key=lambda x: x[1], reverse=True)

            # Identify top contributing factors
            top_factors = []
            risk_indicators = []

            # URL-related indicators
            if features.get("suspicious_domain_ratio", 0) > 0.5:
                risk_indicators.append("Suspicious domains detected in links")
            if features.get("url_count", 0) > 5:
                risk_indicators.append("High number of links")
            if features.get("shortened_url_ratio", 0) > 0:
                risk_indicators.append("URL shorteners detected")

            # Content-related indicators
            if features.get("urgency_score", 0) > 2:
                risk_indicators.append("Urgent language detected")
            if features.get("suspicious_keyword_count", 0) > 3:
                risk_indicators.append("Multiple suspicious keywords")
            if features.get("fear_appeal", 0) > 0:
                risk_indicators.append("Fear-based social engineering")
            if features.get("reward_appeal", 0) > 0:
                risk_indicators.append("Reward-based social engineering")

            # Sender-related indicators
            if features.get("sender_legitimate_domain", 0) == 0:
                risk_indicators.append("Sender from unfamiliar domain")
            if features.get("domain_has_numbers", 0) > 0:
                risk_indicators.append("Suspicious sender domain")

            # Technical indicators
            if (
                features.get("has_html", 0) > 0
                and features.get("html_tag_count", 0) > 10
            ):
                risk_indicators.append("Complex HTML content")
            if features.get("personal_info_requests", 0) > 0:
                risk_indicators.append("Requests for personal information")

            return {
                "confidence_level": self._get_confidence_description(confidence),
                "risk_indicators": risk_indicators[:5],  # Top 5 indicators
                "top_features": feature_importance[:10] if feature_importance else [],
                "recommendation": self._get_recommendation(confidence),
            }

        except Exception as e:
            logger.warning(f"Explanation generation failed: {e}")
            return {
                "confidence_level": self._get_confidence_description(confidence),
                "risk_indicators": ["Analysis completed with basic heuristics"],
                "top_features": [],
                "recommendation": self._get_recommendation(confidence),
            }

    def _get_confidence_description(self, confidence: float) -> str:
        """Get human-readable confidence description."""
        if confidence >= 0.9:
            return "Very High - Almost certainly phishing"
        elif confidence >= self.high_confidence_threshold:
            return "High - Likely phishing"
        elif confidence >= self.medium_confidence_threshold:
            return "Medium - Suspicious characteristics"
        elif confidence >= 0.3:
            return "Low - Some suspicious elements"
        else:
            return "Very Low - Appears legitimate"

    def _get_recommendation(self, confidence: float) -> str:
        """Get recommendation based on confidence level."""
        if confidence >= 0.9:
            return "QUARANTINE IMMEDIATELY - High risk of phishing attack"
        elif confidence >= self.high_confidence_threshold:
            return "QUARANTINE - Review before delivery"
        elif confidence >= self.medium_confidence_threshold:
            return "FLAG FOR REVIEW - Manual inspection recommended"
        elif confidence >= 0.3:
            return "MONITOR - Deliver with caution"
        else:
            return "DELIVER - Email appears safe"

    def _get_error_prediction(self, error_msg: str) -> Dict[str, Any]:
        """Get default prediction result for error cases."""
        return {
            "is_phishing": False,
            "phishing_confidence": 0.0,
            "legitimate_confidence": 1.0,
            "threat_level": "unknown",
            "risk_score": 0.0,
            "explanation": {
                "confidence_level": "Error in analysis",
                "risk_indicators": [f"Analysis failed: {error_msg}"],
                "top_features": [],
                "recommendation": "MANUAL REVIEW REQUIRED - Analysis error",
            },
            "features_analyzed": 0,
            "model_version": "error",
            "timestamp": datetime.now().isoformat(),
            "error": error_msg,
        }

    async def get_model_info(self) -> Dict[str, Any]:
        """
        Get information about the loaded model.

        Returns:
            Dict[str, Any]: Model information and metadata
        """
        if not self.is_loaded:
            return {"status": "not_loaded", "error": "Model not loaded"}

        return {
            "status": "loaded",
            "model_name": self.model_metadata.get("model_name", "unknown"),
            "version": self.model_metadata.get("version", "1.0.0"),
            "training_timestamp": self.model_metadata.get("timestamp"),
            "training_metrics": self.model_metadata.get("training_metrics", {}),
            "confidence_threshold": self.high_confidence_threshold,
            "model_path": str(self.model_path),
        }

    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check on the detection system.

        Returns:
            Dict[str, Any]: Health status
        """
        try:
            if not self.is_loaded:
                return {"status": "unhealthy", "reason": "Model not loaded"}

            # Test prediction with sample data
            test_email = {
                "content": "This is a test email for health check.",
                "subject": "Health Check",
                "sender": "test@example.com",
            }

            result = await self.predict_phishing(test_email)

            if "error" in result:
                return {"status": "unhealthy", "reason": result["error"]}

            return {
                "status": "healthy",
                "model_loaded": True,
                "test_prediction_successful": True,
                "response_time_ms": 50,  # Approximate
            }

        except Exception as e:
            return {"status": "unhealthy", "reason": str(e)}


# Singleton instance for global use
_detector_instance = None


async def get_detector() -> PhishingDetector:
    """Get singleton phishing detector instance."""
    global _detector_instance

    if _detector_instance is None:
        _detector_instance = PhishingDetector()
        await _detector_instance.load_model()

    return _detector_instance


# Convenience functions
async def predict_email_phishing(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convenience function for single email prediction.

    Args:
        email_data: Email data dictionary

    Returns:
        Dict[str, Any]: Prediction result
    """
    detector = await get_detector()
    return await detector.predict_phishing(email_data)


async def batch_predict_phishing(
    email_batch: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Convenience function for batch email prediction.

    Args:
        email_batch: List of email data dictionaries

    Returns:
        List[Dict[str, Any]]: List of prediction results
    """
    detector = await get_detector()
    return await detector.batch_predict(email_batch)

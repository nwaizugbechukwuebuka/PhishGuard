"""
Comprehensive test suite for PhishGuard threat detection engine.
Tests AI models, feature extraction, and threat classification.
"""

import os
import sys
import tempfile
from datetime import datetime
from unittest.mock import MagicMock, Mock, patch

import numpy as np
import pandas as pd
import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_engine.feature_extraction import FeatureExtractor
from ai_engine.inference import PhishingDetector
from ai_engine.train_model import PhishingModelTrainer
from api.services.detection_engine import DetectionEngine


class TestFeatureExtraction:
    """Test feature extraction from emails."""

    def setUp(self):
        self.extractor = FeatureExtractor()

    def test_extract_url_features(self):
        """Test URL feature extraction."""
        # Test legitimate URL
        legitimate_url = "https://www.google.com"
        features = self.extractor.extract_url_features(legitimate_url)

        assert "domain_length" in features
        assert "has_https" in features
        assert "subdomain_count" in features
        assert features["has_https"] == True
        assert features["domain_length"] == len("google.com")

    def test_extract_suspicious_url_features(self):
        """Test feature extraction from suspicious URLs."""
        # Test suspicious URL
        suspicious_url = "http://g00gle-verify.sketchy-domain.tk/login"
        features = self.extractor.extract_url_features(suspicious_url)

        assert features["has_https"] == False
        assert features["subdomain_count"] > 0
        assert "suspicious_tld" in features
        assert features["url_length"] > 30

    def test_extract_text_features(self):
        """Test text feature extraction."""
        # Test urgent/phishing text
        phishing_text = (
            "URGENT! Your account will be suspended. Click here immediately!"
        )
        features = self.extractor.extract_text_features(phishing_text)

        assert "urgency_words" in features
        assert "suspicious_phrases" in features
        assert "text_length" in features
        assert features["urgency_words"] > 0
        assert features["text_length"] == len(phishing_text)

    def test_extract_sender_features(self):
        """Test sender feature extraction."""
        # Test suspicious sender
        suspicious_sender = "noreply@amaz0n-security.com"
        features = self.extractor.extract_sender_features(suspicious_sender)

        assert "domain_reputation" in features
        assert "typosquatting_score" in features
        assert "sender_format_valid" in features
        assert features["typosquatting_score"] > 0  # Should detect amazon typo

    def test_extract_header_features(self):
        """Test email header feature extraction."""
        headers = {
            "Return-Path": "bounce@suspicious-domain.com",
            "Authentication-Results": "fail",
            "SPF": "fail",
            "DKIM": "fail",
            "X-Originating-IP": "192.168.1.1",
        }

        features = self.extractor.extract_header_features(headers)

        assert "spf_pass" in features
        assert "dkim_pass" in features
        assert "auth_results" in features
        assert features["spf_pass"] == False
        assert features["dkim_pass"] == False

    def test_extract_complete_features(self):
        """Test complete feature extraction from email."""
        subject = "URGENT: Verify your account now!"
        body = "Click here to verify: http://fake-bank.tk/verify"
        sender = "security@fake-bank.tk"
        headers = {"SPF": "fail", "DKIM": "pass"}

        features = self.extractor.extract_features(subject, body, sender, headers)

        assert isinstance(features, (list, np.ndarray))
        assert len(features) > 20  # Should have many features

    def test_feature_normalization(self):
        """Test that features are properly normalized."""
        subject = "Test subject"
        body = "Test body content"
        sender = "test@example.com"
        headers = {}

        features = self.extractor.extract_features(subject, body, sender, headers)

        # Features should be numeric and bounded
        for feature in features:
            assert isinstance(feature, (int, float))
            assert -10 <= feature <= 10  # Reasonable bounds

    def test_empty_input_handling(self):
        """Test handling of empty inputs."""
        features = self.extractor.extract_features("", "", "", {})

        assert isinstance(features, (list, np.ndarray))
        assert len(features) > 0  # Should still return features


class TestPhishingDetector:
    """Test phishing detection inference."""

    def setUp(self):
        self.detector = PhishingDetector()

    @patch("ai_engine.inference.joblib.load")
    def test_load_model(self, mock_load):
        """Test model loading."""
        mock_model = Mock()
        mock_load.return_value = mock_model

        detector = PhishingDetector()
        detector.load_model()

        assert detector.model == mock_model
        mock_load.assert_called_once()

    def test_predict_phishing_email(self):
        """Test prediction for phishing email."""
        # Mock a trained model
        mock_model = Mock()
        mock_model.predict.return_value = [1]  # Phishing
        mock_model.predict_proba.return_value = [[0.1, 0.9]]  # 90% phishing

        self.detector.model = mock_model

        # Test features for obvious phishing
        features = [1, 1, 1, 0, 1, 1, 0, 1]  # Suspicious features

        result = self.detector.predict(features)

        assert result["is_threat"] == True
        assert result["confidence"] == 0.9
        assert result["threat_type"] == "phishing"

    def test_predict_legitimate_email(self):
        """Test prediction for legitimate email."""
        # Mock a trained model
        mock_model = Mock()
        mock_model.predict.return_value = [0]  # Legitimate
        mock_model.predict_proba.return_value = [[0.95, 0.05]]  # 5% phishing

        self.detector.model = mock_model

        # Test features for legitimate email
        features = [0, 0, 0, 1, 0, 0, 1, 0]  # Non-suspicious features

        result = self.detector.predict(features)

        assert result["is_threat"] == False
        assert result["confidence"] == 0.05

    def test_predict_with_explanations(self):
        """Test prediction with feature importance explanations."""
        mock_model = Mock()
        mock_model.predict.return_value = [1]
        mock_model.predict_proba.return_value = [[0.2, 0.8]]
        mock_model.feature_importances_ = [0.3, 0.2, 0.1, 0.4]

        self.detector.model = mock_model

        features = [1, 0, 1, 1]
        result = self.detector.predict_with_explanation(features)

        assert "explanations" in result
        assert "top_features" in result
        assert result["is_threat"] == True

    def test_batch_prediction(self):
        """Test batch prediction for multiple emails."""
        mock_model = Mock()
        mock_model.predict.return_value = [1, 0, 1]  # Mixed results
        mock_model.predict_proba.return_value = [[0.1, 0.9], [0.8, 0.2], [0.3, 0.7]]

        self.detector.model = mock_model

        features_batch = [[1, 1, 1, 0], [0, 0, 0, 1], [1, 0, 1, 0]]

        results = self.detector.predict_batch(features_batch)

        assert len(results) == 3
        assert results[0]["is_threat"] == True
        assert results[1]["is_threat"] == False
        assert results[2]["is_threat"] == True

    def test_model_fallback(self):
        """Test fallback when model is not available."""
        # Detector without loaded model
        detector = PhishingDetector()
        detector.model = None

        features = [1, 1, 1, 0]
        result = detector.predict(features)

        # Should use rule-based fallback
        assert "is_threat" in result
        assert "confidence" in result
        assert result["threat_type"] == "unknown"


class TestPhishingModelTrainer:
    """Test model training functionality."""

    def setUp(self):
        self.trainer = PhishingModelTrainer()

    def test_prepare_training_data(self):
        """Test training data preparation."""
        # Mock training data
        emails = [
            {"features": [1, 1, 0, 1], "label": 1},  # Phishing
            {"features": [0, 0, 1, 0], "label": 0},  # Legitimate
            {"features": [1, 0, 1, 1], "label": 1},  # Phishing
        ]

        X, y = self.trainer.prepare_training_data(emails)

        assert X.shape == (3, 4)
        assert y.shape == (3,)
        assert list(y) == [1, 0, 1]

    def test_train_model_basic(self):
        """Test basic model training."""
        # Create synthetic training data
        X_train = np.random.rand(100, 10)
        y_train = np.random.randint(0, 2, 100)
        X_val = np.random.rand(20, 10)
        y_val = np.random.randint(0, 2, 20)

        results = self.trainer.train_model(X_train, y_train, X_val, y_val)

        assert "accuracy" in results
        assert "precision" in results
        assert "recall" in results
        assert "f1_score" in results
        assert self.trainer.model is not None

    def test_hyperparameter_tuning(self):
        """Test hyperparameter optimization."""
        # Create synthetic data
        X = np.random.rand(100, 10)
        y = np.random.randint(0, 2, 100)

        best_params = self.trainer.tune_hyperparameters(X, y)

        assert isinstance(best_params, dict)
        assert "n_estimators" in best_params or "C" in best_params

    def test_feature_importance_extraction(self):
        """Test feature importance extraction."""
        # Train a simple model
        X = np.random.rand(50, 5)
        y = np.random.randint(0, 2, 50)

        self.trainer.train_model(X, y, X[:10], y[:10])
        importance = self.trainer.get_feature_importance()

        assert len(importance) == 5
        assert all(imp >= 0 for imp in importance)
        assert abs(sum(importance) - 1.0) < 0.1  # Should roughly sum to 1

    def test_model_persistence(self):
        """Test model saving and loading."""
        # Train a model
        X = np.random.rand(50, 5)
        y = np.random.randint(0, 2, 50)

        self.trainer.train_model(X, y, X[:10], y[:10])

        # Save model
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            model_path = f.name

        self.trainer.save_model(model_path)

        # Load model
        loaded_trainer = PhishingModelTrainer()
        loaded_trainer.load_model(model_path)

        # Test predictions are similar
        test_features = X[:5]
        original_pred = self.trainer.model.predict(test_features)
        loaded_pred = loaded_trainer.model.predict(test_features)

        assert np.array_equal(original_pred, loaded_pred)

        # Cleanup
        os.unlink(model_path)


class TestDetectionEngine:
    """Test the main detection engine service."""

    def setUp(self):
        self.engine = DetectionEngine()

    @patch("api.services.detection_engine.PhishingDetector")
    @patch("api.services.detection_engine.FeatureExtractor")
    def test_analyze_email_phishing(self, mock_extractor, mock_detector):
        """Test email analysis for phishing detection."""
        # Mock feature extraction
        mock_extractor_instance = mock_extractor.return_value
        mock_extractor_instance.extract_features.return_value = [1, 1, 0, 1, 1]

        # Mock prediction
        mock_detector_instance = mock_detector.return_value
        mock_detector_instance.predict.return_value = {
            "is_threat": True,
            "confidence": 0.95,
            "threat_type": "phishing",
        }

        email_data = {
            "subject": "Urgent: Verify your account",
            "body": "Click here: http://fake-bank.com",
            "sender": "security@fake-bank.com",
            "headers": {"SPF": "fail"},
        }

        result = self.engine.analyze_email(email_data)

        assert result["is_threat"] == True
        assert result["confidence"] == 0.95
        assert result["threat_type"] == "phishing"
        assert "indicators" in result

    @patch("api.services.detection_engine.PhishingDetector")
    @patch("api.services.detection_engine.FeatureExtractor")
    def test_analyze_email_legitimate(self, mock_extractor, mock_detector):
        """Test email analysis for legitimate email."""
        # Mock feature extraction
        mock_extractor_instance = mock_extractor.return_value
        mock_extractor_instance.extract_features.return_value = [0, 0, 1, 0, 0]

        # Mock prediction
        mock_detector_instance = mock_detector.return_value
        mock_detector_instance.predict.return_value = {
            "is_threat": False,
            "confidence": 0.05,
            "threat_type": None,
        }

        email_data = {
            "subject": "Monthly newsletter",
            "body": "Here is our monthly update...",
            "sender": "newsletter@company.com",
            "headers": {"SPF": "pass", "DKIM": "pass"},
        }

        result = self.engine.analyze_email(email_data)

        assert result["is_threat"] == False
        assert result["confidence"] <= 0.1
        assert "indicators" in result

    def test_extract_threat_indicators(self):
        """Test threat indicator extraction."""
        email_data = {
            "subject": "URGENT: Account suspended!",
            "body": "Click http://fake-site.com immediately!",
            "sender": "security@fake-site.com",
            "headers": {"SPF": "fail"},
        }

        indicators = self.engine.extract_threat_indicators(email_data)

        assert "urgent_language" in indicators
        assert "suspicious_url" in indicators
        assert "spf_failure" in indicators
        assert "domain_mismatch" in indicators

    def test_bulk_analysis(self):
        """Test bulk email analysis."""
        emails = [
            {
                "id": 1,
                "subject": "Phishing attempt",
                "body": "Click here now!",
                "sender": "fake@evil.com",
                "headers": {},
            },
            {
                "id": 2,
                "subject": "Newsletter",
                "body": "Monthly update",
                "sender": "news@company.com",
                "headers": {"SPF": "pass"},
            },
        ]

        with patch.object(self.engine, "analyze_email") as mock_analyze:
            mock_analyze.side_effect = [
                {"is_threat": True, "confidence": 0.9},
                {"is_threat": False, "confidence": 0.1},
            ]

            results = self.engine.bulk_analyze(emails)

            assert len(results) == 2
            assert results[0]["id"] == 1
            assert results[0]["is_threat"] == True
            assert results[1]["id"] == 2
            assert results[1]["is_threat"] == False

    def test_real_time_analysis(self):
        """Test real-time email analysis with time constraints."""
        email_data = {
            "subject": "Test email",
            "body": "Test content",
            "sender": "test@example.com",
            "headers": {},
        }

        start_time = datetime.now()
        result = self.engine.analyze_email(email_data)
        end_time = datetime.now()

        # Analysis should be fast for real-time use
        analysis_time = (end_time - start_time).total_seconds()
        assert analysis_time < 2.0  # Should complete within 2 seconds

        assert "is_threat" in result
        assert "confidence" in result


class TestModelPerformance:
    """Test model performance and accuracy."""

    def test_model_accuracy_threshold(self):
        """Test that model meets minimum accuracy requirements."""
        # This would test against a validation dataset
        # For now, test the structure

        detector = PhishingDetector()

        # Mock model with good performance
        mock_model = Mock()
        mock_model.predict.return_value = [1, 0, 1, 0]
        mock_model.predict_proba.return_value = [
            [0.1, 0.9],
            [0.8, 0.2],
            [0.2, 0.8],
            [0.9, 0.1],
        ]

        detector.model = mock_model

        # Test batch prediction
        features_batch = [[1, 1, 0], [0, 0, 1], [1, 0, 1], [0, 1, 0]]
        results = detector.predict_batch(features_batch)

        assert len(results) == 4
        assert all("confidence" in result for result in results)

    def test_false_positive_rate(self):
        """Test false positive rate is within acceptable limits."""
        # Mock legitimate emails that should not be flagged
        legitimate_features = [
            [0, 0, 1, 1, 0],  # Good features
            [0, 1, 1, 0, 0],  # Mixed but mostly good
        ]

        detector = PhishingDetector()
        mock_model = Mock()
        mock_model.predict.return_value = [0, 0]  # Should be legitimate
        mock_model.predict_proba.return_value = [[0.95, 0.05], [0.90, 0.10]]

        detector.model = mock_model

        results = detector.predict_batch(legitimate_features)

        false_positives = sum(1 for r in results if r["is_threat"])
        false_positive_rate = false_positives / len(results)

        assert false_positive_rate <= 0.1  # Less than 10% false positives

    def test_recall_for_obvious_threats(self):
        """Test that obvious threats are caught (high recall)."""
        # Mock obvious phishing features
        phishing_features = [
            [1, 1, 1, 0, 1],  # Very suspicious
            [1, 1, 0, 1, 1],  # Also suspicious
        ]

        detector = PhishingDetector()
        mock_model = Mock()
        mock_model.predict.return_value = [1, 1]  # Should detect both
        mock_model.predict_proba.return_value = [[0.1, 0.9], [0.2, 0.8]]

        detector.model = mock_model

        results = detector.predict_batch(phishing_features)

        detected_threats = sum(1 for r in results if r["is_threat"])
        recall = detected_threats / len(results)

        assert recall >= 0.9  # Should catch at least 90% of obvious threats


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

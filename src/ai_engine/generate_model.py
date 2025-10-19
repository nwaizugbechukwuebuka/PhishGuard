#!/usr/bin/env python3
"""
PhishGuard AI Model Generator
Creates a trained phishing detection model for production use.
"""

import logging
import pickle

import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_sample_training_data():
    """
    Create sample training data for the phishing classifier.
    In production, this would be replaced with real phishing datasets.
    """

    # Sample legitimate emails
    legitimate_emails = [
        {
            "content": "Thank you for your purchase. Your order will be shipped within 2 business days.",
            "sender_domain": "amazon.com",
            "sender_reputation": 0.95,
            "has_attachments": False,
            "url_count": 1,
            "suspicious_urls": 0,
            "urgency_score": 0.1,
            "grammar_errors": 0,
            "label": 0,  # legitimate
        },
        {
            "content": "Your weekly newsletter with the latest updates from our team.",
            "sender_domain": "company.com",
            "sender_reputation": 0.90,
            "has_attachments": False,
            "url_count": 2,
            "suspicious_urls": 0,
            "urgency_score": 0.0,
            "grammar_errors": 0,
            "label": 0,
        },
        {
            "content": "Meeting scheduled for tomorrow at 2 PM in conference room A.",
            "sender_domain": "office365.com",
            "sender_reputation": 0.88,
            "has_attachments": False,
            "url_count": 0,
            "suspicious_urls": 0,
            "urgency_score": 0.2,
            "grammar_errors": 0,
            "label": 0,
        },
    ] * 100  # Duplicate for more training samples

    # Sample phishing emails
    phishing_emails = [
        {
            "content": "URGENT: Your account will be suspended! Click here immediately to verify.",
            "sender_domain": "fake-bank.com",
            "sender_reputation": 0.1,
            "has_attachments": True,
            "url_count": 3,
            "suspicious_urls": 2,
            "urgency_score": 0.9,
            "grammar_errors": 3,
            "label": 1,  # phishing
        },
        {
            "content": "You have won $1,000,000! Claim your prize now before it expires.",
            "sender_domain": "lottery-scam.net",
            "sender_reputation": 0.05,
            "has_attachments": False,
            "url_count": 1,
            "suspicious_urls": 1,
            "urgency_score": 0.8,
            "grammar_errors": 2,
            "label": 1,
        },
        {
            "content": "Your paypal accont has been compromized. Please login immediatly.",
            "sender_domain": "payp4l.com",
            "sender_reputation": 0.02,
            "has_attachments": False,
            "url_count": 1,
            "suspicious_urls": 1,
            "urgency_score": 0.95,
            "grammar_errors": 5,
            "label": 1,
        },
    ] * 80  # Fewer phishing samples to simulate real-world distribution

    return legitimate_emails + phishing_emails


def prepare_features_and_labels(data):
    """Extract features and labels from training data."""

    # Text content for TF-IDF
    text_content = [item["content"] for item in data]

    # Numerical features
    numerical_features = []
    for item in data:
        features = [
            item["sender_reputation"],
            int(item["has_attachments"]),
            item["url_count"],
            item["suspicious_urls"],
            item["urgency_score"],
            item["grammar_errors"],
        ]
        numerical_features.append(features)

    # Labels
    labels = [item["label"] for item in data]

    return text_content, np.array(numerical_features), np.array(labels)


def create_phishing_classifier():
    """Create and train the phishing detection classifier."""

    logger.info("Generating sample training data...")
    training_data = create_sample_training_data()

    logger.info(f"Preparing features from {len(training_data)} samples...")
    text_content, numerical_features, labels = prepare_features_and_labels(
        training_data
    )

    # Create TF-IDF vectorizer for text content
    tfidf_vectorizer = TfidfVectorizer(
        max_features=1000, stop_words="english", lowercase=True, ngram_range=(1, 2)
    )

    # Transform text content
    logger.info("Vectorizing text content...")
    text_features = tfidf_vectorizer.fit_transform(text_content).toarray()

    # Combine text and numerical features
    all_features = np.hstack([text_features, numerical_features])

    logger.info(f"Feature matrix shape: {all_features.shape}")

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        all_features, labels, test_size=0.2, random_state=42, stratify=labels
    )

    # Create and train Random Forest classifier
    logger.info("Training Random Forest classifier...")
    classifier = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        class_weight="balanced",
    )

    classifier.fit(X_train, y_train)

    # Evaluate model
    train_accuracy = classifier.score(X_train, y_train)
    test_accuracy = classifier.score(X_test, y_test)

    logger.info(f"Training accuracy: {train_accuracy:.3f}")
    logger.info(f"Test accuracy: {test_accuracy:.3f}")

    # Create complete model pipeline
    model_pipeline = {
        "vectorizer": tfidf_vectorizer,
        "classifier": classifier,
        "feature_names": [
            "sender_reputation",
            "has_attachments",
            "url_count",
            "suspicious_urls",
            "urgency_score",
            "grammar_errors",
        ],
        "model_version": "1.0.0",
        "training_samples": len(training_data),
        "accuracy": test_accuracy,
    }

    return model_pipeline


def save_model(model_pipeline, filepath):
    """Save the trained model to disk."""
    logger.info(f"Saving model to {filepath}...")

    try:
        with open(filepath, "wb") as f:
            pickle.dump(model_pipeline, f)

        logger.info("Model saved successfully!")
        return True

    except Exception as e:
        logger.error(f"Error saving model: {str(e)}")
        return False


def load_and_test_model(filepath):
    """Load and test the saved model."""
    logger.info(f"Loading model from {filepath}...")

    try:
        with open(filepath, "rb") as f:
            model_pipeline = pickle.load(f)

        # Test with sample email
        test_email = {
            "content": "URGENT: Your account has been compromised! Click here now!",
            "sender_reputation": 0.1,
            "has_attachments": True,
            "url_count": 2,
            "suspicious_urls": 1,
            "urgency_score": 0.9,
            "grammar_errors": 1,
        }

        # Prepare features
        text_features = (
            model_pipeline["vectorizer"].transform([test_email["content"]]).toarray()
        )
        numerical_features = np.array(
            [
                [
                    test_email["sender_reputation"],
                    int(test_email["has_attachments"]),
                    test_email["url_count"],
                    test_email["suspicious_urls"],
                    test_email["urgency_score"],
                    test_email["grammar_errors"],
                ]
            ]
        )

        # Combine features
        combined_features = np.hstack([text_features, numerical_features])

        # Make prediction
        prediction = model_pipeline["classifier"].predict(combined_features)[0]
        probability = model_pipeline["classifier"].predict_proba(combined_features)[0]

        logger.info(
            f"Test prediction: {'Phishing' if prediction == 1 else 'Legitimate'}"
        )
        logger.info(f"Confidence: {max(probability):.3f}")
        logger.info(f"Model version: {model_pipeline['model_version']}")

        return True

    except Exception as e:
        logger.error(f"Error loading/testing model: {str(e)}")
        return False


if __name__ == "__main__":
    # Create the model
    logger.info("Starting PhishGuard AI model generation...")

    model = create_phishing_classifier()

    # Save the model
    model_path = "phishing_classifier.pkl"
    if save_model(model, model_path):
        # Test the saved model
        load_and_test_model(model_path)
        logger.info("Model generation complete!")
    else:
        logger.error("Model generation failed!")

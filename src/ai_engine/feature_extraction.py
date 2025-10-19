"""
PhishGuard AI Engine - Feature Extraction

This module provides comprehensive feature extraction capabilities for email analysis,
including text features, metadata analysis, and behavioral indicators for phishing detection.
"""

import asyncio
import hashlib
import re
import urllib.parse
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

try:
    import tldextract
except ImportError:
    tldextract = None

try:
    import ipaddress
except ImportError:
    import socket

try:
    import nltk
    from nltk.corpus import stopwords
    from nltk.sentiment import SentimentIntensityAnalyzer
    from nltk.tokenize import word_tokenize
except ImportError:
    nltk = None

from ..utils.logger import logger


class EmailFeatureExtractor:
    """
    Comprehensive email feature extraction for phishing detection.

    Extracts various features including:
    - Text-based features (content analysis, sentiment)
    - URL-based features (suspicious domains, redirects)
    - Metadata features (headers, timing)
    - Behavioral features (urgency, social engineering)
    """

    def __init__(self):
        """Initialize the feature extractor with required resources."""
        self.suspicious_keywords = [
            "urgent",
            "immediate",
            "verify",
            "suspend",
            "click here",
            "act now",
            "limited time",
            "expire",
            "confirm",
            "update",
            "winner",
            "congratulations",
            "prize",
            "lottery",
            "free",
            "bonus",
            "offer",
            "discount",
            "deal",
            "security alert",
            "account locked",
            "login",
            "password",
            "credit card",
            "bank",
            "paypal",
            "amazon",
            "apple",
            "microsoft",
            "google",
        ]

        self.legitimate_domains = {
            "gmail.com",
            "yahoo.com",
            "outlook.com",
            "hotmail.com",
            "amazon.com",
            "paypal.com",
            "apple.com",
            "microsoft.com",
            "google.com",
            "facebook.com",
            "twitter.com",
            "linkedin.com",
        }

        self.suspicious_tlds = {
            ".tk",
            ".ml",
            ".ga",
            ".cf",
            ".top",
            ".click",
            ".download",
            ".work",
            ".link",
            ".trade",
            ".science",
            ".date",
        }

        # Initialize NLTK components if available
        if nltk:
            try:
                nltk.download("punkt", quiet=True)
                nltk.download("stopwords", quiet=True)
                nltk.download("vader_lexicon", quiet=True)
                self.sentiment_analyzer = SentimentIntensityAnalyzer()
                self.stop_words = set(stopwords.words("english"))
            except Exception as e:
                logger.warning(f"NLTK initialization failed: {e}")
                self.sentiment_analyzer = None
                self.stop_words = set()
        else:
            self.sentiment_analyzer = None
            self.stop_words = set()

    async def extract_all_features(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract all features from email data.

        Args:
            email_data: Dictionary containing email content, subject, sender, etc.

        Returns:
            Dict[str, Any]: Comprehensive feature set
        """
        try:
            features = {}

            # Extract different feature categories
            text_features = await self.extract_text_features(email_data)
            url_features = await self.extract_url_features(email_data)
            metadata_features = await self.extract_metadata_features(email_data)
            behavioral_features = await self.extract_behavioral_features(email_data)

            # Combine all features
            features.update(text_features)
            features.update(url_features)
            features.update(metadata_features)
            features.update(behavioral_features)

            return features

        except Exception as e:
            logger.error(f"Feature extraction failed: {str(e)}")
            return self._get_default_features()

    async def extract_text_features(
        self, email_data: Dict[str, Any]
    ) -> Dict[str, float]:
        """
        Extract text-based features from email content and subject.

        Args:
            email_data: Email data dictionary

        Returns:
            Dict[str, float]: Text-based features
        """
        content = email_data.get("content", "")
        subject = email_data.get("subject", "")
        combined_text = f"{subject} {content}".lower()

        features = {}

        # Basic text statistics
        features["text_length"] = len(content)
        features["subject_length"] = len(subject)
        features["word_count"] = len(combined_text.split())
        features["sentence_count"] = len(re.split(r"[.!?]+", content))
        features["avg_word_length"] = (
            np.mean([len(word) for word in combined_text.split()])
            if combined_text.split()
            else 0
        )

        # Character analysis
        features["uppercase_ratio"] = (
            sum(1 for c in content if c.isupper()) / len(content) if content else 0
        )
        features["digit_ratio"] = (
            sum(1 for c in content if c.isdigit()) / len(content) if content else 0
        )
        features["special_char_ratio"] = (
            sum(1 for c in content if not c.isalnum() and not c.isspace())
            / len(content)
            if content
            else 0
        )
        features["exclamation_count"] = content.count("!")
        features["question_count"] = content.count("?")

        # Suspicious keyword analysis
        features["suspicious_keyword_count"] = sum(
            1 for keyword in self.suspicious_keywords if keyword in combined_text
        )
        features["suspicious_keyword_ratio"] = (
            features["suspicious_keyword_count"] / len(combined_text.split())
            if combined_text.split()
            else 0
        )

        # Urgency indicators
        urgency_words = [
            "urgent",
            "immediate",
            "asap",
            "quickly",
            "hurry",
            "rush",
            "emergency",
        ]
        features["urgency_score"] = sum(
            1 for word in urgency_words if word in combined_text
        )

        # HTML analysis
        features["has_html"] = 1 if "<" in content and ">" in content else 0
        features["html_tag_count"] = len(re.findall(r"<[^>]+>", content))

        # Sentiment analysis (if NLTK available)
        if self.sentiment_analyzer:
            try:
                sentiment_scores = self.sentiment_analyzer.polarity_scores(
                    combined_text
                )
                features["sentiment_positive"] = sentiment_scores["pos"]
                features["sentiment_negative"] = sentiment_scores["neg"]
                features["sentiment_neutral"] = sentiment_scores["neu"]
                features["sentiment_compound"] = sentiment_scores["compound"]
            except Exception:
                features.update(
                    {
                        "sentiment_positive": 0,
                        "sentiment_negative": 0,
                        "sentiment_neutral": 1,
                        "sentiment_compound": 0,
                    }
                )
        else:
            features.update(
                {
                    "sentiment_positive": 0,
                    "sentiment_negative": 0,
                    "sentiment_neutral": 1,
                    "sentiment_compound": 0,
                }
            )

        return features

    async def extract_url_features(
        self, email_data: Dict[str, Any]
    ) -> Dict[str, float]:
        """
        Extract URL-based features for link analysis.

        Args:
            email_data: Email data dictionary

        Returns:
            Dict[str, float]: URL-based features
        """
        content = email_data.get("content", "")

        # Extract URLs
        url_pattern = r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
        urls = re.findall(url_pattern, content)

        features = {}
        features["url_count"] = len(urls)
        features["has_urls"] = 1 if urls else 0

        if not urls:
            return {**features, **self._get_default_url_features()}

        # Analyze each URL
        suspicious_domain_count = 0
        ip_address_count = 0
        suspicious_tld_count = 0
        shortened_url_count = 0
        redirect_count = 0

        for url in urls:
            try:
                parsed_url = urllib.parse.urlparse(url)
                domain = parsed_url.netloc.lower()

                # Check for IP address
                try:
                    ipaddress.ip_address(domain)
                    ip_address_count += 1
                except ValueError:
                    pass

                # Extract domain components
                extracted = tldextract.extract(url)
                full_domain = f"{extracted.domain}.{extracted.suffix}"

                # Check against legitimate domains
                if full_domain not in self.legitimate_domains:
                    suspicious_domain_count += 1

                # Check for suspicious TLDs
                if f".{extracted.suffix}" in self.suspicious_tlds:
                    suspicious_tld_count += 1

                # Check for URL shorteners
                shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly"]
                if any(shortener in domain for shortener in shorteners):
                    shortened_url_count += 1

                # Check URL length (long URLs can be suspicious)
                if len(url) > 100:
                    redirect_count += 1

            except Exception as e:
                logger.warning(f"URL analysis failed for {url}: {e}")
                suspicious_domain_count += 1

        # Calculate ratios
        features["suspicious_domain_ratio"] = suspicious_domain_count / len(urls)
        features["ip_address_ratio"] = ip_address_count / len(urls)
        features["suspicious_tld_ratio"] = suspicious_tld_count / len(urls)
        features["shortened_url_ratio"] = shortened_url_count / len(urls)
        features["long_url_ratio"] = redirect_count / len(urls)

        return features

    async def extract_metadata_features(
        self, email_data: Dict[str, Any]
    ) -> Dict[str, float]:
        """
        Extract metadata-based features from email headers and sender info.

        Args:
            email_data: Email data dictionary

        Returns:
            Dict[str, float]: Metadata-based features
        """
        sender = email_data.get("sender", "").lower()

        features = {}

        # Sender analysis
        features["sender_length"] = len(sender)
        features["sender_has_numbers"] = 1 if any(c.isdigit() for c in sender) else 0
        features["sender_special_chars"] = sum(
            1 for c in sender if not c.isalnum() and c not in "@.-_"
        )

        # Domain analysis
        if "@" in sender:
            domain = sender.split("@")[1]
            features["sender_domain_length"] = len(domain)
            features["sender_legitimate_domain"] = (
                1 if domain in self.legitimate_domains else 0
            )

            # Check for suspicious patterns in domain
            features["domain_has_numbers"] = (
                1 if any(c.isdigit() for c in domain) else 0
            )
            features["domain_dash_count"] = domain.count("-")
            features["domain_subdomain_count"] = domain.count(".") - 1
        else:
            features.update(
                {
                    "sender_domain_length": 0,
                    "sender_legitimate_domain": 0,
                    "domain_has_numbers": 0,
                    "domain_dash_count": 0,
                    "domain_subdomain_count": 0,
                }
            )

        # Time-based features (if timestamp available)
        timestamp = email_data.get("timestamp")
        if timestamp:
            try:
                dt = (
                    datetime.fromisoformat(timestamp)
                    if isinstance(timestamp, str)
                    else timestamp
                )
                features["hour_of_day"] = dt.hour
                features["day_of_week"] = dt.weekday()
                features["is_weekend"] = 1 if dt.weekday() >= 5 else 0
                features["is_business_hours"] = 1 if 9 <= dt.hour <= 17 else 0
            except Exception:
                features.update(
                    {
                        "hour_of_day": 12,
                        "day_of_week": 0,
                        "is_weekend": 0,
                        "is_business_hours": 1,
                    }
                )
        else:
            features.update(
                {
                    "hour_of_day": 12,
                    "day_of_week": 0,
                    "is_weekend": 0,
                    "is_business_hours": 1,
                }
            )

        return features

    async def extract_behavioral_features(
        self, email_data: Dict[str, Any]
    ) -> Dict[str, float]:
        """
        Extract behavioral and social engineering indicators.

        Args:
            email_data: Email data dictionary

        Returns:
            Dict[str, float]: Behavioral features
        """
        content = email_data.get("content", "").lower()
        subject = email_data.get("subject", "").lower()
        combined_text = f"{subject} {content}"

        features = {}

        # Social engineering indicators
        authority_words = [
            "bank",
            "security",
            "admin",
            "support",
            "official",
            "government",
        ]
        features["authority_appeal"] = sum(
            1 for word in authority_words if word in combined_text
        )

        urgency_phrases = [
            "act now",
            "limited time",
            "expires soon",
            "immediate action",
        ]
        features["urgency_phrases"] = sum(
            1 for phrase in urgency_phrases if phrase in combined_text
        )

        fear_words = ["suspend", "terminate", "block", "freeze", "locked", "disabled"]
        features["fear_appeal"] = sum(1 for word in fear_words if word in combined_text)

        reward_words = ["win", "prize", "lottery", "bonus", "reward", "gift", "free"]
        features["reward_appeal"] = sum(
            1 for word in reward_words if word in combined_text
        )

        # Action requests
        action_words = ["click", "download", "install", "verify", "confirm", "update"]
        features["action_requests"] = sum(
            1 for word in action_words if word in combined_text
        )

        # Personal information requests
        personal_info = [
            "password",
            "ssn",
            "social security",
            "credit card",
            "account number",
        ]
        features["personal_info_requests"] = sum(
            1 for info in personal_info if info in combined_text
        )

        # Spelling and grammar errors (simple heuristic)
        features["potential_typos"] = len(
            re.findall(r"\b\w*[0-9]+\w*\b", combined_text)
        )
        features["repeated_punctuation"] = len(re.findall(r"[!?]{2,}", content))

        # Money-related indicators
        money_patterns = [r"\$\d+", r"dollar", r"money", r"payment", r"transfer"]
        features["money_mentions"] = sum(
            len(re.findall(pattern, combined_text)) for pattern in money_patterns
        )

        return features

    def _get_default_features(self) -> Dict[str, float]:
        """Get default feature values for error cases."""
        return {
            # Text features
            "text_length": 0,
            "subject_length": 0,
            "word_count": 0,
            "sentence_count": 0,
            "avg_word_length": 0,
            "uppercase_ratio": 0,
            "digit_ratio": 0,
            "special_char_ratio": 0,
            "exclamation_count": 0,
            "question_count": 0,
            "suspicious_keyword_count": 0,
            "suspicious_keyword_ratio": 0,
            "urgency_score": 0,
            "has_html": 0,
            "html_tag_count": 0,
            # Sentiment
            "sentiment_positive": 0,
            "sentiment_negative": 0,
            "sentiment_neutral": 1,
            "sentiment_compound": 0,
            # URL features
            "url_count": 0,
            "has_urls": 0,
            **self._get_default_url_features(),
            # Metadata features
            "sender_length": 0,
            "sender_has_numbers": 0,
            "sender_special_chars": 0,
            "sender_domain_length": 0,
            "sender_legitimate_domain": 0,
            "domain_has_numbers": 0,
            "domain_dash_count": 0,
            "domain_subdomain_count": 0,
            "hour_of_day": 12,
            "day_of_week": 0,
            "is_weekend": 0,
            "is_business_hours": 1,
            # Behavioral features
            "authority_appeal": 0,
            "urgency_phrases": 0,
            "fear_appeal": 0,
            "reward_appeal": 0,
            "action_requests": 0,
            "personal_info_requests": 0,
            "potential_typos": 0,
            "repeated_punctuation": 0,
            "money_mentions": 0,
        }

    def _get_default_url_features(self) -> Dict[str, float]:
        """Get default URL feature values."""
        return {
            "suspicious_domain_ratio": 0,
            "ip_address_ratio": 0,
            "suspicious_tld_ratio": 0,
            "shortened_url_ratio": 0,
            "long_url_ratio": 0,
        }


# Utility function for feature extraction
async def extract_email_features(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convenience function for extracting features from email data.

    Args:
        email_data: Email data dictionary

    Returns:
        Dict[str, Any]: Extracted features
    """
    extractor = EmailFeatureExtractor()
    return await extractor.extract_all_features(email_data)


# Feature importance analysis
class FeatureAnalyzer:
    """Analyze and rank feature importance for model interpretation."""

    @staticmethod
    def get_feature_importance(
        model, feature_names: List[str]
    ) -> List[Tuple[str, float]]:
        """
        Get feature importance from trained model.

        Args:
            model: Trained scikit-learn model
            feature_names: List of feature names

        Returns:
            List[Tuple[str, float]]: Feature importance tuples
        """
        try:
            if hasattr(model, "feature_importances_"):
                importances = model.feature_importances_
            elif hasattr(model, "coef_"):
                importances = abs(model.coef_[0])
            else:
                return []

            feature_importance = list(zip(feature_names, importances))
            feature_importance.sort(key=lambda x: x[1], reverse=True)

            return feature_importance

        except Exception as e:
            logger.error(f"Feature importance analysis failed: {e}")
            return []

"""
AI Explainability Utilities for PhishGuard

Provides interpretability and explanation capabilities for ML model decisions,
helping users understand why emails were classified as threats or safe.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple
import json
from datetime import datetime
import uuid
from sklearn.inspection import permutation_importance
import shap
import lime
from lime.lime_text import LimeTextExplainer

from ..utils.logger import get_logger
from ..utils.config import get_settings

logger = get_logger(__name__)
settings = get_settings()

class ModelExplainer:
    """Provides explanations for ML model predictions."""
    
    def __init__(self):
        """Initialize the explainer."""
        self.lime_explainer = None
        self.shap_explainer = None
        self._initialize_explainers()
    
    def _initialize_explainers(self):
        """Initialize LIME and SHAP explainers."""
        try:
            # Initialize LIME text explainer
            self.lime_explainer = LimeTextExplainer(
                mode='classification',
                class_names=['Safe', 'Phishing'],
                feature_selection='auto',
                verbose=False
            )
            
            logger.info("AI explainers initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing AI explainers: {str(e)}")
    
    def explain_email_classification(
        self,
        email_content: str,
        subject: str,
        sender: str,
        model,
        vectorizer,
        prediction_score: float,
        feature_names: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Generate comprehensive explanation for email classification.
        
        Args:
            email_content: Email body text
            subject: Email subject line
            sender: Email sender
            model: Trained ML model
            vectorizer: Text vectorizer
            prediction_score: Model confidence score
            feature_names: Names of features used
            
        Returns:
            Comprehensive explanation data
        """
        try:
            # Combine email text for analysis
            full_text = f"Subject: {subject}\nFrom: {sender}\n\n{email_content}"
            
            # Generate LIME explanation
            lime_explanation = self._generate_lime_explanation(
                full_text, model, vectorizer, prediction_score
            )
            
            # Extract feature importance
            feature_importance = self._extract_feature_importance(
                full_text, model, vectorizer, feature_names
            )
            
            # Analyze suspicious patterns
            suspicious_patterns = self._analyze_suspicious_patterns(
                email_content, subject, sender
            )
            
            # Generate natural language explanation
            natural_explanation = self._generate_natural_explanation(
                prediction_score, lime_explanation, suspicious_patterns
            )
            
            explanation = {
                "prediction_info": {
                    "confidence_score": prediction_score,
                    "classification": "Phishing" if prediction_score > 0.5 else "Safe",
                    "risk_level": self._get_risk_level(prediction_score),
                    "timestamp": datetime.utcnow().isoformat()
                },
                "lime_explanation": lime_explanation,
                "feature_importance": feature_importance,
                "suspicious_patterns": suspicious_patterns,
                "natural_explanation": natural_explanation,
                "technical_details": {
                    "model_type": type(model).__name__,
                    "vectorizer_type": type(vectorizer).__name__,
                    "features_analyzed": len(feature_names) if feature_names else 0
                },
                "recommendations": self._generate_recommendations(
                    prediction_score, suspicious_patterns
                )
            }
            
            return explanation
            
        except Exception as e:
            logger.error(f"Error generating email explanation: {str(e)}")
            return self._get_default_explanation(prediction_score)
    
    def _generate_lime_explanation(
        self,
        text: str,
        model,
        vectorizer,
        prediction_score: float
    ) -> Dict[str, Any]:
        """Generate LIME explanation for text classification."""
        try:
            if not self.lime_explainer:
                return {"error": "LIME explainer not initialized"}
            
            # Create prediction function for LIME
            def predict_proba_fn(texts):
                try:
                    vectors = vectorizer.transform(texts)
                    predictions = model.predict_proba(vectors)
                    return predictions
                except Exception as e:
                    logger.error(f"Error in LIME prediction function: {str(e)}")
                    # Return default probabilities
                    return np.array([[0.5, 0.5]] * len(texts))
            
            # Generate LIME explanation
            explanation = self.lime_explainer.explain_instance(
                text,
                predict_proba_fn,
                num_features=10,
                top_labels=1
            )
            
            # Extract explanation data
            lime_data = {
                "top_features": [],
                "prediction_probability": prediction_score,
                "local_prediction": explanation.local_pred[0] if explanation.local_pred else prediction_score
            }
            
            # Get feature contributions
            for feature, weight in explanation.as_list():
                lime_data["top_features"].append({
                    "feature": feature,
                    "weight": float(weight),
                    "contribution": "positive" if weight > 0 else "negative",
                    "importance": abs(float(weight))
                })
            
            # Sort by importance
            lime_data["top_features"] = sorted(
                lime_data["top_features"],
                key=lambda x: x["importance"],
                reverse=True
            )
            
            return lime_data
            
        except Exception as e:
            logger.error(f"Error generating LIME explanation: {str(e)}")
            return {
                "error": str(e),
                "top_features": [],
                "prediction_probability": prediction_score
            }
    
    def _extract_feature_importance(
        self,
        text: str,
        model,
        vectorizer,
        feature_names: Optional[List[str]]
    ) -> Dict[str, Any]:
        """Extract global feature importance from the model."""
        try:
            importance_data = {
                "global_importance": [],
                "text_specific_importance": []
            }
            
            # Get global feature importance if available
            if hasattr(model, 'feature_importances_'):
                importances = model.feature_importances_
                if feature_names and len(feature_names) == len(importances):
                    for name, importance in zip(feature_names, importances):
                        importance_data["global_importance"].append({
                            "feature": name,
                            "importance": float(importance)
                        })
                    
                    # Sort by importance
                    importance_data["global_importance"] = sorted(
                        importance_data["global_importance"],
                        key=lambda x: x["importance"],
                        reverse=True
                    )[:20]  # Top 20 features
            
            # Analyze text-specific features
            vector = vectorizer.transform([text])
            feature_indices = vector.nonzero()[1]
            feature_scores = vector.data
            
            if hasattr(vectorizer, 'get_feature_names_out'):
                vocab = vectorizer.get_feature_names_out()
                for idx, score in zip(feature_indices, feature_scores):
                    if idx < len(vocab):
                        importance_data["text_specific_importance"].append({
                            "feature": vocab[idx],
                            "score": float(score),
                            "frequency": int(score) if score.is_integer() else float(score)
                        })
            
            return importance_data
            
        except Exception as e:
            logger.error(f"Error extracting feature importance: {str(e)}")
            return {"global_importance": [], "text_specific_importance": []}
    
    def _analyze_suspicious_patterns(
        self,
        email_content: str,
        subject: str,
        sender: str
    ) -> Dict[str, Any]:
        """Analyze email for suspicious patterns and indicators."""
        try:
            patterns = {
                "urgency_indicators": [],
                "suspicious_domains": [],
                "phishing_keywords": [],
                "social_engineering": [],
                "technical_indicators": [],
                "overall_suspicion_score": 0.0
            }
            
            # Convert to lowercase for analysis
            content_lower = email_content.lower()
            subject_lower = subject.lower()
            
            # Urgency indicators
            urgency_words = [
                'urgent', 'immediate', 'asap', 'expire', 'deadline', 'limited time',
                'act now', 'hurry', 'final notice', 'last chance', 'emergency'
            ]
            
            for word in urgency_words:
                if word in content_lower or word in subject_lower:
                    patterns["urgency_indicators"].append({
                        "indicator": word,
                        "location": "subject" if word in subject_lower else "content",
                        "suspicion_level": "medium"
                    })
            
            # Phishing keywords
            phishing_keywords = [
                'verify', 'confirm', 'suspend', 'update', 'click here', 'login',
                'password', 'account', 'security', 'bank', 'paypal', 'amazon',
                'refund', 'prize', 'winner', 'congratulations', 'free'
            ]
            
            for keyword in phishing_keywords:
                if keyword in content_lower:
                    patterns["phishing_keywords"].append({
                        "keyword": keyword,
                        "context": self._extract_context(content_lower, keyword),
                        "suspicion_level": "high" if keyword in ['password', 'login', 'verify'] else "medium"
                    })
            
            # Social engineering indicators
            social_engineering = [
                'personal information', 'confidential', 'don\'t tell anyone',
                'trust me', 'help me', 'you have been selected', 'exclusive offer'
            ]
            
            for indicator in social_engineering:
                if indicator in content_lower:
                    patterns["social_engineering"].append({
                        "indicator": indicator,
                        "technique": self._classify_social_engineering(indicator),
                        "suspicion_level": "high"
                    })
            
            # Technical indicators
            if '@' in email_content and 'http' in email_content:
                patterns["technical_indicators"].append({
                    "type": "embedded_links_and_emails",
                    "description": "Contains both email addresses and URLs",
                    "suspicion_level": "medium"
                })
            
            # Check sender domain
            if sender and '@' in sender:
                domain = sender.split('@')[1].lower()
                suspicious_domains = [
                    'gmail.com', 'yahoo.com', 'hotmail.com'  # Common free domains used in phishing
                ]
                
                if any(susp_domain in domain for susp_domain in suspicious_domains):
                    patterns["suspicious_domains"].append({
                        "domain": domain,
                        "reason": "Free email service often used in phishing",
                        "suspicion_level": "low"
                    })
            
            # Calculate overall suspicion score
            suspicion_score = 0.0
            suspicion_score += len(patterns["urgency_indicators"]) * 0.1
            suspicion_score += len(patterns["phishing_keywords"]) * 0.15
            suspicion_score += len(patterns["social_engineering"]) * 0.2
            suspicion_score += len(patterns["technical_indicators"]) * 0.1
            suspicion_score += len(patterns["suspicious_domains"]) * 0.05
            
            patterns["overall_suspicion_score"] = min(suspicion_score, 1.0)
            
            return patterns
            
        except Exception as e:
            logger.error(f"Error analyzing suspicious patterns: {str(e)}")
            return {
                "urgency_indicators": [],
                "suspicious_domains": [],
                "phishing_keywords": [],
                "social_engineering": [],
                "technical_indicators": [],
                "overall_suspicion_score": 0.0
            }
    
    def _extract_context(self, text: str, keyword: str, context_length: int = 50) -> str:
        """Extract context around a keyword in text."""
        try:
            index = text.find(keyword)
            if index == -1:
                return ""
            
            start = max(0, index - context_length)
            end = min(len(text), index + len(keyword) + context_length)
            
            return text[start:end].strip()
            
        except Exception:
            return ""
    
    def _classify_social_engineering(self, indicator: str) -> str:
        """Classify the type of social engineering technique."""
        if any(word in indicator for word in ['trust', 'help', 'personal']):
            return "trust_building"
        elif any(word in indicator for word in ['selected', 'winner', 'exclusive']):
            return "false_exclusivity"
        elif any(word in indicator for word in ['confidential', 'don\'t tell']):
            return "secrecy_manipulation"
        else:
            return "generic_manipulation"
    
    def _generate_natural_explanation(
        self,
        prediction_score: float,
        lime_explanation: Dict[str, Any],
        suspicious_patterns: Dict[str, Any]
    ) -> str:
        """Generate human-readable explanation of the classification."""
        try:
            if prediction_score > 0.8:
                confidence_phrase = "very confident"
                risk_level = "high"
            elif prediction_score > 0.6:
                confidence_phrase = "confident"
                risk_level = "medium-high"
            elif prediction_score > 0.4:
                confidence_phrase = "somewhat uncertain"
                risk_level = "medium"
            else:
                confidence_phrase = "confident"
                risk_level = "low"
            
            classification = "phishing" if prediction_score > 0.5 else "legitimate"
            
            explanation = f"The AI model is {confidence_phrase} (score: {prediction_score:.2f}) that this email is {classification} with a {risk_level} risk level."
            
            # Add key factors
            key_factors = []
            
            if lime_explanation.get("top_features"):
                top_feature = lime_explanation["top_features"][0]
                if top_feature["weight"] > 0:
                    key_factors.append(f"presence of '{top_feature['feature']}'")
            
            if suspicious_patterns["urgency_indicators"]:
                key_factors.append("urgency language")
            
            if suspicious_patterns["phishing_keywords"]:
                key_factors.append("phishing-related keywords")
            
            if suspicious_patterns["social_engineering"]:
                key_factors.append("social engineering techniques")
            
            if key_factors:
                explanation += f" Key factors include: {', '.join(key_factors)}."
            
            # Add recommendations
            if prediction_score > 0.5:
                explanation += " Exercise caution with this email and avoid clicking links or downloading attachments."
            else:
                explanation += " This email appears to be legitimate, but always remain vigilant."
            
            return explanation
            
        except Exception as e:
            logger.error(f"Error generating natural explanation: {str(e)}")
            return f"The email was classified with a confidence score of {prediction_score:.2f}."
    
    def _get_risk_level(self, prediction_score: float) -> str:
        """Determine risk level based on prediction score."""
        if prediction_score > 0.8:
            return "high"
        elif prediction_score > 0.6:
            return "medium-high"
        elif prediction_score > 0.4:
            return "medium"
        elif prediction_score > 0.2:
            return "low-medium"
        else:
            return "low"
    
    def _generate_recommendations(
        self,
        prediction_score: float,
        suspicious_patterns: Dict[str, Any]
    ) -> List[str]:
        """Generate actionable recommendations based on the analysis."""
        recommendations = []
        
        if prediction_score > 0.7:
            recommendations.extend([
                "Do not click any links in this email",
                "Do not download any attachments",
                "Report this email as suspicious",
                "Delete the email after reporting"
            ])
        elif prediction_score > 0.5:
            recommendations.extend([
                "Exercise caution with this email",
                "Verify sender identity through alternative means",
                "Avoid providing personal information"
            ])
        else:
            recommendations.extend([
                "Email appears legitimate but remain vigilant",
                "Verify any unusual requests independently"
            ])
        
        # Pattern-specific recommendations
        if suspicious_patterns["urgency_indicators"]:
            recommendations.append("Be wary of urgency tactics - legitimate organizations rarely require immediate action")
        
        if suspicious_patterns["phishing_keywords"]:
            recommendations.append("Be cautious of requests for verification or account updates")
        
        if suspicious_patterns["social_engineering"]:
            recommendations.append("Be skeptical of emotional manipulation or pressure tactics")
        
        return recommendations
    
    def _get_default_explanation(self, prediction_score: float) -> Dict[str, Any]:
        """Return default explanation when detailed analysis fails."""
        return {
            "prediction_info": {
                "confidence_score": prediction_score,
                "classification": "Phishing" if prediction_score > 0.5 else "Safe",
                "risk_level": self._get_risk_level(prediction_score),
                "timestamp": datetime.utcnow().isoformat()
            },
            "lime_explanation": {"error": "Analysis unavailable"},
            "feature_importance": {"error": "Analysis unavailable"},
            "suspicious_patterns": {
                "urgency_indicators": [],
                "suspicious_domains": [],
                "phishing_keywords": [],
                "social_engineering": [],
                "technical_indicators": [],
                "overall_suspicion_score": 0.0
            },
            "natural_explanation": f"The email received a confidence score of {prediction_score:.2f}. Detailed analysis was not available.",
            "recommendations": self._generate_recommendations(prediction_score, {
                "urgency_indicators": [],
                "suspicious_domains": [],
                "phishing_keywords": [],
                "social_engineering": [],
                "technical_indicators": []
            })
        }

class ExplanationLogger:
    """Logs and manages explanation data for audit and improvement."""
    
    def __init__(self):
        """Initialize the explanation logger."""
        pass
    
    def log_explanation(
        self,
        email_id: str,
        explanation: Dict[str, Any],
        user_feedback: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Log explanation data for audit and model improvement.
        
        Args:
            email_id: Unique email identifier
            explanation: Generated explanation data
            user_feedback: Optional user feedback on explanation quality
            
        Returns:
            Log entry ID
        """
        try:
            log_id = str(uuid.uuid4())
            
            log_entry = {
                "log_id": log_id,
                "email_id": email_id,
                "timestamp": datetime.utcnow().isoformat(),
                "explanation": explanation,
                "user_feedback": user_feedback
            }
            
            # In a production system, this would be stored in a database
            logger.info(f"Explanation logged: {log_id} for email {email_id}")
            
            return log_id
            
        except Exception as e:
            logger.error(f"Error logging explanation: {str(e)}")
            return ""
    
    def get_explanation_analytics(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Get analytics on explanation quality and user feedback.
        
        Args:
            start_date: Start date for analytics
            end_date: End date for analytics
            
        Returns:
            Explanation analytics data
        """
        try:
            # In a production system, this would query actual data
            analytics = {
                "total_explanations": 1250,
                "user_satisfaction_score": 4.2,
                "most_helpful_features": [
                    "natural_explanation",
                    "suspicious_patterns",
                    "recommendations"
                ],
                "improvement_suggestions": [
                    "Include more context for technical terms",
                    "Provide confidence intervals",
                    "Add visual indicators for risk levels"
                ]
            }
            
            return analytics
            
        except Exception as e:
            logger.error(f"Error getting explanation analytics: {str(e)}")
            return {}

def create_model_explainer() -> ModelExplainer:
    """Factory function to create a model explainer instance."""
    return ModelExplainer()

def explain_prediction(
    email_content: str,
    subject: str,
    sender: str,
    model,
    vectorizer,
    prediction_score: float,
    feature_names: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Convenience function to explain a single prediction.
    
    Args:
        email_content: Email body text
        subject: Email subject line
        sender: Email sender
        model: Trained ML model
        vectorizer: Text vectorizer
        prediction_score: Model confidence score
        feature_names: Names of features used
        
    Returns:
        Explanation data
    """
    explainer = create_model_explainer()
    return explainer.explain_email_classification(
        email_content, subject, sender, model, vectorizer, 
        prediction_score, feature_names
    )

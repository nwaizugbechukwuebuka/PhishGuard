"""
Detection Engine Service for PhishGuard

Business logic for AI-powered email threat detection, analysis,
and classification using machine learning models.
"""

from sqlalchemy.orm import Session
from sqlalchemy import desc, and_, or_, func
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
import uuid
import re
import hashlib
import pickle
import numpy as np
from pathlib import Path

from ..models.quarantine import QuarantinedEmail, QuarantineReason, ThreatLevel
from ..models.audit_log import AuditLog, ActionType
from ..utils.logger import get_logger
from ..utils.config import get_settings
from ..utils.event_bus import EventBus
from ...ai_engine.feature_extraction import FeatureExtractor
from ...ai_engine.inference import ModelInference

logger = get_logger(__name__)
settings = get_settings()

class DetectionEngine:
    """Advanced AI-powered email threat detection engine."""
    
    def __init__(self, db: Session):
        """
        Initialize detection engine.
        
        Args:
            db: Database session
        """
        self.db = db
        self.event_bus = EventBus()
        self.feature_extractor = FeatureExtractor()
        self.model_inference = ModelInference()
        
        # Load threat intelligence data
        self._load_threat_intelligence()
        
        # Initialize detection rules
        self._initialize_detection_rules()
    
    async def analyze_email(
        self,
        sender_email: str,
        recipient_email: str,
        subject: str,
        content: str,
        headers: Dict[str, str],
        attachments: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Comprehensive email threat analysis.
        
        Args:
            sender_email: Email sender
            recipient_email: Email recipient
            subject: Email subject
            content: Email content
            headers: Email headers
            attachments: Email attachments
            
        Returns:
            Analysis results with threat assessment
        """
        try:
            analysis_start = datetime.utcnow()
            
            # Extract features for ML analysis
            features = await self._extract_email_features(
                sender_email, recipient_email, subject, content, headers, attachments
            )
            
            # Run AI model inference
            ml_prediction = await self._run_ml_prediction(features)
            
            # Apply rule-based detection
            rule_based_results = await self._apply_detection_rules(
                sender_email, recipient_email, subject, content, headers, attachments
            )
            
            # Analyze URLs in content
            url_analysis = await self._analyze_urls(content)
            
            # Analyze attachments
            attachment_analysis = await self._analyze_attachments(attachments or [])
            
            # Check against threat intelligence
            threat_intel_results = await self._check_threat_intelligence(
                sender_email, subject, content
            )
            
            # Combine all analysis results
            final_assessment = await self._combine_analysis_results(
                ml_prediction=ml_prediction,
                rule_based_results=rule_based_results,
                url_analysis=url_analysis,
                attachment_analysis=attachment_analysis,
                threat_intel_results=threat_intel_results,
                features=features
            )
            
            analysis_duration = (datetime.utcnow() - analysis_start).total_seconds()
            
            # Log analysis
            await self._log_detection_action(
                action=ActionType.CREATE,
                resource_id=None,
                details={
                    "sender": sender_email,
                    "recipient": recipient_email,
                    "threat_level": final_assessment["threat_level"],
                    "confidence": final_assessment["confidence_score"],
                    "analysis_duration": analysis_duration,
                    "detection_methods": final_assessment["detection_methods"]
                }
            )
            
            # Emit detection event
            await self.event_bus.emit("email_analyzed", {
                "sender": sender_email,
                "recipient": recipient_email,
                "threat_level": final_assessment["threat_level"],
                "should_quarantine": final_assessment["should_quarantine"],
                "confidence": final_assessment["confidence_score"]
            })
            
            return final_assessment
            
        except Exception as e:
            logger.error(f"Error analyzing email: {str(e)}")
            # Return safe default assessment
            return {
                "threat_level": "MEDIUM",
                "confidence_score": 0.5,
                "should_quarantine": True,
                "quarantine_reason": "ANALYSIS_ERROR",
                "threat_indicators": ["Analysis failed - defaulting to safe quarantine"],
                "detection_methods": ["error_handling"],
                "analysis_details": {
                    "error": str(e),
                    "timestamp": datetime.utcnow().isoformat()
                }
            }
    
    async def _extract_email_features(
        self,
        sender_email: str,
        recipient_email: str,
        subject: str,
        content: str,
        headers: Dict[str, str],
        attachments: Optional[List[Dict[str, Any]]]
    ) -> Dict[str, Any]:
        """Extract features for ML model."""
        try:
            return self.feature_extractor.extract_features(
                sender_email=sender_email,
                recipient_email=recipient_email,
                subject=subject,
                content=content,
                headers=headers,
                attachments=attachments or []
            )
        except Exception as e:
            logger.error(f"Error extracting features: {str(e)}")
            return {}
    
    async def _run_ml_prediction(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Run machine learning model prediction."""
        try:
            prediction = self.model_inference.predict(features)
            return {
                "is_phishing": prediction.get("is_phishing", False),
                "confidence": prediction.get("confidence", 0.5),
                "threat_type": prediction.get("threat_type", "unknown"),
                "feature_importance": prediction.get("feature_importance", {}),
                "model_version": prediction.get("model_version", "1.0")
            }
        except Exception as e:
            logger.error(f"Error running ML prediction: {str(e)}")
            return {
                "is_phishing": False,
                "confidence": 0.5,
                "threat_type": "unknown",
                "feature_importance": {},
                "model_version": "error"
            }
    
    async def _apply_detection_rules(
        self,
        sender_email: str,
        recipient_email: str,
        subject: str,
        content: str,
        headers: Dict[str, str],
        attachments: Optional[List[Dict[str, Any]]]
    ) -> Dict[str, Any]:
        """Apply rule-based detection logic."""
        try:
            detected_threats = []
            threat_indicators = []
            confidence_score = 0.0
            
            # Check sender reputation
            sender_check = await self._check_sender_reputation(sender_email, headers)
            if sender_check["is_suspicious"]:
                detected_threats.append("suspicious_sender")
                threat_indicators.extend(sender_check["indicators"])
                confidence_score += sender_check["confidence_impact"]
            
            # Check subject line patterns
            subject_check = await self._check_subject_patterns(subject)
            if subject_check["is_suspicious"]:
                detected_threats.append("suspicious_subject")
                threat_indicators.extend(subject_check["indicators"])
                confidence_score += subject_check["confidence_impact"]
            
            # Check content patterns
            content_check = await self._check_content_patterns(content)
            if content_check["is_suspicious"]:
                detected_threats.append("suspicious_content")
                threat_indicators.extend(content_check["indicators"])
                confidence_score += content_check["confidence_impact"]
            
            # Check for urgency indicators
            urgency_check = await self._check_urgency_indicators(subject, content)
            if urgency_check["is_urgent"]:
                detected_threats.append("urgency_tactics")
                threat_indicators.extend(urgency_check["indicators"])
                confidence_score += urgency_check["confidence_impact"]
            
            # Check for social engineering
            social_eng_check = await self._check_social_engineering(content)
            if social_eng_check["is_social_engineering"]:
                detected_threats.append("social_engineering")
                threat_indicators.extend(social_eng_check["indicators"])
                confidence_score += social_eng_check["confidence_impact"]
            
            # Check email authentication
            auth_check = await self._check_email_authentication(headers)
            if auth_check["auth_failed"]:
                detected_threats.append("authentication_failure")
                threat_indicators.extend(auth_check["indicators"])
                confidence_score += auth_check["confidence_impact"]
            
            return {
                "detected_threats": detected_threats,
                "threat_indicators": threat_indicators,
                "confidence_score": min(confidence_score, 1.0),
                "rule_results": {
                    "sender_check": sender_check,
                    "subject_check": subject_check,
                    "content_check": content_check,
                    "urgency_check": urgency_check,
                    "social_eng_check": social_eng_check,
                    "auth_check": auth_check
                }
            }
            
        except Exception as e:
            logger.error(f"Error in rule-based detection: {str(e)}")
            return {
                "detected_threats": [],
                "threat_indicators": [],
                "confidence_score": 0.0,
                "rule_results": {}
            }
    
    async def _analyze_urls(self, content: str) -> Dict[str, Any]:
        """Analyze URLs found in email content."""
        try:
            # Extract URLs using regex
            url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
            urls = re.findall(url_pattern, content)
            
            suspicious_urls = []
            url_indicators = []
            
            for url in urls:
                url_analysis = await self._analyze_single_url(url)
                if url_analysis["is_suspicious"]:
                    suspicious_urls.append(url)
                    url_indicators.extend(url_analysis["indicators"])
            
            return {
                "total_urls": len(urls),
                "suspicious_urls": suspicious_urls,
                "suspicious_count": len(suspicious_urls),
                "url_indicators": url_indicators,
                "is_suspicious": len(suspicious_urls) > 0,
                "confidence_impact": min(len(suspicious_urls) * 0.2, 0.8)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing URLs: {str(e)}")
            return {
                "total_urls": 0,
                "suspicious_urls": [],
                "suspicious_count": 0,
                "url_indicators": [],
                "is_suspicious": False,
                "confidence_impact": 0.0
            }
    
    async def _analyze_single_url(self, url: str) -> Dict[str, Any]:
        """Analyze a single URL for threats."""
        try:
            indicators = []
            is_suspicious = False
            
            # Check for URL shorteners
            shortener_domains = [
                'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
                'short.link', 'tiny.cc', 'rb.gy', 'cutt.ly'
            ]
            
            for domain in shortener_domains:
                if domain in url.lower():
                    indicators.append(f"URL shortener detected: {domain}")
                    is_suspicious = True
                    break
            
            # Check for suspicious patterns
            suspicious_patterns = [
                r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
                r'[a-zA-Z0-9]+-[a-zA-Z0-9]+-[a-zA-Z0-9]+\.',  # Suspicious subdomains
                r'[a-zA-Z]{20,}\.com',  # Very long domain names
                r'(microsoft|paypal|amazon|google|apple)-[a-zA-Z0-9]+\.',  # Brand spoofing
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, url.lower()):
                    indicators.append(f"Suspicious URL pattern: {pattern}")
                    is_suspicious = True
            
            # Check for homograph attacks (similar looking domains)
            suspicious_chars = ['і', 'о', 'а', 'е', 'р', 'х', 'с', 'у', 'к']  # Cyrillic look-alikes
            for char in suspicious_chars:
                if char in url:
                    indicators.append("Potential homograph attack detected")
                    is_suspicious = True
                    break
            
            return {
                "url": url,
                "is_suspicious": is_suspicious,
                "indicators": indicators
            }
            
        except Exception as e:
            logger.error(f"Error analyzing URL {url}: {str(e)}")
            return {
                "url": url,
                "is_suspicious": False,
                "indicators": []
            }
    
    async def _analyze_attachments(self, attachments: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze email attachments for threats."""
        try:
            suspicious_attachments = []
            attachment_indicators = []
            
            # Dangerous file extensions
            dangerous_extensions = [
                '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs',
                '.js', '.jar', '.app', '.deb', '.pkg', '.dmg', '.iso'
            ]
            
            # Potentially dangerous extensions
            risky_extensions = [
                '.zip', '.rar', '.7z', '.doc', '.docx', '.xls', '.xlsx',
                '.ppt', '.pptx', '.pdf', '.rtf', '.htm', '.html'
            ]
            
            for attachment in attachments:
                filename = attachment.get('filename', '').lower()
                content_type = attachment.get('content_type', '').lower()
                size = attachment.get('size', 0)
                
                attachment_analysis = {
                    "filename": filename,
                    "is_suspicious": False,
                    "indicators": []
                }
                
                # Check file extension
                for ext in dangerous_extensions:
                    if filename.endswith(ext):
                        attachment_analysis["is_suspicious"] = True
                        attachment_analysis["indicators"].append(f"Dangerous file extension: {ext}")
                        break
                
                # Check for double extensions
                if filename.count('.') > 1:
                    attachment_analysis["is_suspicious"] = True
                    attachment_analysis["indicators"].append("Double file extension detected")
                
                # Check for executable disguised as document
                if any(filename.endswith(ext) for ext in dangerous_extensions):
                    if any(doc_word in filename for doc_word in ['document', 'invoice', 'receipt', 'report']):
                        attachment_analysis["is_suspicious"] = True
                        attachment_analysis["indicators"].append("Executable disguised as document")
                
                # Check file size (very small or very large files can be suspicious)
                if size > 0:
                    if size < 1024:  # Less than 1KB
                        attachment_analysis["indicators"].append("Unusually small file size")
                    elif size > 50 * 1024 * 1024:  # Larger than 50MB
                        attachment_analysis["indicators"].append("Unusually large file size")
                
                if attachment_analysis["is_suspicious"]:
                    suspicious_attachments.append(attachment_analysis)
                    attachment_indicators.extend(attachment_analysis["indicators"])
            
            return {
                "total_attachments": len(attachments),
                "suspicious_attachments": suspicious_attachments,
                "suspicious_count": len(suspicious_attachments),
                "attachment_indicators": attachment_indicators,
                "is_suspicious": len(suspicious_attachments) > 0,
                "confidence_impact": min(len(suspicious_attachments) * 0.3, 0.9)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing attachments: {str(e)}")
            return {
                "total_attachments": len(attachments),
                "suspicious_attachments": [],
                "suspicious_count": 0,
                "attachment_indicators": [],
                "is_suspicious": False,
                "confidence_impact": 0.0
            }
    
    async def _check_threat_intelligence(
        self,
        sender_email: str,
        subject: str,
        content: str
    ) -> Dict[str, Any]:
        """Check against threat intelligence databases."""
        try:
            threat_matches = []
            indicators = []
            
            # Check sender against known bad domains
            sender_domain = sender_email.split('@')[-1].lower()
            if sender_domain in self.malicious_domains:
                threat_matches.append("malicious_sender_domain")
                indicators.append(f"Known malicious domain: {sender_domain}")
            
            # Check for known phishing keywords
            content_lower = content.lower()
            subject_lower = subject.lower()
            
            for keyword in self.phishing_keywords:
                if keyword in content_lower or keyword in subject_lower:
                    threat_matches.append("phishing_keyword")
                    indicators.append(f"Phishing keyword detected: {keyword}")
            
            # Check for IOCs (Indicators of Compromise)
            for ioc in self.iocs:
                if ioc in content or ioc in subject:
                    threat_matches.append("ioc_match")
                    indicators.append(f"IOC detected: {ioc}")
            
            return {
                "threat_matches": threat_matches,
                "indicators": indicators,
                "is_threat": len(threat_matches) > 0,
                "confidence_impact": min(len(threat_matches) * 0.4, 1.0)
            }
            
        except Exception as e:
            logger.error(f"Error checking threat intelligence: {str(e)}")
            return {
                "threat_matches": [],
                "indicators": [],
                "is_threat": False,
                "confidence_impact": 0.0
            }
    
    async def _check_sender_reputation(self, sender_email: str, headers: Dict[str, str]) -> Dict[str, Any]:
        """Check sender reputation and authenticity."""
        try:
            indicators = []
            is_suspicious = False
            confidence_impact = 0.0
            
            sender_domain = sender_email.split('@')[-1].lower()
            
            # Check for suspicious domain patterns
            suspicious_patterns = [
                r'[0-9]{5,}',  # Long numeric sequences
                r'[a-zA-Z]{1,2}[0-9]{3,}',  # Short letters followed by numbers
                r'-[a-zA-Z]{1,3}$',  # Ending with dash and short suffix
                r'^[a-zA-Z]{1,2}-',  # Starting with short prefix and dash
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, sender_domain):
                    indicators.append(f"Suspicious domain pattern: {pattern}")
                    is_suspicious = True
                    confidence_impact += 0.2
            
            # Check for recently registered domains (would need external API)
            # For now, we'll check for common free email providers used in phishing
            free_providers = [
                'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
                '10minutemail.com', 'tempmail.org', 'guerrillamail.com'
            ]
            
            if sender_domain in free_providers:
                indicators.append(f"Free email provider: {sender_domain}")
                confidence_impact += 0.1
            
            # Check display name vs sender email mismatch
            display_name = headers.get('From', '').split('<')[0].strip()
            if display_name and '@' in display_name:
                display_domain = display_name.split('@')[-1].lower()
                if display_domain != sender_domain:
                    indicators.append("Display name/sender domain mismatch")
                    is_suspicious = True
                    confidence_impact += 0.3
            
            return {
                "is_suspicious": is_suspicious,
                "indicators": indicators,
                "confidence_impact": min(confidence_impact, 0.8),
                "sender_domain": sender_domain
            }
            
        except Exception as e:
            logger.error(f"Error checking sender reputation: {str(e)}")
            return {
                "is_suspicious": False,
                "indicators": [],
                "confidence_impact": 0.0,
                "sender_domain": ""
            }
    
    async def _check_subject_patterns(self, subject: str) -> Dict[str, Any]:
        """Check subject line for suspicious patterns."""
        try:
            indicators = []
            is_suspicious = False
            confidence_impact = 0.0
            
            subject_lower = subject.lower()
            
            # Common phishing subject patterns
            phishing_patterns = [
                r'urgent.{0,10}action.{0,10}required',
                r'account.{0,10}suspended',
                r'verify.{0,10}account',
                r'click.{0,10}here',
                r'limited.{0,10}time',
                r'act.{0,10}now',
                r'congratulations.{0,20}winner',
                r'free.{0,10}money',
                r'nigerian.{0,10}prince',
                r'inheritance',
                r'lottery.{0,10}winner'
            ]
            
            for pattern in phishing_patterns:
                if re.search(pattern, subject_lower):
                    indicators.append(f"Phishing pattern in subject: {pattern}")
                    is_suspicious = True
                    confidence_impact += 0.3
            
            # Check for excessive capitalization
            if subject.isupper() and len(subject) > 5:
                indicators.append("Excessive capitalization")
                confidence_impact += 0.1
            
            # Check for excessive punctuation
            punct_count = sum(1 for char in subject if char in '!?')
            if punct_count > 2:
                indicators.append("Excessive punctuation")
                confidence_impact += 0.1
            
            # Check for suspicious keywords
            suspicious_keywords = [
                'urgent', 'immediate', 'suspended', 'expired', 'verify',
                'confirm', 'update', 'secure', 'alert', 'warning',
                'final notice', 'refund', 'prize', 'winner', 'selected'
            ]
            
            keyword_count = sum(1 for keyword in suspicious_keywords if keyword in subject_lower)
            if keyword_count > 1:
                indicators.append(f"Multiple suspicious keywords: {keyword_count}")
                confidence_impact += keyword_count * 0.1
            
            return {
                "is_suspicious": is_suspicious,
                "indicators": indicators,
                "confidence_impact": min(confidence_impact, 0.6)
            }
            
        except Exception as e:
            logger.error(f"Error checking subject patterns: {str(e)}")
            return {
                "is_suspicious": False,
                "indicators": [],
                "confidence_impact": 0.0
            }
    
    async def _check_content_patterns(self, content: str) -> Dict[str, Any]:
        """Check email content for suspicious patterns."""
        try:
            indicators = []
            is_suspicious = False
            confidence_impact = 0.0
            
            content_lower = content.lower()
            
            # Social engineering phrases
            social_eng_phrases = [
                'click here immediately',
                'verify your account',
                'suspend your account',
                'update your information',
                'confirm your identity',
                'act now',
                'limited time offer',
                'expires today',
                'last chance',
                'urgent response required'
            ]
            
            for phrase in social_eng_phrases:
                if phrase in content_lower:
                    indicators.append(f"Social engineering phrase: {phrase}")
                    is_suspicious = True
                    confidence_impact += 0.2
            
            # Check for credential harvesting indicators
            credential_patterns = [
                r'username.{0,20}password',
                r'login.{0,20}credential',
                r'enter.{0,20}password',
                r'type.{0,20}password',
                r'social.{0,20}security',
                r'bank.{0,20}account',
                r'credit.{0,20}card'
            ]
            
            for pattern in credential_patterns:
                if re.search(pattern, content_lower):
                    indicators.append(f"Credential harvesting pattern: {pattern}")
                    is_suspicious = True
                    confidence_impact += 0.3
            
            # Check for poor grammar/spelling (basic check)
            grammar_indicators = [
                'recieve', 'seperate', 'teh', 'thier', 'wont',
                'cant', 'youre', 'its urgent', 'dont delay'
            ]
            
            grammar_errors = sum(1 for error in grammar_indicators if error in content_lower)
            if grammar_errors > 2:
                indicators.append(f"Multiple grammar/spelling errors: {grammar_errors}")
                confidence_impact += 0.15
            
            return {
                "is_suspicious": is_suspicious,
                "indicators": indicators,
                "confidence_impact": min(confidence_impact, 0.8)
            }
            
        except Exception as e:
            logger.error(f"Error checking content patterns: {str(e)}")
            return {
                "is_suspicious": False,
                "indicators": [],
                "confidence_impact": 0.0
            }
    
    async def _check_urgency_indicators(self, subject: str, content: str) -> Dict[str, Any]:
        """Check for urgency and pressure tactics."""
        try:
            indicators = []
            is_urgent = False
            confidence_impact = 0.0
            
            text = (subject + " " + content).lower()
            
            urgency_keywords = [
                'urgent', 'immediate', 'asap', 'rush', 'emergency',
                'expires', 'deadline', 'last chance', 'final notice',
                'act now', 'dont wait', 'hurry', 'quickly'
            ]
            
            urgency_count = sum(1 for keyword in urgency_keywords if keyword in text)
            
            if urgency_count > 2:
                indicators.append(f"High urgency indicators: {urgency_count}")
                is_urgent = True
                confidence_impact += urgency_count * 0.1
            
            # Time pressure phrases
            time_phrases = [
                'within 24 hours',
                'expires today',
                'expires tomorrow',
                'act within',
                'respond immediately',
                'time sensitive'
            ]
            
            for phrase in time_phrases:
                if phrase in text:
                    indicators.append(f"Time pressure phrase: {phrase}")
                    is_urgent = True
                    confidence_impact += 0.2
            
            return {
                "is_urgent": is_urgent,
                "indicators": indicators,
                "confidence_impact": min(confidence_impact, 0.5)
            }
            
        except Exception as e:
            logger.error(f"Error checking urgency indicators: {str(e)}")
            return {
                "is_urgent": False,
                "indicators": [],
                "confidence_impact": 0.0
            }
    
    async def _check_social_engineering(self, content: str) -> Dict[str, Any]:
        """Check for social engineering tactics."""
        try:
            indicators = []
            is_social_engineering = False
            confidence_impact = 0.0
            
            content_lower = content.lower()
            
            # Authority impersonation
            authority_keywords = [
                'irs', 'fbi', 'police', 'government', 'tax authority',
                'bank', 'paypal', 'amazon', 'microsoft', 'google',
                'apple', 'facebook', 'twitter', 'linkedin'
            ]
            
            for keyword in authority_keywords:
                if keyword in content_lower:
                    indicators.append(f"Authority impersonation: {keyword}")
                    is_social_engineering = True
                    confidence_impact += 0.25
            
            # Fear tactics
            fear_keywords = [
                'suspended', 'frozen', 'locked', 'blocked', 'terminated',
                'cancelled', 'penalty', 'fine', 'legal action', 'arrest'
            ]
            
            fear_count = sum(1 for keyword in fear_keywords if keyword in content_lower)
            if fear_count > 0:
                indicators.append(f"Fear tactics detected: {fear_count}")
                is_social_engineering = True
                confidence_impact += fear_count * 0.15
            
            # Reward/greed tactics
            reward_keywords = [
                'prize', 'winner', 'lottery', 'jackpot', 'million',
                'inheritance', 'refund', 'cashback', 'reward', 'gift'
            ]
            
            reward_count = sum(1 for keyword in reward_keywords if keyword in content_lower)
            if reward_count > 0:
                indicators.append(f"Reward/greed tactics: {reward_count}")
                is_social_engineering = True
                confidence_impact += reward_count * 0.2
            
            return {
                "is_social_engineering": is_social_engineering,
                "indicators": indicators,
                "confidence_impact": min(confidence_impact, 0.8)
            }
            
        except Exception as e:
            logger.error(f"Error checking social engineering: {str(e)}")
            return {
                "is_social_engineering": False,
                "indicators": [],
                "confidence_impact": 0.0
            }
    
    async def _check_email_authentication(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Check email authentication (SPF, DKIM, DMARC)."""
        try:
            indicators = []
            auth_failed = False
            confidence_impact = 0.0
            
            # Check SPF
            spf_result = headers.get('Received-SPF', '').lower()
            if 'fail' in spf_result:
                indicators.append("SPF authentication failed")
                auth_failed = True
                confidence_impact += 0.3
            elif 'softfail' in spf_result:
                indicators.append("SPF soft fail")
                confidence_impact += 0.15
            
            # Check DKIM
            dkim_signature = headers.get('DKIM-Signature', '')
            if not dkim_signature:
                indicators.append("DKIM signature missing")
                confidence_impact += 0.2
            
            # Check DMARC
            authentication_results = headers.get('Authentication-Results', '').lower()
            if 'dmarc=fail' in authentication_results:
                indicators.append("DMARC authentication failed")
                auth_failed = True
                confidence_impact += 0.4
            
            return {
                "auth_failed": auth_failed,
                "indicators": indicators,
                "confidence_impact": min(confidence_impact, 0.7)
            }
            
        except Exception as e:
            logger.error(f"Error checking email authentication: {str(e)}")
            return {
                "auth_failed": False,
                "indicators": [],
                "confidence_impact": 0.0
            }
    
    async def _combine_analysis_results(
        self,
        ml_prediction: Dict[str, Any],
        rule_based_results: Dict[str, Any],
        url_analysis: Dict[str, Any],
        attachment_analysis: Dict[str, Any],
        threat_intel_results: Dict[str, Any],
        features: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Combine all analysis results into final assessment."""
        try:
            # Calculate weighted confidence score
            ml_weight = 0.4
            rules_weight = 0.3
            url_weight = 0.15
            attachment_weight = 0.1
            threat_intel_weight = 0.05
            
            confidence_score = (
                ml_prediction["confidence"] * ml_weight +
                rule_based_results["confidence_score"] * rules_weight +
                url_analysis["confidence_impact"] * url_weight +
                attachment_analysis["confidence_impact"] * attachment_weight +
                threat_intel_results["confidence_impact"] * threat_intel_weight
            )
            
            # Collect all threat indicators
            all_indicators = []
            all_indicators.extend(rule_based_results.get("threat_indicators", []))
            all_indicators.extend(url_analysis.get("url_indicators", []))
            all_indicators.extend(attachment_analysis.get("attachment_indicators", []))
            all_indicators.extend(threat_intel_results.get("indicators", []))
            
            # Determine threat level
            if confidence_score >= 0.8:
                threat_level = ThreatLevel.CRITICAL
                should_quarantine = True
                quarantine_reason = QuarantineReason.HIGH_CONFIDENCE_PHISHING
            elif confidence_score >= 0.6:
                threat_level = ThreatLevel.HIGH
                should_quarantine = True
                quarantine_reason = QuarantineReason.SUSPECTED_PHISHING
            elif confidence_score >= 0.4:
                threat_level = ThreatLevel.MEDIUM
                should_quarantine = True
                quarantine_reason = QuarantineReason.POLICY_VIOLATION
            elif confidence_score >= 0.2:
                threat_level = ThreatLevel.LOW
                should_quarantine = False
                quarantine_reason = None
            else:
                threat_level = ThreatLevel.SAFE
                should_quarantine = False
                quarantine_reason = None
            
            # Override if ML model is highly confident
            if ml_prediction["is_phishing"] and ml_prediction["confidence"] > 0.85:
                threat_level = ThreatLevel.CRITICAL
                should_quarantine = True
                quarantine_reason = QuarantineReason.AI_DETECTION
            
            # Detection methods used
            detection_methods = []
            if ml_prediction["confidence"] > 0.1:
                detection_methods.append("machine_learning")
            if rule_based_results["detected_threats"]:
                detection_methods.append("rule_based")
            if url_analysis["is_suspicious"]:
                detection_methods.append("url_analysis")
            if attachment_analysis["is_suspicious"]:
                detection_methods.append("attachment_analysis")
            if threat_intel_results["is_threat"]:
                detection_methods.append("threat_intelligence")
            
            return {
                "threat_level": threat_level.value,
                "confidence_score": round(confidence_score, 3),
                "should_quarantine": should_quarantine,
                "quarantine_reason": quarantine_reason.value if quarantine_reason else None,
                "threat_indicators": all_indicators,
                "detection_methods": detection_methods,
                "analysis_details": {
                    "ml_prediction": ml_prediction,
                    "rule_based_results": rule_based_results,
                    "url_analysis": url_analysis,
                    "attachment_analysis": attachment_analysis,
                    "threat_intel_results": threat_intel_results,
                    "features": features,
                    "timestamp": datetime.utcnow().isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"Error combining analysis results: {str(e)}")
            return {
                "threat_level": ThreatLevel.MEDIUM.value,
                "confidence_score": 0.5,
                "should_quarantine": True,
                "quarantine_reason": QuarantineReason.ANALYSIS_ERROR.value,
                "threat_indicators": ["Error in analysis combination"],
                "detection_methods": ["error_handling"],
                "analysis_details": {"error": str(e)}
            }
    
    def _load_threat_intelligence(self):
        """Load threat intelligence data."""
        try:
            # In a real implementation, this would load from external threat feeds
            # For now, we'll use hardcoded lists
            
            self.malicious_domains = {
                'phishing-domain.com',
                'fake-bank.net',
                'malicious-site.org',
                'scam-website.info',
                'phish-site.co'
            }
            
            self.phishing_keywords = {
                'verify account',
                'suspended account',
                'click here now',
                'update payment',
                'confirm identity',
                'nigerian prince',
                'lottery winner',
                'inheritance money',
                'tax refund',
                'free money'
            }
            
            self.iocs = {
                'malicious-hash-123',
                'evil-ip-address',
                'bad-domain.com',
                'suspicious-file.exe'
            }
            
            logger.info("Threat intelligence data loaded")
            
        except Exception as e:
            logger.error(f"Error loading threat intelligence: {str(e)}")
            # Initialize with empty sets if loading fails
            self.malicious_domains = set()
            self.phishing_keywords = set()
            self.iocs = set()
    
    def _initialize_detection_rules(self):
        """Initialize detection rules and patterns."""
        try:
            # Detection rules are already implemented in the check methods
            # This could be used to load external rule files
            logger.info("Detection rules initialized")
            
        except Exception as e:
            logger.error(f"Error initializing detection rules: {str(e)}")
    
    async def _log_detection_action(
        self,
        action: ActionType,
        resource_id: Optional[uuid.UUID],
        details: Dict[str, Any]
    ):
        """Log detection engine actions."""
        try:
            audit_log = AuditLog(
                id=uuid.uuid4(),
                action=action,
                resource_type="email_analysis",
                resource_id=resource_id,
                user_id=None,  # System action
                details=details,
                timestamp=datetime.utcnow()
            )
            
            self.db.add(audit_log)
            # Note: Don't commit here, let the calling method handle it
            
        except Exception as e:
            logger.error(f"Error logging detection action: {str(e)}")
    
    async def update_threat_intelligence(self, new_indicators: Dict[str, List[str]]) -> bool:
        """Update threat intelligence with new indicators."""
        try:
            if 'domains' in new_indicators:
                self.malicious_domains.update(new_indicators['domains'])
            
            if 'keywords' in new_indicators:
                self.phishing_keywords.update(new_indicators['keywords'])
            
            if 'iocs' in new_indicators:
                self.iocs.update(new_indicators['iocs'])
            
            logger.info("Threat intelligence updated")
            return True
            
        except Exception as e:
            logger.error(f"Error updating threat intelligence: {str(e)}")
            return False
    
    async def get_detection_statistics(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Get detection engine statistics."""
        try:
            query = self.db.query(AuditLog).filter(
                AuditLog.resource_type == "email_analysis"
            )
            
            if start_date:
                query = query.filter(AuditLog.timestamp >= start_date)
            
            if end_date:
                query = query.filter(AuditLog.timestamp <= end_date)
            
            analysis_logs = query.all()
            
            total_analyses = len(analysis_logs)
            
            # Count by threat level
            threat_levels = {}
            detection_methods = {}
            
            for log in analysis_logs:
                details = log.details
                threat_level = details.get('threat_level', 'UNKNOWN')
                threat_levels[threat_level] = threat_levels.get(threat_level, 0) + 1
                
                methods = details.get('detection_methods', [])
                for method in methods:
                    detection_methods[method] = detection_methods.get(method, 0) + 1
            
            # Calculate average confidence
            confidences = [log.details.get('confidence', 0) for log in analysis_logs]
            avg_confidence = sum(confidences) / len(confidences) if confidences else 0
            
            return {
                "total_analyses": total_analyses,
                "threat_level_distribution": threat_levels,
                "detection_method_usage": detection_methods,
                "average_confidence": round(avg_confidence, 3),
                "period": {
                    "start_date": start_date.isoformat() if start_date else None,
                    "end_date": end_date.isoformat() if end_date else None
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting detection statistics: {str(e)}")
            return {
                "total_analyses": 0,
                "threat_level_distribution": {},
                "detection_method_usage": {},
                "average_confidence": 0.0,
                "period": {}
            }

"""
Validation Utilities for PhishGuard

Provides comprehensive validation functions for data integrity,
security checks, and input sanitization across the application.
"""

import email
import ipaddress
import json
import re
import uuid
from datetime import date, datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

from .config import get_settings
from .logger import get_logger

logger = get_logger(__name__)
settings = get_settings()


class ValidationError(Exception):
    """Custom exception for validation errors."""

    pass


class ValidationSeverity(Enum):
    """Validation severity levels."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class EmailValidator:
    """Email validation and security checks."""

    @staticmethod
    def is_valid_email(email_address: str) -> bool:
        """
        Validate email address format.

        Args:
            email_address: Email address to validate

        Returns:
            True if valid, False otherwise
        """
        try:
            pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            return re.match(pattern, email_address) is not None
        except Exception:
            return False

    @staticmethod
    def validate_email_structure(email_message: str) -> Dict[str, Any]:
        """
        Validate email message structure and headers.

        Args:
            email_message: Raw email message

        Returns:
            Validation results
        """
        try:
            validation_result = {
                "is_valid": True,
                "issues": [],
                "headers": {},
                "structure_score": 100,
            }

            # Parse email
            try:
                msg = email.message_from_string(email_message)
                validation_result["headers"] = dict(msg.items())
            except Exception as e:
                validation_result["is_valid"] = False
                validation_result["issues"].append(
                    {
                        "type": "parsing_error",
                        "message": f"Failed to parse email: {str(e)}",
                        "severity": ValidationSeverity.CRITICAL.value,
                    }
                )
                return validation_result

            # Check required headers
            required_headers = ["From", "Date", "Subject"]
            for header in required_headers:
                if header not in validation_result["headers"]:
                    validation_result["issues"].append(
                        {
                            "type": "missing_header",
                            "message": f"Missing required header: {header}",
                            "severity": ValidationSeverity.WARNING.value,
                        }
                    )
                    validation_result["structure_score"] -= 10

            # Validate From header
            from_header = validation_result["headers"].get("From", "")
            if from_header and not EmailValidator.is_valid_email(
                EmailValidator.extract_email_from_header(from_header)
            ):
                validation_result["issues"].append(
                    {
                        "type": "invalid_from",
                        "message": "Invalid From header format",
                        "severity": ValidationSeverity.ERROR.value,
                    }
                )
                validation_result["structure_score"] -= 20

            # Check for suspicious headers
            suspicious_headers = [
                "X-Mailer",
                "X-Originating-IP",
                "Authentication-Results",
            ]
            for header in suspicious_headers:
                if header in validation_result["headers"]:
                    value = validation_result["headers"][header]
                    if EmailValidator._is_suspicious_header_value(header, value):
                        validation_result["issues"].append(
                            {
                                "type": "suspicious_header",
                                "message": f"Suspicious {header}: {value}",
                                "severity": ValidationSeverity.WARNING.value,
                            }
                        )
                        validation_result["structure_score"] -= 5

            # Validate message structure
            if hasattr(msg, "get_payload"):
                payload = msg.get_payload()
                if isinstance(payload, list):
                    # Multipart message
                    for part in payload:
                        if part.get_content_type() == "text/html":
                            html_issues = EmailValidator._validate_html_content(
                                part.get_payload()
                            )
                            validation_result["issues"].extend(html_issues)

            # Final validation status
            if validation_result["structure_score"] < 50:
                validation_result["is_valid"] = False

            return validation_result

        except Exception as e:
            logger.error(f"Error validating email structure: {str(e)}")
            return {
                "is_valid": False,
                "issues": [
                    {
                        "type": "validation_error",
                        "message": f"Validation failed: {str(e)}",
                        "severity": ValidationSeverity.CRITICAL.value,
                    }
                ],
                "headers": {},
                "structure_score": 0,
            }

    @staticmethod
    def extract_email_from_header(header_value: str) -> str:
        """Extract email address from email header."""
        try:
            # Remove display name and extract email
            email_pattern = r"<([^>]+)>"
            match = re.search(email_pattern, header_value)
            if match:
                return match.group(1)

            # If no angle brackets, assume the whole value is the email
            return header_value.strip()

        except Exception:
            return ""

    @staticmethod
    def _is_suspicious_header_value(header_name: str, value: str) -> bool:
        """Check if header value is suspicious."""
        try:
            suspicious_patterns = {
                "X-Mailer": ["bulk mailer", "mass mailer", "spammer", "phishing"],
                "X-Originating-IP": [
                    # Check for suspicious IP ranges
                ],
                "Authentication-Results": ["fail", "none", "neutral"],
            }

            patterns = suspicious_patterns.get(header_name, [])
            value_lower = value.lower()

            return any(pattern in value_lower for pattern in patterns)

        except Exception:
            return False

    @staticmethod
    def _validate_html_content(html_content: str) -> List[Dict[str, Any]]:
        """Validate HTML content for suspicious elements."""
        try:
            issues = []

            # Check for suspicious HTML elements
            suspicious_elements = [
                r"<script[^>]*>",  # JavaScript
                r"<iframe[^>]*>",  # Iframes
                r"<object[^>]*>",  # Objects
                r"<embed[^>]*>",  # Embeds
                r"<form[^>]*>",  # Forms
            ]

            for pattern in suspicious_elements:
                if re.search(pattern, html_content, re.IGNORECASE):
                    issues.append(
                        {
                            "type": "suspicious_html",
                            "message": f"Suspicious HTML element found: {pattern}",
                            "severity": ValidationSeverity.WARNING.value,
                        }
                    )

            # Check for excessive external links
            link_pattern = r'href=["\']http[^"\']*["\']'
            links = re.findall(link_pattern, html_content, re.IGNORECASE)
            if len(links) > 10:
                issues.append(
                    {
                        "type": "excessive_links",
                        "message": f"Excessive external links: {len(links)}",
                        "severity": ValidationSeverity.WARNING.value,
                    }
                )

            return issues

        except Exception as e:
            return [
                {
                    "type": "html_validation_error",
                    "message": f"HTML validation failed: {str(e)}",
                    "severity": ValidationSeverity.ERROR.value,
                }
            ]


class URLValidator:
    """URL validation and security checks."""

    @staticmethod
    def is_valid_url(url: str) -> bool:
        """
        Validate URL format.

        Args:
            url: URL to validate

        Returns:
            True if valid, False otherwise
        """
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False

    @staticmethod
    def validate_url_safety(url: str) -> Dict[str, Any]:
        """
        Check URL for security risks.

        Args:
            url: URL to check

        Returns:
            Safety validation results
        """
        try:
            validation_result = {
                "is_safe": True,
                "risk_score": 0,
                "risks": [],
                "url_info": {},
            }

            if not URLValidator.is_valid_url(url):
                validation_result["is_safe"] = False
                validation_result["risks"].append(
                    {
                        "type": "invalid_url",
                        "message": "Invalid URL format",
                        "severity": ValidationSeverity.ERROR.value,
                    }
                )
                return validation_result

            parsed_url = urlparse(url)
            validation_result["url_info"] = {
                "scheme": parsed_url.scheme,
                "domain": parsed_url.netloc,
                "path": parsed_url.path,
                "query": parsed_url.query,
                "fragment": parsed_url.fragment,
            }

            # Check for suspicious schemes
            if parsed_url.scheme not in ["http", "https"]:
                validation_result["risks"].append(
                    {
                        "type": "suspicious_scheme",
                        "message": f"Unusual URL scheme: {parsed_url.scheme}",
                        "severity": ValidationSeverity.WARNING.value,
                    }
                )
                validation_result["risk_score"] += 20

            # Check for IP addresses instead of domains
            try:
                ipaddress.ip_address(parsed_url.netloc.split(":")[0])
                validation_result["risks"].append(
                    {
                        "type": "ip_address_domain",
                        "message": "URL uses IP address instead of domain name",
                        "severity": ValidationSeverity.WARNING.value,
                    }
                )
                validation_result["risk_score"] += 30
            except ValueError:
                pass  # Not an IP address, which is good

            # Check for URL shorteners
            url_shorteners = [
                "bit.ly",
                "tinyurl.com",
                "t.co",
                "goo.gl",
                "ow.ly",
                "short.link",
                "tiny.cc",
                "is.gd",
                "buff.ly",
            ]

            if any(shortener in parsed_url.netloc for shortener in url_shorteners):
                validation_result["risks"].append(
                    {
                        "type": "url_shortener",
                        "message": "URL uses a shortening service",
                        "severity": ValidationSeverity.WARNING.value,
                    }
                )
                validation_result["risk_score"] += 15

            # Check for suspicious domain patterns
            domain_risks = URLValidator._check_domain_risks(parsed_url.netloc)
            validation_result["risks"].extend(domain_risks)
            validation_result["risk_score"] += len(domain_risks) * 10

            # Check for suspicious path patterns
            path_risks = URLValidator._check_path_risks(parsed_url.path)
            validation_result["risks"].extend(path_risks)
            validation_result["risk_score"] += len(path_risks) * 5

            # Final safety determination
            if validation_result["risk_score"] > 50:
                validation_result["is_safe"] = False

            return validation_result

        except Exception as e:
            logger.error(f"Error validating URL safety: {str(e)}")
            return {
                "is_safe": False,
                "risk_score": 100,
                "risks": [
                    {
                        "type": "validation_error",
                        "message": f"URL validation failed: {str(e)}",
                        "severity": ValidationSeverity.CRITICAL.value,
                    }
                ],
                "url_info": {},
            }

    @staticmethod
    def _check_domain_risks(domain: str) -> List[Dict[str, Any]]:
        """Check domain for suspicious patterns."""
        try:
            risks = []

            # Check for excessive subdomains
            parts = domain.split(".")
            if len(parts) > 4:
                risks.append(
                    {
                        "type": "excessive_subdomains",
                        "message": f"Domain has many subdomains: {domain}",
                        "severity": ValidationSeverity.WARNING.value,
                    }
                )

            # Check for suspicious TLDs
            suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".pw", ".cc"]
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                risks.append(
                    {
                        "type": "suspicious_tld",
                        "message": f"Domain uses suspicious TLD: {domain}",
                        "severity": ValidationSeverity.WARNING.value,
                    }
                )

            # Check for homograph attacks (basic)
            suspicious_chars = ["ρ", "о", "е", "а", "р", "х", "с"]  # Cyrillic chars
            if any(char in domain for char in suspicious_chars):
                risks.append(
                    {
                        "type": "potential_homograph",
                        "message": "Domain may contain lookalike characters",
                        "severity": ValidationSeverity.WARNING.value,
                    }
                )

            return risks

        except Exception:
            return []

    @staticmethod
    def _check_path_risks(path: str) -> List[Dict[str, Any]]:
        """Check URL path for suspicious patterns."""
        try:
            risks = []

            # Check for suspicious keywords in path
            suspicious_keywords = [
                "login",
                "signin",
                "verify",
                "update",
                "secure",
                "account",
                "suspended",
                "confirm",
                "validate",
            ]

            path_lower = path.lower()
            for keyword in suspicious_keywords:
                if keyword in path_lower:
                    risks.append(
                        {
                            "type": "suspicious_path_keyword",
                            "message": f"Path contains suspicious keyword: {keyword}",
                            "severity": ValidationSeverity.INFO.value,
                        }
                    )

            # Check for excessive path depth
            if path.count("/") > 5:
                risks.append(
                    {
                        "type": "deep_path",
                        "message": "URL has unusually deep path structure",
                        "severity": ValidationSeverity.INFO.value,
                    }
                )

            return risks

        except Exception:
            return []


class DataValidator:
    """General data validation utilities."""

    @staticmethod
    def validate_uuid(uuid_string: str) -> bool:
        """
        Validate UUID format.

        Args:
            uuid_string: UUID string to validate

        Returns:
            True if valid, False otherwise
        """
        try:
            uuid.UUID(uuid_string)
            return True
        except (ValueError, AttributeError):
            return False

    @staticmethod
    def validate_json(json_string: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Validate JSON format and parse if valid.

        Args:
            json_string: JSON string to validate

        Returns:
            Tuple of (is_valid, parsed_data)
        """
        try:
            parsed_data = json.loads(json_string)
            return True, parsed_data
        except (json.JSONDecodeError, TypeError):
            return False, None

    @staticmethod
    def validate_date_range(
        start_date: Union[str, datetime, date], end_date: Union[str, datetime, date]
    ) -> Dict[str, Any]:
        """
        Validate date range.

        Args:
            start_date: Start date
            end_date: End date

        Returns:
            Validation results
        """
        try:
            result = {"is_valid": True, "issues": []}

            # Convert to datetime objects
            if isinstance(start_date, str):
                try:
                    start_date = datetime.fromisoformat(
                        start_date.replace("Z", "+00:00")
                    )
                except ValueError:
                    result["issues"].append("Invalid start date format")
                    result["is_valid"] = False
                    return result

            if isinstance(end_date, str):
                try:
                    end_date = datetime.fromisoformat(end_date.replace("Z", "+00:00"))
                except ValueError:
                    result["issues"].append("Invalid end date format")
                    result["is_valid"] = False
                    return result

            # Check if start is before end
            if start_date >= end_date:
                result["issues"].append("Start date must be before end date")
                result["is_valid"] = False

            # Check if dates are reasonable (not too far in past/future)
            now = datetime.utcnow()
            max_past = now.replace(year=now.year - 10)  # 10 years ago
            max_future = now.replace(year=now.year + 1)  # 1 year from now

            if start_date < max_past:
                result["issues"].append("Start date is too far in the past")

            if end_date > max_future:
                result["issues"].append("End date is too far in the future")

            return result

        except Exception as e:
            return {"is_valid": False, "issues": [f"Date validation error: {str(e)}"]}

    @staticmethod
    def sanitize_string(
        input_string: str,
        max_length: Optional[int] = None,
        allowed_chars: Optional[str] = None,
        remove_html: bool = True,
    ) -> str:
        """
        Sanitize string input for security.

        Args:
            input_string: String to sanitize
            max_length: Maximum allowed length
            allowed_chars: Regex pattern for allowed characters
            remove_html: Whether to remove HTML tags

        Returns:
            Sanitized string
        """
        try:
            if not isinstance(input_string, str):
                return ""

            sanitized = input_string

            # Remove HTML tags
            if remove_html:
                sanitized = re.sub(r"<[^>]+>", "", sanitized)

            # Apply character whitelist
            if allowed_chars:
                sanitized = re.sub(f"[^{allowed_chars}]", "", sanitized)

            # Apply length limit
            if max_length and len(sanitized) > max_length:
                sanitized = sanitized[:max_length]

            # Remove excessive whitespace
            sanitized = re.sub(r"\s+", " ", sanitized).strip()

            return sanitized

        except Exception as e:
            logger.error(f"Error sanitizing string: {str(e)}")
            return ""

    @staticmethod
    def validate_file_upload(
        filename: str,
        file_size: int,
        allowed_extensions: Optional[List[str]] = None,
        max_size: int = 10 * 1024 * 1024,  # 10MB default
    ) -> Dict[str, Any]:
        """
        Validate file upload parameters.

        Args:
            filename: Name of the uploaded file
            file_size: Size of the file in bytes
            allowed_extensions: List of allowed file extensions
            max_size: Maximum file size in bytes

        Returns:
            Validation results
        """
        try:
            result = {"is_valid": True, "issues": []}

            # Check filename
            if not filename or len(filename.strip()) == 0:
                result["issues"].append("Filename is required")
                result["is_valid"] = False
                return result

            # Sanitize filename
            safe_filename = re.sub(r"[^\w\-_\.]", "_", filename)
            if safe_filename != filename:
                result["issues"].append("Filename contains unsafe characters")

            # Check file extension
            if "." not in filename:
                result["issues"].append("File extension is required")
                result["is_valid"] = False
            else:
                extension = filename.lower().split(".")[-1]

                # Check against allowed extensions
                if allowed_extensions and extension not in allowed_extensions:
                    result["issues"].append(f"File type not allowed: .{extension}")
                    result["is_valid"] = False

                # Check for dangerous extensions
                dangerous_extensions = [
                    "exe",
                    "bat",
                    "com",
                    "scr",
                    "pif",
                    "vbs",
                    "js",
                    "jar",
                    "cmd",
                    "ps1",
                    "msi",
                    "dll",
                ]

                if extension in dangerous_extensions:
                    result["issues"].append(f"Dangerous file type: .{extension}")
                    result["is_valid"] = False

            # Check file size
            if file_size > max_size:
                result["issues"].append(
                    f"File too large: {file_size} bytes (max: {max_size})"
                )
                result["is_valid"] = False

            if file_size <= 0:
                result["issues"].append("File is empty")
                result["is_valid"] = False

            return result

        except Exception as e:
            return {"is_valid": False, "issues": [f"File validation error: {str(e)}"]}


class SecurityValidator:
    """Security-focused validation utilities."""

    @staticmethod
    def validate_password_strength(password: str) -> Dict[str, Any]:
        """
        Validate password strength.

        Args:
            password: Password to validate

        Returns:
            Strength validation results
        """
        try:
            result = {"is_strong": True, "score": 0, "issues": [], "suggestions": []}

            if len(password) < 8:
                result["issues"].append("Password too short (minimum 8 characters)")
                result["is_strong"] = False
            else:
                result["score"] += 20

            if len(password) >= 12:
                result["score"] += 10

            # Check for different character types
            if re.search(r"[a-z]", password):
                result["score"] += 10
            else:
                result["issues"].append("Missing lowercase letters")
                result["suggestions"].append("Add lowercase letters")

            if re.search(r"[A-Z]", password):
                result["score"] += 10
            else:
                result["issues"].append("Missing uppercase letters")
                result["suggestions"].append("Add uppercase letters")

            if re.search(r"\d", password):
                result["score"] += 10
            else:
                result["issues"].append("Missing numbers")
                result["suggestions"].append("Add numbers")

            if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                result["score"] += 15
            else:
                result["issues"].append("Missing special characters")
                result["suggestions"].append("Add special characters (!@#$%^&*)")

            # Check for common patterns
            common_patterns = [
                r"123+",
                r"abc+",
                r"qwe+",
                r"password",
                r"admin",
                r"user",
            ]

            password_lower = password.lower()
            for pattern in common_patterns:
                if re.search(pattern, password_lower):
                    result["issues"].append(f"Contains common pattern: {pattern}")
                    result["score"] -= 15

            # Check for repeated characters
            if re.search(r"(.)\1{2,}", password):
                result["issues"].append("Contains repeated characters")
                result["score"] -= 5

            # Determine strength level
            if result["score"] >= 80:
                result["strength_level"] = "very_strong"
            elif result["score"] >= 60:
                result["strength_level"] = "strong"
            elif result["score"] >= 40:
                result["strength_level"] = "medium"
            else:
                result["strength_level"] = "weak"
                result["is_strong"] = False

            return result

        except Exception as e:
            return {
                "is_strong": False,
                "score": 0,
                "issues": [f"Password validation error: {str(e)}"],
                "suggestions": ["Please try again with a valid password"],
            }

    @staticmethod
    def validate_input_injection(input_data: str) -> Dict[str, Any]:
        """
        Check input for potential injection attacks.

        Args:
            input_data: Input string to check

        Returns:
            Injection validation results
        """
        try:
            result = {"is_safe": True, "threats": [], "risk_score": 0}

            # SQL injection patterns
            sql_patterns = [
                r"(?i)(\bUNION\b.*\bSELECT\b)",
                r"(?i)(\bSELECT\b.*\bFROM\b)",
                r"(?i)(\bINSERT\b.*\bINTO\b)",
                r"(?i)(\bUPDATE\b.*\bSET\b)",
                r"(?i)(\bDELETE\b.*\bFROM\b)",
                r"(?i)(\bDROP\b.*\bTABLE\b)",
                r"[\'\"];?\s*(OR|AND)\s*[\'\"]?\w+[\'\"]?\s*=\s*[\'\"]?\w+",
                r"[\'\"];?\s*(OR|AND)\s*[\d\'\"]+=[\d\'\"]+",
            ]

            for pattern in sql_patterns:
                if re.search(pattern, input_data):
                    result["threats"].append(
                        {
                            "type": "sql_injection",
                            "pattern": pattern,
                            "severity": ValidationSeverity.CRITICAL.value,
                        }
                    )
                    result["risk_score"] += 50

            # XSS patterns
            xss_patterns = [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"on\w+\s*=",
                r"<iframe[^>]*>",
                r"<object[^>]*>",
                r"<embed[^>]*>",
            ]

            for pattern in xss_patterns:
                if re.search(pattern, input_data, re.IGNORECASE):
                    result["threats"].append(
                        {
                            "type": "xss_injection",
                            "pattern": pattern,
                            "severity": ValidationSeverity.HIGH.value,
                        }
                    )
                    result["risk_score"] += 30

            # Command injection patterns
            cmd_patterns = [
                r"[;&|`]",
                r"\$\(",
                r"`.*`",
                r"(?i)(cmd|command|exec|system|shell)",
            ]

            for pattern in cmd_patterns:
                if re.search(pattern, input_data):
                    result["threats"].append(
                        {
                            "type": "command_injection",
                            "pattern": pattern,
                            "severity": ValidationSeverity.HIGH.value,
                        }
                    )
                    result["risk_score"] += 40

            # Path traversal patterns
            path_patterns = [
                r"\.\.[\\/]",
                r"(?i)(etc|passwd|shadow|hosts)",
                r"(?i)(windows|system32|boot\.ini)",
            ]

            for pattern in path_patterns:
                if re.search(pattern, input_data):
                    result["threats"].append(
                        {
                            "type": "path_traversal",
                            "pattern": pattern,
                            "severity": ValidationSeverity.HIGH.value,
                        }
                    )
                    result["risk_score"] += 35

            # Determine overall safety
            if result["risk_score"] > 0:
                result["is_safe"] = False

            return result

        except Exception as e:
            return {
                "is_safe": False,
                "threats": [
                    {
                        "type": "validation_error",
                        "message": f"Injection validation failed: {str(e)}",
                        "severity": ValidationSeverity.CRITICAL.value,
                    }
                ],
                "risk_score": 100,
            }


# Convenience functions for common validation tasks
def validate_user_input(
    data: Dict[str, Any],
    required_fields: List[str],
    field_validators: Optional[Dict[str, callable]] = None,
) -> Dict[str, Any]:
    """
    Validate user input data against requirements.

    Args:
        data: Input data to validate
        required_fields: List of required field names
        field_validators: Custom validators for specific fields

    Returns:
        Validation results
    """
    try:
        result = {"is_valid": True, "errors": {}, "sanitized_data": {}}

        field_validators = field_validators or {}

        # Check required fields
        for field in required_fields:
            if field not in data or data[field] is None or data[field] == "":
                result["errors"][field] = f"Field '{field}' is required"
                result["is_valid"] = False
            else:
                # Apply field-specific validation
                if field in field_validators:
                    validator = field_validators[field]
                    try:
                        validation_result = validator(data[field])
                        if not validation_result.get("is_valid", True):
                            result["errors"][field] = validation_result.get(
                                "error", "Validation failed"
                            )
                            result["is_valid"] = False
                        else:
                            result["sanitized_data"][field] = validation_result.get(
                                "value", data[field]
                            )
                    except Exception as e:
                        result["errors"][field] = f"Validation error: {str(e)}"
                        result["is_valid"] = False
                else:
                    # Basic sanitization
                    if isinstance(data[field], str):
                        result["sanitized_data"][field] = DataValidator.sanitize_string(
                            data[field]
                        )
                    else:
                        result["sanitized_data"][field] = data[field]

        return result

    except Exception as e:
        logger.error(f"Error validating user input: {str(e)}")
        return {
            "is_valid": False,
            "errors": {"general": f"Validation failed: {str(e)}"},
            "sanitized_data": {},
        }


def create_email_validator() -> EmailValidator:
    """Factory function for email validator."""
    return EmailValidator()


def create_url_validator() -> URLValidator:
    """Factory function for URL validator."""
    return URLValidator()


def create_data_validator() -> DataValidator:
    """Factory function for data validator."""
    return DataValidator()


def create_security_validator() -> SecurityValidator:
    """Factory function for security validator."""
    return SecurityValidator()

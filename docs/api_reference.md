# PhishGuard API Reference

## Overview

PhishGuard provides a comprehensive REST API for email threat detection, quarantine management, and security analytics. This document covers all available endpoints, authentication methods, and integration patterns.

## Base URL

```
Production: https://api.phishguard.your-domain.com
Development: http://localhost:8000
```

## Authentication

### JWT Bearer Token Authentication

All API endpoints require authentication using JWT bearer tokens.

#### Obtain Access Token

```http
POST /api/auth/token
Content-Type: application/json

{
  "username": "user@example.com",
  "password": "your_password"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

#### Refresh Token

```http
POST /api/auth/refresh
Content-Type: application/json

{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### Using Authentication

Include the access token in the Authorization header:

```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## Rate Limiting

API requests are rate limited based on the following rules:

- **Authentication endpoints**: 10 requests per minute
- **General API endpoints**: 1000 requests per minute
- **Upload endpoints**: 20 requests per minute

Rate limit headers are included in responses:

```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640995200
X-RateLimit-Window: 60
```

## API Endpoints

### Authentication

#### POST /api/auth/token
Authenticate user and obtain access token.

**Request Body:**
```json
{
  "username": "string",
  "password": "string"
}
```

**Response:** `200 OK`
```json
{
  "access_token": "string",
  "refresh_token": "string",
  "token_type": "bearer",
  "expires_in": 1800
}
```

#### POST /api/auth/refresh
Refresh access token using refresh token.

#### POST /api/auth/logout
Invalidate current session.

#### POST /api/auth/register
Register new user account (admin only).

### Users

#### GET /api/users/me
Get current user profile.

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "username": "string",
  "email": "string",
  "first_name": "string",
  "last_name": "string",
  "role": "admin|security_analyst|user|viewer",
  "is_verified": true,
  "created_at": "2024-01-01T00:00:00Z",
  "last_login": "2024-01-01T00:00:00Z"
}
```

#### PUT /api/users/me
Update current user profile.

#### GET /api/users
List all users (admin/security_analyst only).

**Query Parameters:**
- `page` (integer): Page number (default: 1)
- `size` (integer): Page size (default: 20)
- `role` (string): Filter by role
- `search` (string): Search by name or email

#### POST /api/users
Create new user (admin only).

#### GET /api/users/{user_id}
Get user by ID (admin/security_analyst only).

#### PUT /api/users/{user_id}
Update user (admin only).

#### DELETE /api/users/{user_id}
Delete user (admin only).

### Emails

#### GET /api/emails
List emails with optional filtering.

**Query Parameters:**
- `page` (integer): Page number
- `size` (integer): Page size
- `is_phishing` (boolean): Filter by phishing status
- `is_quarantined` (boolean): Filter by quarantine status
- `threat_level` (string): Filter by threat level
- `platform` (string): Filter by email platform
- `sender_email` (string): Filter by sender
- `date_from` (string): Date range filter (ISO format)
- `date_to` (string): Date range filter (ISO format)

**Response:** `200 OK`
```json
{
  "total": 1000,
  "page": 1,
  "size": 20,
  "pages": 50,
  "items": [
    {
      "id": "uuid",
      "sender_email": "sender@example.com",
      "recipient_email": "recipient@example.com",
      "subject": "Email Subject",
      "received_date": "2024-01-01T00:00:00Z",
      "is_phishing": true,
      "threat_level": "high",
      "risk_score": 0.85,
      "is_quarantined": true,
      "status": "quarantined",
      "source_platform": "gmail",
      "has_attachments": false
    }
  ]
}
```

#### GET /api/emails/{email_id}
Get email details by ID.

#### POST /api/emails/scan
Manually scan emails from connected platforms.

#### PUT /api/emails/{email_id}/quarantine
Quarantine email.

#### DELETE /api/emails/{email_id}/quarantine
Restore email from quarantine.

### Quarantine

#### GET /api/quarantine
List quarantined emails.

#### POST /api/quarantine/{email_id}/restore
Restore email from quarantine.

#### DELETE /api/quarantine/{email_id}
Permanently delete quarantined email.

#### POST /api/quarantine/bulk-action
Perform bulk actions on quarantined emails.

**Request Body:**
```json
{
  "email_ids": ["uuid1", "uuid2"],
  "action": "restore|delete"
}
```

### Reports

#### GET /api/reports/dashboard
Get dashboard analytics data.

**Response:** `200 OK`
```json
{
  "summary": {
    "total_emails": 10000,
    "threats_detected": 150,
    "emails_quarantined": 140,
    "false_positives": 5,
    "detection_rate": 0.015
  },
  "threat_levels": {
    "low": 50,
    "medium": 60,
    "high": 30,
    "critical": 10
  },
  "platforms": {
    "gmail": 8000,
    "microsoft365": 2000
  },
  "timeline": [
    {
      "date": "2024-01-01",
      "emails": 500,
      "threats": 8
    }
  ]
}
```

#### GET /api/reports/threat-analytics
Get threat analytics and trends.

#### GET /api/reports/executive-summary
Get executive summary report.

#### POST /api/reports/export
Export reports in various formats.

**Request Body:**
```json
{
  "format": "pdf|csv|xlsx",
  "report_type": "dashboard|threat_analytics|executive_summary",
  "date_range": {
    "start": "2024-01-01",
    "end": "2024-01-31"
  },
  "filters": {
    "threat_level": ["high", "critical"],
    "platform": ["gmail"]
  }
}
```

### Simulations

#### GET /api/simulations
List phishing simulations.

#### POST /api/simulations
Create new phishing simulation.

**Request Body:**
```json
{
  "name": "Simulation Name",
  "template_id": "uuid",
  "target_groups": ["group1", "group2"],
  "schedule": {
    "start_date": "2024-01-01T09:00:00Z",
    "frequency": "once|daily|weekly|monthly"
  },
  "settings": {
    "track_clicks": true,
    "track_data_entry": true,
    "send_training": true
  }
}
```

#### GET /api/simulations/{simulation_id}
Get simulation details and results.

#### PUT /api/simulations/{simulation_id}
Update simulation.

#### POST /api/simulations/{simulation_id}/start
Start simulation.

#### POST /api/simulations/{simulation_id}/stop
Stop simulation.

### Notifications

#### GET /api/notifications
List user notifications.

#### PUT /api/notifications/{notification_id}/read
Mark notification as read.

#### POST /api/notifications/preferences
Update notification preferences.

## Webhooks

PhishGuard supports webhooks for real-time event notifications.

### Webhook Events

- `email.processed` - Email analysis completed
- `threat.detected` - Threat detected
- `email.quarantined` - Email quarantined
- `email.restored` - Email restored from quarantine
- `simulation.completed` - Simulation completed

### Webhook Payload

```json
{
  "event": "threat.detected",
  "timestamp": "2024-01-01T00:00:00Z",
  "data": {
    "email_id": "uuid",
    "threat_level": "high",
    "risk_score": 0.85,
    "sender_email": "sender@example.com",
    "recipient_email": "recipient@example.com"
  },
  "organization_id": "uuid"
}
```

### Webhook Security

Webhooks are signed using HMAC-SHA256. Verify the signature using the `X-PhishGuard-Signature` header.

```python
import hmac
import hashlib

def verify_webhook(payload, signature, secret):
    expected = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)
```

## Error Handling

### Error Response Format

```json
{
  "error": "error_code",
  "message": "Human readable error message",
  "details": {
    "field": "Additional error details"
  },
  "timestamp": "2024-01-01T00:00:00Z",
  "request_id": "uuid"
}
```

### HTTP Status Codes

- `200 OK` - Request successful
- `201 Created` - Resource created
- `400 Bad Request` - Invalid request data
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `409 Conflict` - Resource conflict
- `422 Unprocessable Entity` - Validation error
- `429 Too Many Requests` - Rate limit exceeded
- `500 Internal Server Error` - Server error

### Common Error Codes

- `INVALID_CREDENTIALS` - Invalid username/password
- `TOKEN_EXPIRED` - JWT token expired
- `INSUFFICIENT_PERMISSIONS` - User lacks required permissions
- `RESOURCE_NOT_FOUND` - Requested resource not found
- `VALIDATION_ERROR` - Request validation failed
- `RATE_LIMIT_EXCEEDED` - Rate limit exceeded

## SDK Examples

### Python SDK

```python
import phishguard

# Initialize client
client = phishguard.Client(
    base_url="https://api.phishguard.your-domain.com",
    api_key="your_api_key"
)

# Get dashboard data
dashboard = client.reports.get_dashboard()

# List emails
emails = client.emails.list(
    is_phishing=True,
    threat_level="high"
)

# Quarantine email
client.emails.quarantine("email_id")
```

### JavaScript SDK

```javascript
import PhishGuard from '@phishguard/sdk';

// Initialize client
const client = new PhishGuard({
  baseURL: 'https://api.phishguard.your-domain.com',
  apiKey: 'your_api_key'
});

// Get dashboard data
const dashboard = await client.reports.getDashboard();

// List emails
const emails = await client.emails.list({
  isPhishing: true,
  threatLevel: 'high'
});

// Quarantine email
await client.emails.quarantine('email_id');
```

### cURL Examples

```bash
# Get access token
curl -X POST "https://api.phishguard.your-domain.com/api/auth/token" \
  -H "Content-Type: application/json" \
  -d '{"username": "user@example.com", "password": "password"}'

# List emails
curl -X GET "https://api.phishguard.your-domain.com/api/emails" \
  -H "Authorization: Bearer your_token"

# Quarantine email
curl -X PUT "https://api.phishguard.your-domain.com/api/emails/email_id/quarantine" \
  -H "Authorization: Bearer your_token"
```

## OpenAPI Specification

The complete OpenAPI 3.0 specification is available at:
- Interactive documentation: `https://api.phishguard.your-domain.com/docs`
- OpenAPI JSON: `https://api.phishguard.your-domain.com/openapi.json`

## Support

For API support and questions:
- Documentation: [https://docs.phishguard.your-domain.com](https://docs.phishguard.your-domain.com)
- Support Email: api-support@phishguard.your-domain.com
- GitHub Issues: [https://github.com/your-org/phishguard/issues](https://github.com/your-org/phishguard/issues)

# PhishGuard Architecture Documentation

## Overview

PhishGuard is an enterprise-grade email threat detection platform that combines artificial intelligence, real-time analysis, and automated response capabilities to protect organizations from phishing attacks. This document provides a comprehensive overview of the system architecture, components, and design principles.

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Load Balancer/Ingress                   │
└─────────────────────────┬───────────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────────┐
│                      Frontend Layer                            │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │  React Web App  │  │   Admin Panel   │  │  Mobile Apps    │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────┬───────────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────────┐
│                      API Gateway                               │
│           Authentication • Rate Limiting • Routing            │
└─────────────────────────┬───────────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────────┐
│                    Application Layer                           │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   FastAPI Core  │  │  AI/ML Engine   │  │  Task Queue     │ │
│  │                 │  │                 │  │   (Celery)      │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────┬───────────────────┬───────────────────┬───────────┘
              │                   │                   │
┌─────────────▼───────┐ ┌─────────▼───────┐ ┌─────────▼───────────┐
│   Data Layer        │ │  Integration    │ │   Monitoring &      │
│                     │ │     Layer       │ │    Security         │
│ ┌─────────────────┐ │ │ ┌─────────────┐ │ │ ┌─────────────────┐ │
│ │   PostgreSQL    │ │ │ │Gmail/M365   │ │ │ │   Prometheus    │ │
│ │     Database    │ │ │ │    APIs     │ │ │ │    Metrics      │ │
│ └─────────────────┘ │ │ └─────────────┘ │ │ └─────────────────┘ │
│ ┌─────────────────┐ │ │ ┌─────────────┐ │ │ ┌─────────────────┐ │
│ │     Redis       │ │ │ │Slack/SIEM   │ │ │ │     Grafana     │ │
│ │     Cache       │ │ │ │Integration  │ │ │ │   Dashboards    │ │
│ └─────────────────┘ │ │ └─────────────┘ │ │ └─────────────────┘ │
│ ┌─────────────────┐ │ │ ┌─────────────┐ │ │ ┌─────────────────┐ │
│ │   File Storage  │ │ │ │ SOAR/SIEM   │ │ │ │    Security     │ │
│ │   (Quarantine)  │ │ │ │ Connectors  │ │ │ │   Monitoring    │ │
│ └─────────────────┘ │ │ └─────────────┘ │ │ └─────────────────┘ │
└─────────────────────┘ └─────────────────┘ └─────────────────────┘
```

## Core Components

### 1. API Gateway Layer

#### FastAPI Core Application
- **Purpose**: Central REST API server providing all business logic endpoints
- **Technology**: FastAPI with Uvicorn/Gunicorn
- **Features**:
  - Async request handling
  - Automatic API documentation (OpenAPI/Swagger)
  - Request/response validation with Pydantic
  - Dependency injection for database connections
  - Comprehensive error handling

#### Authentication & Authorization
- **JWT-based authentication** with refresh token support
- **Role-based access control (RBAC)** with granular permissions
- **OAuth2 integration** for enterprise SSO
- **API key authentication** for service-to-service communication

#### Rate Limiting & Security
- **Redis-based rate limiting** with sliding window algorithm
- **Request throttling** per user/IP/endpoint
- **CORS configuration** for cross-origin requests
- **Security headers** injection (HSTS, CSP, X-Frame-Options)

### 2. Artificial Intelligence Engine

#### Machine Learning Pipeline
```
Email Input → Feature Extraction → Model Inference → Threat Scoring → Action Decision
     │              │                    │               │              │
     │              ▼                    │               ▼              ▼
     │      ┌─────────────────┐         │        ┌─────────────┐  ┌─────────────┐
     │      │   Text Features │         │        │Risk Scoring │  │Auto-Actions │
     │      │   URL Analysis  │         │        │Confidence   │  │Quarantine   │
     │      │Header Analysis  │         │        │Threat Level │  │Notify Users │
     │      │Attachment Info  │         │        └─────────────┘  └─────────────┘
     │      └─────────────────┘         │
     │              │                    │
     ▼              ▼                    ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────────┐
│Raw Email    │ │Feature      │ │ML Model         │
│Content      │ │Vector       │ │(Random Forest + │
│Metadata     │ │(Normalized) │ │ Ensemble)       │
│Attachments  │ │             │ │                 │
└─────────────┘ └─────────────┘ └─────────────────┘
```

#### AI Components

**Feature Extraction Engine** (`src/ai_engine/feature_extraction.py`)
- Text analysis (TF-IDF, sentiment, readability)
- URL reputation and pattern analysis
- Header examination for spoofing indicators
- Attachment metadata analysis
- Sender reputation scoring

**Model Training Pipeline** (`src/ai_engine/train_model.py`)
- Automated model retraining with new threat data
- Cross-validation and hyperparameter optimization
- Ensemble model management (Random Forest + SVM + Neural Network)
- Model versioning and rollback capabilities
- Performance metrics tracking

**Threat Inference Engine** (`src/ai_engine/inference.py`)
- Real-time email threat scoring
- Multi-model ensemble predictions
- Confidence scoring and uncertainty quantification
- Adaptive threshold management
- Explainable AI for threat reasoning

### 3. Data Architecture

#### Database Design (PostgreSQL)

```sql
-- Core Entity Relationships
Users ←── Emails ←── Threat_Analysis
  │         │              │
  │         ▼              ▼
  │    Quarantine    AI_Model_Results
  │         │              │
  │         ▼              ▼
  ▼    Audit_Logs    Performance_Metrics
Notifications
  │
  ▼
Simulation_Results
```

**Key Tables:**
- `users` - User accounts and authentication
- `emails` - Email metadata and analysis results
- `quarantine` - Quarantined email management
- `notifications` - Alert and notification system
- `audit_log` - Security and compliance logging
- `simulation` - Phishing simulation campaigns

#### Caching Strategy (Redis)

**Cache Layers:**
1. **Session Cache** - User sessions and JWT tokens
2. **Query Cache** - Expensive database query results
3. **Rate Limiting** - Request counting and throttling
4. **AI Model Cache** - Cached model predictions
5. **Integration Cache** - External API response caching

### 4. Integration Architecture

#### Email Platform Integrations

**Gmail API Integration** (`src/integrations/gmail_api.py`)
```
PhishGuard ←→ OAuth2 Flow ←→ Gmail API
    │               │            │
    │               ▼            ▼
    │        Access Tokens   Email Fetch
    │               │            │
    ▼               ▼            ▼
AI Analysis ←── Email Data ←── Gmail Messages
    │               │            │
    ▼               ▼            ▼
Quarantine ←── Risk Score ←── Labels/Actions
```

**Microsoft 365 Integration** (`src/integrations/microsoft365.py`)
- Microsoft Graph API integration
- Azure AD authentication
- Exchange Online email processing
- Teams/SharePoint threat correlation

#### Security Integrations

**SIEM Export** (`src/integrations/siem_exporter.py`)
- CEF/LEEF format support
- JSON structured logging
- Real-time threat intelligence feeds
- Compliance reporting

**SOAR Integration** (`src/integrations/soar_connector.py`)
- Automated incident creation
- Playbook triggering
- Case management integration
- Evidence artifact collection

### 5. Background Processing

#### Task Queue Architecture (Celery)

```
FastAPI App → Redis Broker → Celery Workers → Result Backend
     │             │              │               │
     │             ▼              ▼               ▼
     │       Task Queue     ┌─────────────┐  Results Cache
     │           │          │   Worker    │       │
     ▼           │          │   Pool      │       ▼
Task Creation   │          └─────────────┘  Task Status
     │           │              │               │
     │           ▼              ▼               │
     │    Task Distribution   Task Execution ←──┘
     │           │              │
     ▼           ▼              ▼
Async Response  Load Balancing  Error Handling
```

**Background Tasks:**
- Email scanning and analysis
- Model training and optimization
- Report generation
- Integration synchronization
- Cleanup and maintenance

### 6. Monitoring & Observability

#### Metrics Collection (Prometheus)

**Application Metrics:**
- HTTP request duration and counts
- Email processing performance
- AI model accuracy and latency
- Authentication success/failure rates
- Integration API response times

**Infrastructure Metrics:**
- CPU, memory, and disk utilization
- Database connection pool status
- Redis cache hit rates
- Task queue length and processing time

**Business Metrics:**
- Threat detection rates
- False positive/negative rates
- User engagement metrics
- Security incident response times

#### Health Monitoring

```
Health Check System
├── Database Connectivity
├── Redis Availability
├── External API Status
├── AI Model Performance
├── File System Access
└── Resource Utilization
```

## Security Architecture

### Multi-Layer Security Model

#### 1. Network Security
- TLS 1.3 encryption for all communications
- Network segmentation and firewall rules
- VPN access for administrative functions
- DDoS protection and rate limiting

#### 2. Application Security
- JWT token-based authentication
- Role-based access control (RBAC)
- Input validation and sanitization
- SQL injection prevention
- XSS and CSRF protection

#### 3. Data Security
- Encryption at rest (AES-256)
- Encryption in transit (TLS 1.3)
- Personal data anonymization
- Secure key management
- Data retention policies

#### 4. Operational Security
- Comprehensive audit logging
- Security event monitoring
- Intrusion detection system
- Automated security scanning
- Incident response procedures

## Deployment Architecture

### Container Orchestration (Kubernetes)

```yaml
Kubernetes Cluster
├── Namespace: phishguard
│   ├── Deployments
│   │   ├── phishguard-backend (3 replicas)
│   │   ├── phishguard-frontend (2 replicas)
│   │   ├── phishguard-celery-worker (2 replicas)
│   │   └── phishguard-celery-beat (1 replica)
│   ├── Services
│   │   ├── Load Balancer (External)
│   │   ├── ClusterIP Services (Internal)
│   │   └── NodePort Services (Development)
│   ├── ConfigMaps
│   │   ├── Application Configuration
│   │   └── Environment Variables
│   ├── Secrets
│   │   ├── Database Credentials
│   │   ├── API Keys
│   │   └── JWT Secrets
│   └── Persistent Volumes
│       ├── Database Storage
│       ├── Redis Storage
│       └── Quarantine File Storage
```

### High Availability

**Database Layer:**
- PostgreSQL with streaming replication
- Automated failover with Patroni
- Point-in-time recovery (PITR)
- Regular automated backups

**Application Layer:**
- Multiple backend replicas
- Load balancing with health checks
- Circuit breaker patterns
- Graceful degradation

**Cache Layer:**
- Redis Sentinel for high availability
- Redis Cluster for horizontal scaling
- Automatic failover detection

## Performance Optimization

### Scalability Design

#### Horizontal Scaling
- Stateless application design
- Database read replicas
- Distributed caching
- Microservice decomposition readiness

#### Performance Monitoring
- Real-time performance metrics
- Database query optimization
- Cache hit rate monitoring
- Resource utilization tracking

### Optimization Strategies

**Database Optimization:**
- Connection pooling
- Query optimization
- Index management
- Partitioning for large tables

**Application Optimization:**
- Async request processing
- Database query caching
- Response compression
- CDN for static assets

**AI/ML Optimization:**
- Model quantization
- Feature caching
- Batch prediction processing
- GPU acceleration support

## Future Architecture Considerations

### Planned Enhancements

1. **Microservices Migration**
   - Service decomposition strategy
   - Event-driven architecture
   - Distributed tracing
   - Service mesh implementation

2. **Advanced AI/ML**
   - Deep learning model integration
   - Real-time model updates
   - Federated learning capabilities
   - Automated feature engineering

3. **Enhanced Integrations**
   - Additional email platform support
   - Cloud security platform integration
   - Advanced SOAR playbooks
   - Threat intelligence feeds

4. **Global Deployment**
   - Multi-region deployment
   - Data residency compliance
   - Global load balancing
   - Edge computing integration

## Compliance & Standards

### Security Standards
- SOC 2 Type II compliance
- ISO 27001 certification readiness
- GDPR data protection compliance
- HIPAA security safeguards

### Industry Standards
- NIST Cybersecurity Framework
- MITRE ATT&CK mapping
- CIS Controls implementation
- OWASP security guidelines

This architecture provides a robust, scalable, and secure foundation for enterprise email threat detection while maintaining flexibility for future enhancements and compliance requirements.

# PhishGuard CI/CD Configuration

## GitHub Actions Workflow Overview

The PhishGuard project uses a comprehensive CI/CD pipeline that ensures code quality, security, and reliable deployments. The workflow is defined in `.github/workflows/ci-cd.yml`.

## Pipeline Stages

### 1. Code Quality & Security
- **Black** - Code formatting validation
- **isort** - Import statement organization
- **Flake8** - Linting and style checking
- **MyPy** - Static type checking
- **Bandit** - Security vulnerability scanning
- **Safety** - Dependency vulnerability checking

### 2. Testing
- **Backend Tests** - FastAPI application testing with PostgreSQL and Redis
- **Frontend Tests** - React component and integration testing
- **AI Model Tests** - Machine learning model validation and inference testing
- **Integration Tests** - End-to-end application testing

### 3. Build & Security Scanning
- **Docker Image Building** - Multi-stage container builds
- **Trivy Security Scanning** - Container vulnerability assessment
- **Snyk Security Analysis** - Dependency and container security

### 4. Performance Testing
- **Load Testing** - Application performance under load
- **Benchmark Testing** - Performance regression detection

### 5. Deployment
- **Staging Deployment** - Automated deployment to staging environment
- **Production Deployment** - Release-triggered production deployment
- **Smoke Testing** - Post-deployment health verification

## Environment Variables

Configure the following secrets in your GitHub repository:

### Required Secrets
```bash
# Container Registry
GITHUB_TOKEN                 # Automatic GitHub token

# Kubernetes Clusters
KUBE_CONFIG_STAGING         # Base64 encoded kubeconfig for staging
KUBE_CONFIG_PRODUCTION      # Base64 encoded kubeconfig for production

# Security Scanning
SNYK_TOKEN                  # Snyk API token for security scanning

# Notifications
SLACK_WEBHOOK               # Slack webhook URL for deployment notifications
```

### Optional Secrets
```bash
# Additional integrations
CODECOV_TOKEN              # Code coverage reporting
SONAR_TOKEN               # SonarQube integration
DATADOG_API_KEY           # Application monitoring
```

## Trigger Conditions

### Automatic Triggers
- **Push to main/develop** - Full pipeline execution
- **Pull Requests** - Quality checks and testing (no deployment)
- **Release Published** - Production deployment pipeline

### Manual Triggers
- **workflow_dispatch** - Manual pipeline execution
- **repository_dispatch** - External system triggers

## Branch Strategy

### Main Branch (`main`)
- Production-ready code
- Triggers production deployment on release
- Requires all checks to pass
- Protected branch with required status checks

### Development Branch (`develop`)
- Latest development changes
- Triggers staging deployment
- Integration testing environment
- Feature branch merge target

### Feature Branches
- Individual feature development
- Must pass all quality checks
- Merged via pull request to develop
- Automatic cleanup after merge

## Quality Gates

### Code Quality Requirements
- **Code Coverage**: Minimum 80% for backend, 70% for frontend
- **Linting**: Zero violations allowed
- **Security**: No high-severity vulnerabilities
- **Type Safety**: MyPy validation required

### Testing Requirements
- **Unit Tests**: All critical paths covered
- **Integration Tests**: API and database interactions
- **Security Tests**: Authentication and authorization
- **Performance Tests**: Response time benchmarks

## Deployment Strategy

### Staging Environment
- **Trigger**: Push to develop branch
- **Purpose**: Integration testing and quality assurance
- **URL**: https://phishguard-staging.example.com
- **Database**: Staging PostgreSQL instance
- **Monitoring**: Basic health checks and logs

### Production Environment
- **Trigger**: Release publication
- **Purpose**: Live application serving users
- **URL**: https://phishguard.example.com
- **Database**: Production PostgreSQL cluster
- **Monitoring**: Full observability stack

## Rollback Strategy

### Automatic Rollback
- Failed health checks trigger automatic rollback
- Database migration failures prevent deployment
- Security scan failures block deployment

### Manual Rollback
```bash
# Rollback to previous version
kubectl rollout undo deployment/phishguard-backend -n phishguard-production
kubectl rollout undo deployment/phishguard-frontend -n phishguard-production

# Rollback to specific revision
kubectl rollout undo deployment/phishguard-backend --to-revision=2 -n phishguard-production
```

## Monitoring & Alerting

### Pipeline Monitoring
- **GitHub Actions Dashboard** - Pipeline execution status
- **Slack Notifications** - Deployment success/failure alerts
- **Email Notifications** - Critical failure notifications

### Application Monitoring
- **Health Checks** - Automated endpoint monitoring
- **Performance Metrics** - Response time and throughput
- **Error Tracking** - Application error reporting
- **Security Alerts** - Threat detection notifications

## Maintenance

### Regular Tasks
- **Dependency Updates** - Weekly security and feature updates
- **Image Updates** - Monthly base image refreshes
- **Certificate Renewal** - Automated SSL certificate management
- **Log Cleanup** - Automated log rotation and archival

### Performance Optimization
- **Cache Warming** - Post-deployment cache optimization
- **Database Optimization** - Query performance monitoring
- **CDN Management** - Asset delivery optimization

## Troubleshooting

### Common Issues

#### Build Failures
```bash
# Check build logs
gh run view --log

# Debug specific job
gh run view [RUN_ID] --job [JOB_ID] --log
```

#### Test Failures
```bash
# Run tests locally
pytest tests/ -v --tb=short

# Check test coverage
pytest tests/ --cov=src --cov-report=html
```

#### Deployment Issues
```bash
# Check Kubernetes status
kubectl get pods -n phishguard-production
kubectl describe deployment phishguard-backend -n phishguard-production

# View logs
kubectl logs -f deployment/phishguard-backend -n phishguard-production
```

### Support Contacts
- **Development Team**: developers@phishguard.com
- **DevOps Team**: devops@phishguard.com
- **Security Team**: security@phishguard.com

## Contributing

When contributing to the project:

1. **Fork the repository** and create a feature branch
2. **Follow coding standards** enforced by the pipeline
3. **Write comprehensive tests** for new functionality
4. **Update documentation** for any API changes
5. **Submit pull request** with clear description

All contributions must pass the full CI/CD pipeline before merge approval.

## Security Considerations

### Supply Chain Security
- **Dependency Scanning** - Automated vulnerability detection
- **Image Scanning** - Container security validation
- **SBOM Generation** - Software bill of materials tracking

### Secrets Management
- **GitHub Secrets** - Encrypted secret storage
- **Kubernetes Secrets** - Runtime secret management
- **Secret Rotation** - Regular credential updates

### Access Control
- **Branch Protection** - Required reviews and status checks
- **Environment Protection** - Deployment approval requirements
- **Audit Logging** - Complete deployment audit trail

For detailed implementation guidance, refer to the individual workflow files and deployment documentation.
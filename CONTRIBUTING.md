# Contributing to PhishGuard

Thank you for your interest in contributing to PhishGuard! This document provides guidelines for contributing to this enterprise email security platform.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Contributing Process](#contributing-process)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Security Guidelines](#security-guidelines)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)
- [Community](#community)

## 🤝 Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## 🚀 Getting Started

### Prerequisites

- **Python 3.9+**
- **Node.js 18+**
- **PostgreSQL 13+**
- **Redis 6+**
- **Git**
- **Docker** (recommended for development)

### First Contribution

1. **Fork the repository**
2. **Set up development environment** (see below)
3. **Find a good first issue** - Look for issues labeled `good first issue` or `help wanted`
4. **Make your changes**
5. **Submit a pull request**

## 🛠️ Development Environment

### Local Setup

1. **Clone your fork**
   ```bash
   git clone https://github.com/your-username/phishguard.git
   cd phishguard
   ```

2. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your local configuration
   ```

3. **Backend setup**
   ```bash
   cd src/
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # Development dependencies
   ```

4. **Database setup**
   ```bash
   createdb phishguard_dev
   alembic upgrade head
   ```

5. **Frontend setup**
   ```bash
   cd src/frontend/
   npm install
   ```

6. **Start services**
   ```bash
   # Terminal 1: Backend API
   uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
   
   # Terminal 2: Celery worker
   celery -A tasks.celery_app worker --loglevel=info
   
   # Terminal 3: Frontend
   cd src/frontend && npm run dev
   ```

### Docker Development

```bash
# Start all services
docker-compose -f docker-compose.dev.yml up -d

# View logs
docker-compose logs -f phishguard-api

# Run tests
docker-compose exec phishguard-api pytest
```

## 🔄 Contributing Process

### Branch Naming

Use descriptive branch names that follow this pattern:
- `feature/feature-name` - New features
- `bugfix/issue-description` - Bug fixes
- `hotfix/critical-issue` - Critical production fixes
- `docs/documentation-update` - Documentation changes
- `refactor/component-name` - Code refactoring
- `test/test-description` - Test improvements

### Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
type(scope): subject

body (optional)

footer (optional)
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(detection): add new URL analysis algorithm

Implement advanced heuristic analysis for URL reputation
that improves detection accuracy by 15%.

Closes #123
```

```
fix(quarantine): resolve encryption key rotation issue

The quarantine service was not properly handling key rotation
which caused decryption failures for older files.

Fixes #456
```

### Development Workflow

1. **Create a new branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Write code following our coding standards
   - Add tests for new functionality
   - Update documentation as needed

3. **Test your changes**
   ```bash
   # Run all tests
   pytest src/tests/ -v
   
   # Run specific test categories
   pytest src/tests/test_api_endpoints.py -v
   
   # Check code coverage
   pytest --cov=src --cov-report=html src/tests/
   ```

4. **Lint and format code**
   ```bash
   # Python formatting
   black src/
   isort src/
   
   # Python linting
   flake8 src/
   pylint src/
   
   # JavaScript/TypeScript formatting
   cd src/frontend && npm run lint:fix
   ```

5. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat(component): add new feature"
   ```

6. **Push and create pull request**
   ```bash
   git push origin feature/your-feature-name
   ```

## 📝 Coding Standards

### Python Code Style

- **PEP 8** compliance is required
- Use **Black** for code formatting
- Use **isort** for import sorting
- Maximum line length: **88 characters** (Black default)
- Use **type hints** for all function parameters and return values
- Write **docstrings** for all public functions and classes

**Example:**
```python
from typing import List, Optional
from datetime import datetime

def analyze_email_content(
    content: str, 
    sender: str, 
    timestamp: Optional[datetime] = None
) -> dict:
    """
    Analyze email content for potential threats.
    
    Args:
        content: The email content to analyze
        sender: Email address of the sender
        timestamp: When the email was received
        
    Returns:
        Dictionary containing analysis results with threat score
        
    Raises:
        ValueError: If content is empty or invalid
    """
    if not content.strip():
        raise ValueError("Email content cannot be empty")
    
    # Analysis logic here
    return {
        "threat_score": 0.7,
        "confidence": 0.85,
        "detected_threats": ["suspicious_links"]
    }
```

### JavaScript/TypeScript Code Style

- Use **ESLint** and **Prettier** for formatting
- Follow **Airbnb JavaScript Style Guide**
- Use **TypeScript** for type safety
- Use **functional components** with hooks in React
- Maximum line length: **100 characters**

**Example:**
```typescript
interface EmailAnalysisResult {
  threatScore: number;
  confidence: number;
  detectedThreats: string[];
}

const analyzeEmail = async (
  emailContent: string,
  sender: string
): Promise<EmailAnalysisResult> => {
  if (!emailContent.trim()) {
    throw new Error('Email content cannot be empty');
  }

  const response = await api.post('/analyze', {
    content: emailContent,
    sender,
  });

  return response.data;
};
```

### SQL and Database

- Use **descriptive table and column names**
- Follow **snake_case** naming convention
- Include **proper indexes** for performance
- Use **database migrations** for schema changes
- Write **migration rollback scripts**

### API Design

- Follow **RESTful** principles
- Use **consistent HTTP status codes**
- Implement **proper error responses**
- Include **comprehensive API documentation**
- Use **semantic versioning** for API versions

## 🧪 Testing Guidelines

### Test Structure

```
src/tests/
├── unit/           # Unit tests
├── integration/    # Integration tests
├── e2e/           # End-to-end tests
├── fixtures/      # Test data
└── conftest.py    # Pytest configuration
```

### Writing Tests

- **Test coverage minimum: 80%**
- Use **descriptive test names**
- Follow **AAA pattern** (Arrange, Act, Assert)
- Mock **external dependencies**
- Test **both success and failure cases**

**Example:**
```python
import pytest
from unittest.mock import Mock, patch

class TestEmailAnalysis:
    def test_analyze_email_content_success(self):
        # Arrange
        content = "Click here to claim your prize!"
        sender = "suspicious@example.com"
        
        # Act
        result = analyze_email_content(content, sender)
        
        # Assert
        assert result["threat_score"] > 0.5
        assert "suspicious_links" in result["detected_threats"]
    
    def test_analyze_email_content_empty_content_raises_error(self):
        # Arrange
        content = ""
        sender = "test@example.com"
        
        # Act & Assert
        with pytest.raises(ValueError, match="Email content cannot be empty"):
            analyze_email_content(content, sender)
    
    @patch('src.services.external_api.VirusTotalAPI')
    def test_analyze_email_with_external_api_failure(self, mock_api):
        # Arrange
        mock_api.return_value.scan_url.side_effect = Exception("API Error")
        content = "Check out http://malicious.com"
        sender = "test@example.com"
        
        # Act
        result = analyze_email_content(content, sender)
        
        # Assert
        assert result["threat_score"] > 0  # Should still detect threats
        assert "external_api_error" in result["warnings"]
```

### Frontend Testing

```typescript
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { EmailAnalysisComponent } from './EmailAnalysisComponent';

describe('EmailAnalysisComponent', () => {
  it('should display analysis results when email is analyzed', async () => {
    // Arrange
    const mockAnalyzeEmail = jest.fn().mockResolvedValue({
      threatScore: 0.8,
      detectedThreats: ['phishing'],
    });
    
    render(<EmailAnalysisComponent onAnalyze={mockAnalyzeEmail} />);
    
    // Act
    fireEvent.change(screen.getByLabelText('Email Content'), {
      target: { value: 'Suspicious email content' },
    });
    fireEvent.click(screen.getByText('Analyze'));
    
    // Assert
    await waitFor(() => {
      expect(screen.getByText('Threat Score: 0.8')).toBeInTheDocument();
      expect(screen.getByText('phishing')).toBeInTheDocument();
    });
  });
});
```

## 🔒 Security Guidelines

### Secure Coding Practices

- **Never commit secrets** to version control
- **Validate all user inputs**
- **Use parameterized queries** to prevent SQL injection
- **Implement proper authentication** and authorization
- **Hash passwords** using strong algorithms (bcrypt)
- **Use HTTPS** for all communications
- **Sanitize outputs** to prevent XSS

### Security Testing

- **Test authentication** and authorization flows
- **Validate input sanitization**
- **Check for injection vulnerabilities**
- **Test rate limiting** and abuse prevention
- **Verify encryption** of sensitive data

### Reporting Security Issues

**DO NOT** create public GitHub issues for security vulnerabilities. Instead:

1. Email security@phishguard.com with details
2. Include steps to reproduce the issue
3. Wait for acknowledgment before public disclosure
4. We aim to respond within 24 hours

## 📚 Documentation

### Code Documentation

- **Document all public APIs**
- **Include usage examples**
- **Explain complex algorithms**
- **Document configuration options**
- **Keep documentation up-to-date**

### Documentation Types

1. **API Documentation**: Auto-generated from code
2. **User Guides**: How to use the platform
3. **Developer Guides**: Technical implementation details
4. **Architecture Docs**: System design and decisions
5. **Deployment Guides**: Installation and configuration

## 🔄 Pull Request Process

### Before Submitting

- [ ] **Tests pass** locally
- [ ] **Code is formatted** and linted
- [ ] **Documentation** is updated
- [ ] **Commit messages** follow conventions
- [ ] **Branch is up-to-date** with main

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Security
- [ ] No sensitive data exposed
- [ ] Security implications considered
- [ ] Input validation implemented

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
```

### Review Process

1. **Automated checks** must pass
2. **Code review** by maintainers
3. **Security review** for sensitive changes
4. **Testing** in staging environment
5. **Approval** from code owners

## 🐛 Issue Reporting

### Bug Reports

Use the bug report template and include:

- **Environment details** (OS, Python version, etc.)
- **Steps to reproduce** the issue
- **Expected vs actual behavior**
- **Error messages** and logs
- **Screenshots** if applicable

### Feature Requests

Use the feature request template and include:

- **Problem description** you're trying to solve
- **Proposed solution** or implementation ideas
- **Alternative solutions** considered
- **Use cases** and business value

### Issue Labels

- `bug`: Something isn't working
- `enhancement`: New feature or improvement
- `documentation`: Documentation related
- `good first issue`: Suitable for newcomers
- `help wanted`: Looking for contributors
- `security`: Security-related issue
- `performance`: Performance optimization
- `ui/ux`: User interface/experience

## 🌟 Recognition

Contributors will be recognized in:

- **CONTRIBUTORS.md** file
- **Release notes** for significant contributions
- **Project README** for major features
- **Annual contributor report**

### Contribution Types

We recognize various types of contributions:

- **Code**: New features, bug fixes, improvements
- **Documentation**: Guides, tutorials, API docs
- **Testing**: Test cases, testing infrastructure
- **Design**: UI/UX improvements, graphics
- **Security**: Vulnerability reports, security improvements
- **Community**: Issue triage, code reviews, mentoring

## 💬 Community

### Communication Channels

- **GitHub Discussions**: General questions and discussions
- **Discord**: Real-time chat and community support
- **Email**: security@phishguard.com for security issues
- **Twitter**: @PhishGuard for announcements

### Getting Help

1. **Check existing documentation** first
2. **Search existing issues** for similar problems
3. **Ask in GitHub Discussions** for general questions
4. **Join our Discord** for real-time help
5. **Create an issue** for bugs or feature requests

### Mentorship

New contributors can request mentorship for:

- **First-time contributions**
- **Complex feature development**
- **Understanding codebase architecture**
- **Security best practices**

Contact us on Discord or email to request a mentor.

---

## 📞 Contact

- **Project Maintainers**: [maintainers@phishguard.com](mailto:maintainers@phishguard.com)
- **Security Team**: [security@phishguard.com](mailto:security@phishguard.com)
- **Community**: [Discord Server](https://discord.gg/phishguard)

Thank you for contributing to PhishGuard! Together, we're building a more secure email ecosystem. 🛡️
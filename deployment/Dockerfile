# PhishGuard Development Dockerfile
FROM python:3.11-slim as base

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set work directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY deployment/ ./deployment/

# Create necessary directories
RUN mkdir -p /app/src/quarantine_storage/attachments \
    && mkdir -p /app/src/quarantine_storage/logs \
    && mkdir -p /app/src/quarantine_storage/quarantined_emails

# Production stage
FROM base as production

# Install gunicorn for production
RUN pip install gunicorn

# Copy gunicorn configuration
COPY deployment/gunicorn.conf.py ./

# Create non-root user
RUN useradd --create-home --shell /bin/bash phishguard
RUN chown -R phishguard:phishguard /app
USER phishguard

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose port
EXPOSE 8000

# Start application
CMD ["gunicorn", "--config", "gunicorn.conf.py", "src.api.main:app"]

# Development stage
FROM base as development

# Install development dependencies
RUN pip install pytest pytest-asyncio pytest-cov black isort flake8 mypy

# Start with auto-reload
CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

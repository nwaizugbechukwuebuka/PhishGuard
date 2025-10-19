#!/bin/bash
set -e

# PhishGuard Docker Entrypoint Script
# Handles initialization, migrations, and service startup

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    exit 1
}

# Wait for database to be ready
wait_for_db() {
    log "Waiting for database connection..."
    
    for i in {1..30}; do
        if python -c "
import os
import psycopg2
try:
    conn = psycopg2.connect(
        host=os.getenv('DATABASE_HOST', 'postgres'),
        port=os.getenv('DATABASE_PORT', '5432'),
        user=os.getenv('DATABASE_USER', 'phishguard'),
        password=os.getenv('DATABASE_PASSWORD', 'phishguard'),
        database=os.getenv('DATABASE_NAME', 'phishguard')
    )
    conn.close()
    print('Database is ready!')
except Exception as e:
    print(f'Database not ready: {e}')
    exit(1)
"; then
            log "Database connection established!"
            return 0
        fi
        
        warn "Database not ready yet. Attempt $i/30. Retrying in 5 seconds..."
        sleep 5
    done
    
    error "Database connection failed after 30 attempts"
}

# Wait for Redis to be ready
wait_for_redis() {
    log "Waiting for Redis connection..."
    
    for i in {1..30}; do
        if python -c "
import os
import redis
try:
    r = redis.Redis(
        host=os.getenv('REDIS_HOST', 'redis'),
        port=int(os.getenv('REDIS_PORT', '6379')),
        db=int(os.getenv('REDIS_DB', '0'))
    )
    r.ping()
    print('Redis is ready!')
except Exception as e:
    print(f'Redis not ready: {e}')
    exit(1)
"; then
            log "Redis connection established!"
            return 0
        fi
        
        warn "Redis not ready yet. Attempt $i/30. Retrying in 3 seconds..."
        sleep 3
    done
    
    error "Redis connection failed after 30 attempts"
}

# Run database migrations
run_migrations() {
    log "Running database migrations..."
    
    cd /app
    python -c "
from src.api.database import engine, Base
from src.api.models import user, email, notification, quarantine, simulation, audit_log

try:
    Base.metadata.create_all(bind=engine)
    print('Database tables created successfully!')
except Exception as e:
    print(f'Migration failed: {e}')
    exit(1)
"
    
    log "Database migrations completed!"
}

# Initialize default data
initialize_data() {
    log "Initializing default data..."
    
    python -c "
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.api.models.user import User
from src.api.utils.security import hash_password
import uuid

DATABASE_URL = f\"postgresql://{os.getenv('DATABASE_USER', 'phishguard')}:{os.getenv('DATABASE_PASSWORD', 'phishguard')}@{os.getenv('DATABASE_HOST', 'postgres')}:{os.getenv('DATABASE_PORT', '5432')}/{os.getenv('DATABASE_NAME', 'phishguard')}\"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

try:
    db = SessionLocal()
    
    # Check if admin user exists
    admin_user = db.query(User).filter(User.username == 'admin').first()
    if not admin_user:
        admin_user = User(
            id=str(uuid.uuid4()),
            username='admin',
            email='admin@phishguard.local',
            first_name='System',
            last_name='Administrator',
            role='admin',
            password_hash=hash_password('admin123')[0],
            password_salt=hash_password('admin123')[1],
            is_verified=True
        )
        db.add(admin_user)
        db.commit()
        print('Default admin user created!')
    else:
        print('Admin user already exists')
        
    db.close()
except Exception as e:
    print(f'Data initialization failed: {e}')
    exit(1)
"
    
    log "Default data initialization completed!"
}

# Train initial AI model
train_initial_model() {
    log "Training initial AI model..."
    
    python -c "
try:
    from src.ai_engine.train_model import PhishingModelTrainer
    
    trainer = PhishingModelTrainer()
    # Use sample data for initial training
    trainer.generate_sample_data()
    trainer.train()
    print('Initial AI model trained successfully!')
except Exception as e:
    print(f'Model training failed: {e}')
    print('Continuing without initial model...')
"
    
    log "AI model training completed!"
}

# Start background tasks
start_celery_worker() {
    log "Starting Celery worker in background..."
    celery -A src.tasks.scan_tasks worker --loglevel=info --detach
}

# Health check
health_check() {
    log "Performing health check..."
    
    python -c "
import requests
import time
import sys

for i in range(10):
    try:
        response = requests.get('http://localhost:8000/health', timeout=5)
        if response.status_code == 200:
            print('Health check passed!')
            sys.exit(0)
    except Exception as e:
        print(f'Health check attempt {i+1}/10 failed: {e}')
        time.sleep(2)

print('Health check failed after 10 attempts')
sys.exit(1)
" &
}

# Main execution
main() {
    log "Starting PhishGuard initialization..."
    
    # Set default environment variables
    export PYTHONPATH="/app:$PYTHONPATH"
    
    # Wait for dependencies
    wait_for_db
    wait_for_redis
    
    # Initialize application
    run_migrations
    initialize_data
    train_initial_model
    
    # Start background services
    if [ "$START_CELERY_WORKER" = "true" ]; then
        start_celery_worker
    fi
    
    log "PhishGuard initialization completed successfully!"
    
    # Execute the main command
    exec "$@"
}

# Script entry point
if [ "$1" = "web" ]; then
    main gunicorn -c /app/deployment/gunicorn.conf.py src.api.main:app
elif [ "$1" = "celery-worker" ]; then
    wait_for_db
    wait_for_redis
    exec celery -A src.tasks.scan_tasks worker --loglevel=info
elif [ "$1" = "celery-beat" ]; then
    wait_for_db
    wait_for_redis
    exec celery -A src.tasks.scan_tasks beat --loglevel=info
elif [ "$1" = "migrate" ]; then
    wait_for_db
    run_migrations
elif [ "$1" = "train" ]; then
    wait_for_db
    train_initial_model
else
    # For any other command, run it directly
    exec "$@"
fi

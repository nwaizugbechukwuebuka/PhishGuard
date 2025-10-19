"""
Gunicorn Configuration for PhishGuard Production Deployment
"""

import multiprocessing
import os

# Server socket
bind = "0.0.0.0:8000"
backlog = 2048

# Worker processes
workers = int(os.environ.get("WORKERS", multiprocessing.cpu_count() * 2 + 1))
worker_class = "uvicorn.workers.UvicornWorker"
worker_connections = 1000
timeout = 30
keepalive = 2

# Restart workers
max_requests = 1000
max_requests_jitter = 50
preload_app = True

# Logging
accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("LOG_LEVEL", "info")
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = "phishguard"

# Server mechanics
daemon = False
pidfile = "/tmp/phishguard.pid"
user = None
group = None
tmp_upload_dir = None

# SSL (if enabled)
keyfile = os.environ.get("SSL_KEYFILE")
certfile = os.environ.get("SSL_CERTFILE")

# Environment variables
raw_env = [
    f"DATABASE_URL={os.environ.get('DATABASE_URL', 'postgresql://localhost/phishguard')}",
    f"REDIS_URL={os.environ.get('REDIS_URL', 'redis://localhost:6379')}",
]

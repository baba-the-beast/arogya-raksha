"""
Gunicorn configuration for ArogyaRaksha production deployment.

ARCHITECTURAL MANDATE:
  worker_class MUST be 'sync'.
  Asynchronous worker models (gevent, eventlet) monkey-patch Python's socket and
  threading modules. This causes severe conflicts with PyCryptodome and OpenSSL/cryptography
  C-extensions, risking entropy degradation in AES-256-GCM IV generation and C-level deadlocks.
"""
import os

bind = f"0.0.0.0:{os.getenv('PORT', '5000')}"

# Concurrency: 4 workers by default or (2 * cores + 1)
default_workers = 4
workers = int(os.getenv("WEB_CONCURRENCY", str(default_workers)))

# Worker model: Synchronous workers only
worker_class = "sync"

# Worker lifecycle
timeout = int(os.getenv("GUNICORN_TIMEOUT", "60"))
keepalive = int(os.getenv("GUNICORN_KEEPALIVE", "5"))
max_requests = int(os.getenv("GUNICORN_MAX_REQUESTS", "1000"))
max_requests_jitter = int(os.getenv("GUNICORN_MAX_REQUESTS_JITTER", "50"))

# Logging: Stream to stdout/stderr for container logging collectors
accesslog = "-"
errorlog = "-"
loglevel = os.getenv("LOG_LEVEL", "info")
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" (%(L)ss)'

# Process naming
proc_name = "arogya_gunicorn"

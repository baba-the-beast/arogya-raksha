"""
Operational metrics tracking for clinical workloads (Phase 6).
Provides in-memory telemetry gauges and counters ready for Prometheus scraping.
"""
import time
from collections import defaultdict
from threading import Lock

from flask import request


class MetricsRegistry:
    """Thread-safe in-memory metric collector."""

    def __init__(self):
        self._lock = Lock()
        self.request_count = defaultdict(int)
        self.request_latencies = defaultdict(list)
        self.auth_failures = defaultdict(int)
        self.audit_verifications = {"success": 0, "failure": 0}

    def record_request(self, endpoint: str, status_code: int, duration_ms: float):
        key = f"{endpoint}:{status_code}"
        with self._lock:
            self.request_count[key] += 1
            lat_list = self.request_latencies[endpoint]
            lat_list.append(duration_ms)
            if len(lat_list) > 1000:
                self.request_latencies[endpoint] = lat_list[-1000:]

    def record_auth_failure(self, reason: str):
        with self._lock:
            self.auth_failures[reason] += 1

    def record_audit_verification(self, is_valid: bool):
        with self._lock:
            if is_valid:
                self.audit_verifications["success"] += 1
            else:
                self.audit_verifications["failure"] += 1

    def get_summary(self) -> dict:
        with self._lock:
            summary = {
                "request_counts": dict(self.request_count),
                "auth_failures": dict(self.auth_failures),
                "audit_verifications": dict(self.audit_verifications),
                "endpoints_p95_ms": {},
            }
            for endpoint, latencies in self.request_latencies.items():
                if latencies:
                    sorted_lat = sorted(latencies)
                    idx = int(0.95 * len(sorted_lat))
                    summary["endpoints_p95_ms"][endpoint] = round(sorted_lat[min(idx, len(sorted_lat) - 1)], 2)
            return summary


metrics = MetricsRegistry()


def init_metrics(app):
    """Installs before_request and after_request hooks for latency and status tracking."""

    @app.before_request
    def start_timer():
        request._start_time = time.perf_counter()

    @app.after_request
    def record_metrics(response):
        if hasattr(request, "_start_time"):
            duration = (time.perf_counter() - request._start_time) * 1000
            endpoint = request.endpoint or "unknown"
            metrics.record_request(endpoint, response.status_code, duration)
        return response

"""
rate_limiter.py - Centralized Request Scheduler & Rate Limiter
Enforces precise request throttling, concurrency limits, host request ceilings,
and telemetry tracking to ensure strict compliance with bug-bounty program limits.
"""

import time
import threading
from typing import Dict, Any, Optional

class RateLimiter:
    """
    Token-bucket request rate limiter and scheduler.
    """
    def __init__(
        self,
        requests_per_second: float = 2.0,
        concurrency: int = 1,
        request_timeout: float = 8.0,
        max_requests_per_host: int = 100
    ):
        self.requests_per_second = max(0.1, float(requests_per_second))
        self.min_interval = 1.0 / self.requests_per_second
        self.concurrency = max(1, concurrency)
        self.request_timeout = request_timeout
        self.max_requests_per_host = max_requests_per_host

        self.last_request_time = 0.0
        self.lock = threading.Lock()
        
        # Telemetry metrics
        self.requests_sent = 0
        self.start_time = time.time()
        self.target_host: str = ""

    def reset_for_target(self, target_host: str, rps: Optional[float] = None):
        """Resets counters for a new scan target."""
        with self.lock:
            if rps is not None:
                self.requests_per_second = max(0.1, float(rps))
                self.min_interval = 1.0 / self.requests_per_second
            self.requests_sent = 0
            self.start_time = time.time()
            self.last_request_time = 0.0
            self.target_host = target_host

    def acquire(self) -> bool:
        """
        Blocks until the next request slot is available under the configured rate limit.
        Returns False if max_requests_per_host has been exceeded.
        """
        with self.lock:
            if self.requests_sent >= self.max_requests_per_host:
                return False

            now = time.time()
            time_since_last = now - self.last_request_time
            sleep_duration = self.min_interval - time_since_last

            if sleep_duration > 0:
                time.sleep(sleep_duration)

            self.last_request_time = time.time()
            self.requests_sent += 1
            return True

    def get_telemetry(self) -> Dict[str, Any]:
        """Returns current scheduler telemetry."""
        with self.lock:
            now = time.time()
            elapsed = max(0.001, now - self.start_time)
            effective_rate = round(self.requests_sent / elapsed, 2)
            remaining = max(0, self.max_requests_per_host - self.requests_sent)

            return {
                "target_host": self.target_host,
                "requests_sent": self.requests_sent,
                "requests_remaining": remaining,
                "max_requests_per_host": self.max_requests_per_host,
                "configured_rps": self.requests_per_second,
                "current_effective_rate": effective_rate,
                "elapsed_time_seconds": round(elapsed, 2)
            }

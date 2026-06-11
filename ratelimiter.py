"""Thread-safe token-bucket rate limiter."""

import threading
import time


class TokenBucket:
    def __init__(self, rate: float, per: float = 60.0):
        """
        rate – how many requests are allowed per `per` seconds.
        per  – the window in seconds (default 60).
        """
        self._rate = rate
        self._per = per
        self._tokens = float(rate)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last
        self._last = now
        self._tokens = min(self._rate, self._tokens + elapsed * (self._rate / self._per))

    def wait_and_consume(self) -> None:
        """Block until a token is available, then consume it."""
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                # Calculate wait until next token is available
                deficit = 1 - self._tokens
                wait = deficit * (self._per / self._rate)
            time.sleep(wait)


# Shared limiters – one instance per service used across the entire process
virustotal = TokenBucket(rate=4, per=60)   # 4 req/min (free tier hard limit)
ipapi = TokenBucket(rate=45, per=60)       # 45 req/min (ip-api.com free tier)
abuseipdb = TokenBucket(rate=30, per=60)   # conservative; true limit is 1000/day
shodan = TokenBucket(rate=1, per=2)        # very conservative to protect credits

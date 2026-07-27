"""Flask-middleware: security headers ja yksinkertainen rate limiting.

Security headers:
  Content-Security-Policy (CSP)  — rajoittaa XSS-hyökkäysvektoreita
  X-Content-Type-Options         — estää MIME-sniffing
  X-Frame-Options                — estää clickjacking
  Referrer-Policy                — rajoittaa Referer-otsakkeen lähetystä
  Permissions-Policy             — poistaa turhat selaimen API:t käytöstä

Rate limiting:
  Yksinkertainen in-memory sliding window per IP-osoite.
  Tuotannossa suositellaan Redis-pohjaista ratkaisua (flask-limiter + Redis)
  jos Cloud Run skaalaa useampaan instanssiin.
  Ref: Fielding & Reschke (2022) RFC 9110 §15.5.30 (429 Too Many Requests).
  Ref: OWASP API Security Top 10 (2023) API4:2023 Unrestricted Resource Consumption.
"""
import time
import threading
import logging
from collections import defaultdict, deque
from flask import Flask, request, jsonify

logger = logging.getLogger(__name__)


class SlidingWindowLimiter:
    def __init__(self, limit: int, window: int):
        self._limit = limit
        self._window = window
        self._counts: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def is_limited(self, key: str) -> bool:
        now = time.monotonic()  # monotonic, ei time.time() NTP-hyppyjen välttämiseksi
        with self._lock:
            dq = self._counts[key]
            while dq and now - dq[0] > self._window:
                dq.popleft()
            if not dq:
                self._counts.pop(key, None)
            if len(dq) >= self._limit:
                return True
            dq.append(now)
            return False

_limiter = SlidingWindowLimiter(60, 60)


def register_middleware(app: Flask) -> None:
    """Rekisteröi security header- ja rate limit -middleware Flask-sovellukseen.

    Args:
        app: Flask-sovellus johon middleware rekisteröidään.
    """

    @app.before_request
    def rate_limit_check():
        # Ohitetaan healthz — Cloud Runin health check ei saa saada 429
        if request.path == "/healthz":
            return
        # X-Forwarded-For: Cloud Run asettaa tämän, käytetään ensimmäistä IP:tä
        forwarded_for = request.headers.get("X-Forwarded-For", "")
        ip = forwarded_for.split(",")[0].strip() if forwarded_for else (request.remote_addr or "unknown")
        if _limiter.is_limited(ip):
            logger.warning("Rate limit ylitetty: ip=%s path=%s", ip, request.path)
            return jsonify({"error": "Liian monta pyyntöä — yritä uudelleen hetken kuluttua"}), 429

    @app.after_request
    def add_security_headers(response):
        # CSP: sallitaan vain same-origin skriptit ja tyylit; ei inline-skriptejä.
        # Admin API on JSON-only — selainpohjaisia resursseja ei tarvita.
        # Ref: W3C Content Security Policy Level 3 (2023).
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; "
            "frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        return response

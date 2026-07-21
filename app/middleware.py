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
import random
import threading
import logging
from collections import defaultdict, deque
from flask import Flask, request, jsonify

logger = logging.getLogger(__name__)

# Rate limit -asetukset.
# Muuta RATE_LIMIT_REQUESTS ja RATE_LIMIT_WINDOW tarpeen mukaan.
_RATE_LIMIT_REQUESTS = 60   # max pyyntöä
_RATE_LIMIT_WINDOW   = 60   # sekunteina (sliding window)

# In-memory store: ip -> deque(timestamps)
# HUOM: Ei jaettu Cloud Run -instanssien välillä — jokainen instanssi
# pitää omaa laskuriaan. Tuotannossa käytä flask-limiter + Redis.
_request_counts: dict[str, deque] = defaultdict(deque)
_rate_lock = threading.Lock()


def _is_rate_limited(ip: str) -> bool:
    """Tarkistaa onko IP ylittänyt pyyntörajan.

    Käyttää sliding window -algoritmia: vanhat timestampit poistetaan
    ikkunan ulkopuolelta ennen tarkistusta.

    Args:
        ip: Pyytäjän IP-osoite.

    Returns:
        True jos IP on ylittänyt rajan, False muuten.
    """
    now = time.time()
    with _rate_lock:
        # Satunnainen siivous (1 % pyynnöistä) estämään muistivuotoa (inactive IPs memory leak)
        if random.random() < 0.01:
            for k in list(_request_counts.keys()):
                dq_clean = _request_counts[k]
                while dq_clean and now - dq_clean[0] > _RATE_LIMIT_WINDOW:
                    dq_clean.popleft()
                if not dq_clean:
                    _request_counts.pop(k, None)

        dq = _request_counts[ip]
        # Poista vanhat merkinnät ikkunan ulkopuolelta
        while dq and now - dq[0] > _RATE_LIMIT_WINDOW:
            dq.popleft()
        if len(dq) >= _RATE_LIMIT_REQUESTS:
            return True
        dq.append(now)
        return False


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
        if _is_rate_limited(ip):
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

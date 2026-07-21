"""Falko MDM Server — Flask-sovelluksen sisääntulopiste.

Rekisteröi Blueprintit:
  - checkin_bp  → /checkin        (Apple MDM Check-In)
  - mdm_bp      → /mdm            (Apple MDM Command)
  - admin_bp    → /admin/*        (Admin API, IAP-suojattu)

Cloud Runissa käynnistys tapahtuu Gunicornin kautta (Dockerfile).
Paikallinen ajo: python main.py

Parannus (2026-07): middleware (security headers, rate limiting) rekisteröity.
"""
import os
import logging
from flask import Flask
from app.mdm import mdm_bp
from app.checkin import checkin_bp
from app.admin import admin_bp
from app.middleware import register_middleware

logging.basicConfig(
    level=logging.INFO,
    format='{"time": "%(asctime)s", "level": "%(levelname)s", "name": "%(name)s", "message": "%(message)s"}',
    datefmt="%Y-%m-%dT%H:%M:%S",
)


def create_app() -> Flask:
    """Luo ja palauttaa Flask-sovelluksen konfiguroituna.

    Erillinen tehdasfunktio (factory pattern) helpottaa testausta:
    testit voivat kutsua create_app() ilman sivuvaikutuksia.

    Returns:
        Konfiguroitu Flask-instanssi.
    """
    app = Flask(__name__)
    # SECRET_KEY vaaditaan Flaskin sessioille. MDM-protokolla ei käytä sessioita,
    # mutta Flask vaatii arvon — tuotannossa aseta vahva satunnainen arvo:
    #   openssl rand -base64 32 | gcloud secrets create falko-secret-key --data-file=-
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-me")

    app.register_blueprint(mdm_bp)
    app.register_blueprint(checkin_bp)
    app.register_blueprint(admin_bp)

    register_middleware(app)

    @app.get("/healthz")
    def health():
        """Cloud Runin liveness-tarkistus. Ei vaadi autentikaatiota."""
        return {"status": "ok"}, 200

    return app


app = create_app()

if __name__ == "__main__":
    # Paikallinen ajo kehityskäyttöön. Tuotannossa Gunicorn käynnistää suoraan
    # 'app'-objektin (ks. Dockerfile CMD).
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)  # nosec B104

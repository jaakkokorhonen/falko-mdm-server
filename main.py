"""Falko MDM Server — Flask-sovelluksen sisääntulopiste.

Rekisteröi Blueprintit:
  - checkin_bp  → /checkin        (Apple MDM Check-In)
  - mdm_bp      → /mdm            (Apple MDM Command)
  - admin_bp    → /admin/*        (Admin API, IAP-suojattu)

Cloud Runissa käynnistys tapahtuu Gunicornin kautta (Dockerfile).
Paikallinen ajo: LOCAL_DEV=1 python main.py

Parannus (2026-07): middleware (security headers, rate limiting) rekisteröity.
Korjaus (2026-07): SECRET_KEY-fallback poistettu (SEC-15).
Korjaus (2026-07): LOCAL_DEV-fallback käyttää secrets.token_urlsafe(48) (SEC-15 jätko).
"""
import os
import secrets
import logging
from flask import Flask
from flask_cors import CORS
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

    Raises:
        ValueError: Jos SECRET_KEY-ympäristömuuttuja puuttuu tuotantoympäristössä.
    """
    app = Flask(__name__)
    CORS(
        app,
        resources={r"/admin/*": {"origins": [
            "https://mdm.falko.fi",
            "https://qa.mdm.falko.fi",
            r"https://.*\.web\.app",
            r"https://.*\.firebaseapp\.com",
            r"http://localhost:\d+"
        ]}},
        supports_credentials=True
    )

    # SEC-15: SECRET_KEY ei saa olla kovakoodattu fallback-arvo.
    # Paikallisessa kehityksessä (LOCAL_DEV=1) sallitaan heikko avain —
    # tuotannossa Cloud Run -ympäristömuuttuja on pakollinen.
    # Generoi vahva avain: openssl rand -base64 32
    # Tallenna: gcloud secrets create falko-secret-key --data-file=-
    #
    # SEC-15 jätko: käytetään secrets.token_urlsafe(48) staattisen
    # 'local-dev-only-...' -merkkijonon sijaan. Syä:
    #   1. Staattinen vakio voi vahingossa committautua .env-tiedostoon.
    #   2. Staattinen vakio voi päätyä loggeihin tai virheilmoituksiin.
    #   3. secrets.token_urlsafe(48) tuottaa 64-merkkisen kryptografisesti
    #      vahvan avaimen joka restartin yhteydessä — hyväksyttävää
    #      LOCAL_DEV-ympäristössä jossa sessioiden jatkuvuus ei ole vaatimus.
    _secret_key = os.environ.get("SECRET_KEY", "")
    if not _secret_key:
        if os.environ.get("LOCAL_DEV") == "1":
            _secret_key = secrets.token_urlsafe(48)
            logging.getLogger(__name__).warning(
                "SECRET_KEY puuttuu — generoidaan väliaikainen kehitysavain (LOCAL_DEV=1). "
                "Avain vaihtuu restartin yhteydessä. ÄLÄ käytä tuotannossa."
            )
        else:
            raise ValueError(
                "SECRET_KEY-ympäristömuuttuja on pakollinen tuotannossa. "
                "Aseta se Cloud Run -salaisuutena tai ympäristömuuttujana."
            )
    app.config["SECRET_KEY"] = _secret_key

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
    # Paikallinen ajo kehitystkäyttöön. Tuotannossa Gunicorn käynnistää suoraan
    # 'app'-objektin (ks. Dockerfile CMD).
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)  # nosec B104

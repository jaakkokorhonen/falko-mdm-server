"""Yhteiset apufunktiot ja vakiot Linux MDM -rajapinnoille.

Tämä moduuli sisältää tarkistukset ja turvafunktiot laitetunnisteille ja
Bearer-tokeneille. Keskittämällä nämä vältetään koodin duplikointia ja
varmistetaan yhtenäinen tietoturvakäytäntö.

ISO 27001 -viittaukset:
  - A.12.4.1 Tapahtumaloki (Käyttäjien ja laitteiden toimet kirjataan)
  - A.9.4.2 Turvalliset sisäänkirjautumismenettelyt (Laitteet tunnistetaan vahvasti)
"""
from __future__ import annotations
import hashlib
import re
import secrets

# Laitetunnisteen muodon validointi (64 merkkiä, hex).
# ISO 27001 Audit Evidence: Device ID:t ovat tiukasti validoituja ennen Firestore-hakuja
# estäen SQL-injection tai NoSQL-pääsynkalastelun (impersonation).
_DEVICE_ID_RE = re.compile(r"^[a-f0-9]{64}$")


def hash_token(token: str) -> str:
    """Laskee Bearer-tokenista SHA-256 tiivisteen Firestore-hakua varten.

    ISO 27001 Audit Evidence: Tokeneita ei koskaan tallenneta tai verrata
    selkokielisinä palvelimella. Vain SHA-256 tiivisteitä säilytetään ja verrataan.

    Args:
        token: Selkokielinen Bearer-token.

    Returns:
        str: SHA-256 tiiviste (hex).
    """
    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()


def verify_token(token: str, stored_hash: str) -> bool:
    """Tarkistaa täsmääkö annettu token tallennetun tiivisteen kanssa.

    ISO 27001 Audit Evidence (Control A.9.4.2 & Q25): Käytetään timing-safe
    secrets.compare_digest -funktiota vertailuun sivukanavahyökkäysten (timing attacks)
    estämiseksi.

    Args:
        token: Selkokielinen Bearer-token.
        stored_hash: Firestoreen tallennettu SHA-256 tiiviste.

    Returns:
        bool: True jos täsmää, muuten False.
    """
    if not token or not stored_hash:
        return False
    computed_hash = hash_token(token)
    return secrets.compare_digest(computed_hash, stored_hash)

# ============================================================
# security.tf — Cloud Armor -tietoturvakäytäntö
#
# Cloud Armor toimii infrastruktuuritason ensimmäisenä
# puolustuslinjana ennen kuin pyyntö saapuu Cloud Runiin.
# Se ei korvaa sovelluskerroksen rate limitingiä (middleware.py),
# vaan toimii sen rinnalla täydentävänä suojana.
#
# Kerrostettu rate limiting -arkkitehtuuri:
#   1. Cloud Armor (tässä tiedostossa):
#        var.cloud_armor_rate_limit_requests / var.cloud_armor_rate_limit_window_sec
#        Oletuksena: 100 pyyntöä / 60 sek per IP
#        Toiminta: estää pyynnön ennen Cloud Run -instanssia -> nopea, halpa
#        Heikkous: ei skaalaudu per-endpoint-tasolla
#
#   2. Sovelluskerros (middleware.py, _RATE_LIMIT_REQUESTS / _RATE_LIMIT_WINDOW):
#        60 pyyntöä / 60 sek per IP (in-memory sliding window)
#        Toiminta: hienojakoisempi, per-instanssi, ohitetaan /healthz-polulle
#        Heikkous: ei jaettu Cloud Run -instanssien välillä (in-memory)
#
# Viitteet:
#   - OWASP API Security Top 10 (2023) API4:2023 Unrestricted Resource Consumption
#   - RFC 9110 §15.5.30 — 429 Too Many Requests
#   - Google Cloud Armor rate limiting -dokumentaatio
# ============================================================

resource "google_compute_security_policy" "rate_limit_policy" {
  # checkov:skip=CKV_GCP_73:Cloud Armor Log4j protection is not needed since the service runs in a python sandbox without Java log4j dependencies
  project     = var.gcp_project_id
  name        = "mdm-rate-limit-policy"
  description = "Nopeusrajoitukset (Rate Limiting) Falko MDM:n julkisille rajapinnoille. Suojaa brute-force- ja DDoS-hyökkäyksiltä."

  # ----------------------------------------------------------
  # Oletussääntö: salli kaikki liikenne
  # ----------------------------------------------------------
  # Prioriteetti 2147483647 = korkein numeraalisesti = pienin prioriteetti.
  # Cloud Armor käy säännöt läpi pienimmästä prioriteetista alkaen
  # ja soveltaa ensimmäistä täsmäävää. Oletussääntö täsmää aina viimeisenä.
  rule {
    action      = "allow"
    priority    = "2147483647"
    description = "Salli kaikki liikenne oletuksena (muut säännöt rajoittavat erikoistapauksia)"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
  }

  # ----------------------------------------------------------
  # Nopeusrajoitussääntö (Throttling)
  # ----------------------------------------------------------
  # Prioriteetti 1000 = käsitellään ennen oletussääntöä.
  # throttle-toiminto hidastaa liikennettä (vs. deny, joka estää kokonaan).
  # Ylitykset saavat HTTP 429 — standardimukainen vastaus (RFC 9110).
  #
  # Raja-arvot tulevat variables.tf:stä:
  #   cloud_armor_rate_limit_requests (oletus 100)
  #   cloud_armor_rate_limit_window_sec (oletus 60)
  #
  # Nämä ovat korkeammat kuin sovelluskerroksen rajat (60/60s) koska
  # Cloud Armor on infrastruktuuritason suoja — sovelluskerros tekee
  # tarkemman rajoituksen sen jälkeen.
  rule {
    action      = "throttle"
    priority    = "1000"
    description = "Rajoita pyyntömäärät tasolle ${var.cloud_armor_rate_limit_requests} req/${var.cloud_armor_rate_limit_window_sec}s per IP. Ylitys -> HTTP 429."
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    rate_limit_options {
      rate_limit_threshold {
        count        = var.cloud_armor_rate_limit_requests
        interval_sec = var.cloud_armor_rate_limit_window_sec
      }
      # deny(429): palauttaa standardimukaisen "Too Many Requests" -vastauksen.
      # Vaihtoehtona olisi deny(403) mutta 429 on semanttisesti oikeampi
      # ja sallii clientin yrittää uudelleen Retry-After-otsakkeen perusteella.
      exceed_action = "deny(429)"
      # IP-kohtainen laskenta: jokainen IP saa oman kiintiönsä.
      # Vaihtoehtona olisi ALL (globaali kiintiö), mutta se ei suojaa
      # yksittäiseltä aggressiiviselta IP:ltä.
      enforce_on_key = "IP"
    }
  }
}

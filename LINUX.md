# Falko MDM — Linux Support

This document describes the Linux device management design for Falko MDM, covering both the MVP (minimum viable product) and production-grade architecture.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Firestore Data Model](#firestore-data-model)
4. [MVP Design](#mvp-design)
   - [Enrollment](#enrollment)
   - [Checkin — POST /linux/checkin](#checkin)
   - [Command Poll — PUT /linux/mdm/:device_id](#command-poll)
   - [Admin API Extensions](#admin-api-extensions)
   - [Agent (falko-agent)](#agent-falko-agent)
   - [Security Model (MVP)](#security-model-mvp)
   - [Out of Scope in MVP](#out-of-scope-in-mvp)
5. [Production Design](#production-design)
   - [mTLS Client Certificates (GCP CAS)](#mtls-client-certificates-gcp-cas)
   - [Command Signing (GCP KMS)](#command-signing-gcp-kms)
   - [FCM Push Wake-Up](#fcm-push-wake-up)
   - [Agent Auto-Update (GCS)](#agent-auto-update-gcs)
   - [Multi-Distro Support](#multi-distro-support)
   - [Rate Limiting](#rate-limiting)
   - [Structured Logging and Observability](#structured-logging-and-observability)
   - [Firestore Security Rules](#firestore-security-rules)
   - [Integration Tests and CI](#integration-tests-and-ci)
   - [Agent Hardening and Sandboxing](#agent-hardening-and-sandboxing)
   - [LUKS Disk Encryption Key Escrow](#luks-disk-encryption-key-escrow)
   - [Compliance Monitoring and Drift Detection](#compliance-monitoring-and-drift-detection)
   - [Release Binary Signing](#release-binary-signing)
6. [Endpoint Reference](#endpoint-reference)
7. [Distro Support Matrix](#distro-support-matrix)
8. [Issue Index](#issue-index)

---

## Overview

Falko MDM manages Apple devices via the Apple MDM protocol (mobileconfig, APNs). Linux support adds a parallel management plane for Linux workstations using a polling agent (`falko-agent`) that runs as a systemd service. The protocol is JSON over HTTPS — no plist, no APNs dependency.

The Linux plane reuses the same Firestore database, the same OIDC-protected admin API, and the same Cloud Run deployment. New server modules (`linux_checkin.py`, `linux_mdm.py`) are added alongside the existing Apple modules without modifying them.

---

## Architecture

```
┌─────────────────────────────────────────┐
│  Admin (browser / falko-device-onboarding) │
│  GET /admin/devices?platform=linux        │
│  POST /admin/devices/:id/command?platform=linux │
└───────────────────┬─────────────────────┘
                    │ OIDC (Google)
                    ▼
┌─────────────────────────────────────────┐
│  Cloud Run — falko-mdm-server            │
│  app/linux_checkin.py  POST /linux/checkin │
│  app/linux_mdm.py      PUT  /linux/mdm/:id │
│  app/admin.py          GET/POST /admin/* │
│  app/db.py             Firestore abstraction │
└──────┬──────────────────────────────────┘
       │ Firestore
       ▼
┌─────────────────────────────────────────┐
│  linux_devices/{device_id}               │
│  linux_devices/{device_id}/commands/{id} │
└─────────────────────────────────────────┘
       ▲
       │ HTTPS (Bearer token MVP / mTLS prod)
┌──────┴──────────────────────────────────┐
│  Linux workstation                       │
│  /opt/falko-agent/agent.py  (systemd)    │
│  polls PUT /linux/mdm/:device_id         │
│  reports POST /linux/checkin on startup  │
└─────────────────────────────────────────┘
```

---

## Firestore Data Model

### `linux_devices/{device_id}`

| Field | Type | Description |
|---|---|---|
| `device_id` | string | SHA-256 of `hostname + /etc/machine-id` (64-char hex) |
| `hostname` | string | `socket.gethostname()` |
| `os` | string | `/etc/os-release` `PRETTY_NAME` |
| `kernel` | string | `platform.release()` |
| `arch` | string | `platform.machine()` |
| `cpu` | string | `/proc/cpuinfo` `model name` |
| `ram_gb` | int | Total RAM in GB |
| `ip_local` | string | Primary local IP |
| `enrolled_at` | string | ISO 8601 |
| `last_seen` | string | ISO 8601, updated on every poll |
| `status` | string | `enrolled` \| `unenrolled` |
| `agent_version` | string | Semver of installed agent |
| `token_hash` | string | SHA-256 of device bearer token (MVP) |
| `fcm_token` | string | FCM registration token (prod) |

### `linux_devices/{device_id}/commands/{cmd_id}`

| Field | Type | Description |
|---|---|---|
| `command_type` | string | `ShellCommand`, `GetInventory`, `RebootDevice`, `ShutDownDevice`, `LockScreen`, `InstallPackage` (prod), `RemovePackage` (prod) |
| `payload` | map | Command-specific parameters |
| `status` | string | `pending` \| `sent` \| `acknowledged` \| `error` |
| `created_at` | string | ISO 8601 |
| `output` | string | stdout+stderr from agent (Linux-specific, truncated to 4096 chars) |
| `exit_code` | int | Process exit code |
| `signature` | string | Base64 KMS signature over canonical JSON payload (prod) |

**Required composite index**: `status ASC + created_at ASC` on the `commands` subcollection (add to `terraform/main.tf`).

### `enroll_tokens/{token}`

One-time enrollment tokens. Fields: `used` (bool), `expires_at` (ISO 8601).

### `server_config/linux_agent`

Fields: `min_agent_version`, `latest_agent_version`. Written by CI/CD and `POST /admin/linux/agent_version`.

---

## MVP Design

The MVP delivers the minimal surface to enroll a Linux workstation, receive inventory, and dispatch commands. Complexity deferred to prod is explicitly marked.

### Enrollment

Enrollment is a two-step process:

**Step 1 — Admin generates a one-time token:**
```
POST /admin/linux/enroll_token
Authorization: Bearer <oidc_token>
{"expires_in_hours": 24}
→ {"token": "<one_time_token>", "expires_at": "<ISO8601>"}
```
Token is stored as SHA-256 hash in `enroll_tokens/{token}` in Firestore. Single-use, 24-hour expiry.

**Step 2 — Bootstrap script on the workstation:**
```bash
curl -fsSL https://mdm-api.falko.fi/linux/bootstrap | \
  sudo bash -s -- --token <one_time_token>
```

`scripts/linux-enroll.sh` steps:
1. Verify running as root.
2. Check Python 3.9+.
3. Install agent files to `/opt/falko-agent/`.
4. Create `/etc/falko/` with `chmod 700`.
5. Generate `device_id`: `sha256(hostname + /etc/machine-id)`.
6. `POST /linux/enroll` — exchange one-time token for device token.
7. Write `/etc/falko/device.token` with `chmod 600 root:root`.
8. Write `/etc/falko/agent.conf` (server URL, poll interval).
9. Install and enable `falko-agent.service` systemd unit.
10. Verify with `systemctl is-active falko-agent`.

**`POST /linux/enroll` payload:**
```json
{"device_id": "<sha256hex>", "hostname": "jaakko-thinkpad", "one_time_token": "<token>"}
```
**Response:**
```json
{"device_token": "<32-byte hex>"}
```
Server stores SHA-256 of device token in `linux_devices/{device_id}/token_hash`. Token is returned once, never stored in plaintext.

---

### Checkin

**`POST /linux/checkin`**
```
Authorization: Bearer <device_token>
Content-Type: application/json
```

Request body:
```json
{
  "message_type": "Authenticate" | "CheckOut",
  "device_id": "<sha256hex>",
  "hostname": "jaakko-thinkpad",
  "os": "Ubuntu 24.04.2 LTS",
  "kernel": "6.8.0-60-generic",
  "arch": "x86_64",
  "cpu": "Intel Core i7-1185G7",
  "ram_gb": 16,
  "ip_local": "192.168.1.42",
  "agent_version": "0.1.0"
}
```

Behaviour:
- `Authenticate`: upserts `linux_devices/{device_id}` via `db.upsert_linux_device()`. Sets `status: enrolled`.
- `CheckOut`: sets `status: unenrolled`. Does not delete the document.
- `device_id` validated against `^[a-f0-9]{64}$` before any Firestore write.
- Token verified against `linux_devices/{device_id}/token_hash` (SHA-256 comparison).

Responses: `200 {}` on success, `400` on validation error, `401` on bad token.

---

### Command Poll

**`PUT /linux/mdm/:device_id`**
```
Authorization: Bearer <device_token>
Content-Type: application/json
```

Agent polls this endpoint every N seconds (default 900 s). Protocol:

1. Agent sends PUT with optional result of previous command.
2. Server acks previous command (`db.ack_linux_command()`).
3. Server updates `last_seen`.
4. Server dequeues next pending command (`db.dequeue_linux_command()`).
5. Returns the command, or `{}` if queue empty.

**Request body (reporting result):**
```json
{
  "command_id": "<id>",
  "status": "acknowledged" | "error",
  "output": "<stdout+stderr, max 4096 chars>",
  "exit_code": 0
}
```

**Response (command queued):**
```json
{
  "command_id": "<id>",
  "command_type": "ShellCommand",
  "payload": {"command": "apt-get update -y"}
}
```

**Response (no command):** `200 {}`

Status values: `sent`, `acknowledged`, `error`. `NotNow` does not apply to Linux.

---

### Admin API Extensions

All existing `/admin/*` endpoints remain OIDC-protected. Linux devices are served by the same routes via a `?platform=` parameter.

| Endpoint | Change |
|---|---|
| `GET /admin/devices` | Default `platform=apple` (no breaking change). `?platform=linux` or `?platform=all` supported. Each device has a `platform` field. |
| `POST /admin/devices/:id/command` | Accepts `?platform=linux`. Routes to `db.enqueue_linux_command()`. Validates `command_type` against `LINUX_COMMAND_TYPES`. |
| `POST /admin/devices/:id/push` | MVP: returns `200 {"status": "polling", "message": "Linux devices poll on interval, no push available in MVP"}`. |
| `POST /admin/linux/enroll_token` | New. Generates one-time enrollment token. |

**`LINUX_COMMAND_TYPES` (MVP):**
```python
{"ShellCommand", "GetInventory", "RebootDevice", "ShutDownDevice", "LockScreen"}
```

---

### Agent (falko-agent)

Lives in `agent/` directory. Runs as a systemd service (`root`). No dependencies beyond `requests` and stdlib.

**Directory layout:**
```
agent/
├── agent.py          # main poll loop
├── executor.py       # command dispatch
├── inventory.py      # hardware/OS info collection
├── config.py         # reads /etc/falko/agent.conf + env overrides
├── requirements.txt  # requests only
└── falko-agent.service
```

**agent.py poll loop:**
```
startup → POST /linux/checkin
loop:
  PUT /linux/mdm/:device_id (with optional previous result)
  if command received → executor.dispatch(command)
  sleep(POLL_INTERVAL)  # default 900 s
  on any error → log, sleep, retry (never crash process)
  on 401 → log error, back off (do not retry storm)
  on 5xx → exponential backoff up to 10 min
```

**executor.py command dispatch (MVP):**

| `command_type` | Implementation |
|---|---|
| `ShellCommand` | `subprocess.run(payload["command"], shell=True, capture_output=True, timeout=300)` — stdout+stderr truncated to 4096 chars |
| `GetInventory` | `inventory.collect()` — no subprocess |
| `RebootDevice` | `subprocess.run(["systemctl", "reboot"])` |
| `ShutDownDevice` | `subprocess.run(["systemctl", "poweroff"])` |
| `LockScreen` | `subprocess.run(["loginctl", "lock-sessions"])` — best-effort |

All commands return `{"status": "acknowledged"|"error", "output": str, "exit_code": int}`.

**inventory.py fields:**
`hostname`, `device_id`, `os` (from `/etc/os-release`), `kernel` (`platform.release()`), `arch`, `cpu` (`/proc/cpuinfo`), `ram_gb`, `ip_local`, `agent_version`.

**config.py:**

| Key | Env var | Default |
|---|---|---|
| `server_url` | `FALKO_SERVER_URL` | `https://mdm-api.falko.fi` |
| `poll_interval` | `FALKO_POLL_INTERVAL` | `900` |
| `token_path` | `FALKO_TOKEN_PATH` | `/etc/falko/device.token` |
| `log_level` | `FALKO_LOG_LEVEL` | `INFO` |
| `conf_path` | `FALKO_CONF_PATH` | `/etc/falko/agent.conf` |

**falko-agent.service:**
```ini
[Unit]
Description=Falko MDM Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=falko
Group=falko
ExecStart=/usr/bin/python3 /opt/falko-agent/agent.py
Restart=on-failure
RestartSec=60
EnvironmentFile=-/etc/falko/agent.env
ReadOnlyPaths=/
ReadWritePaths=/opt/falko-agent /etc/falko /tmp
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

---

### Security Model (MVP)

- **Device auth**: Static bearer token. Random 32-byte hex (`secrets.token_hex(32)`), written to `/etc/falko/device.token` (`chmod 600 root:root`). Server stores SHA-256 hash only. Token returned once at enrollment — never stored in plaintext on the server.
- **One-time enrollment tokens**: Single-use, 24-hour expiry. SHA-256 hash stored. Marked `used: true` on consumption. `403` on reuse or expiry.
- **Admin auth**: Existing Google OIDC + Firestore access control. No change.
- **TLS**: Bootstrap script validates server TLS cert (no `-k`). Agent uses `requests` default CA bundle.
- **Token path permissions**: `/etc/falko/` is `chmod 700 root:root`. `device.token` is `chmod 600 root:root`.
- **Tokens never logged.**

---

### Out of Scope in MVP

These items are explicitly deferred to the production phase (see [Production Design](#production-design)):

- mTLS client certificate authentication
- GCP KMS command signing
- FCM push wake-up (agent polls on interval)
- Agent auto-update mechanism
- `dnf` / `zypper` package manager support (apt/Ubuntu only in MVP)
- `InstallPackage` / `RemovePackage` command types
- Redis-backed distributed rate limiting
- Structured JSON logging to Cloud Logging
- Firestore security rules for `linux_devices`
- End-to-end integration test suite
- Windows or macOS agent

---

## Production Design

Production graduation requires all items below. Each maps to a `Linux-prod` GitHub issue.

### mTLS Client Certificates (GCP CAS)

**Issue: [#45](https://github.com/jaakkokorhonen/falko-mdm-server/issues/45)**

Replace static bearer tokens with mutual TLS using GCP Certificate Authority Service (CAS). Short-lived certificates (30-day) bound to the TLS channel cannot be replayed from a different machine, eliminating the stolen-token attack vector.

**Flow:**
1. At enrollment, agent generates a P-256 key pair and a CSR with `CN=<device_id>`.
2. `POST /linux/enroll` accepts CSR + one-time token, calls GCP CAS `CreateCertificate`, returns signed PEM.
3. Agent writes `/etc/falko/device.crt` and `/etc/falko/device.key` (`chmod 600 root:root`).
4. All subsequent requests use the client certificate for mTLS.
5. Cloud Run LB passes `X-Client-Cert-Dn` header after successful mTLS handshake. `middleware.require_device_cert()` replaces `verify_device_token()`.

**Renewal:** Agent checks expiry at startup and daily. If expiry < 7 days: auto-renew via `POST /linux/enroll/renew` (mTLS-authenticated).

**Revocation:** `POST /admin/devices/:id/revoke` calls GCP CAS `RevokeCertificate`.

**Migration from MVP:** Existing bearer-token-enrolled devices re-enroll via new one-time tokens. Feature flag `FALKO_AUTH_MODE=bearer|mtls` preserves backward compatibility during migration.

**GCP CAS Terraform:** `google_privateca_ca_pool` + `google_privateca_certificate_authority` (`EC_P256_SHA256`, `europe-north1`).

---

### Command Signing (GCP KMS)

**Issue: [#44](https://github.com/jaakkokorhonen/falko-mdm-server/issues/44)**

Sign all Linux command payloads with a GCP KMS asymmetric key (`EC_SIGN_P256_SHA256`). Agent verifies the signature before executing. This prevents a compromised server credential from issuing arbitrary `ShellCommand` payloads.

**Server-side (enqueue):**
1. Serialize `payload` to canonical JSON (sorted keys, no whitespace).
2. Call KMS `AsymmetricSign`.
3. Store `signature` (base64 DER) in Firestore command document.
4. Return `signature` field in poll response.

**Agent-side (before execute):**
1. Reconstruct canonical JSON of `payload`.
2. Verify `signature` with cached public key (fetched from `GET /linux/command-signing-pubkey`).
3. If invalid: ack with `error`, output `signature_invalid`, do not execute.

**Public key distribution:** `GET /linux/command-signing-pubkey` — unauthenticated, returns current PEM. Agent caches and re-fetches on `404` (key rotation).

**Optional `ShellCommand` policy:** Firestore flag `linux_settings/shell_command_policy` (`disabled|allowlist|any`). Default `any`. Set to `allowlist` in prod with allowed command patterns in `linux_settings/shell_command_allowlist`.

**KMS Terraform:** `google_kms_key_ring` + `google_kms_crypto_key` (`ASYMMETRIC_SIGN`, `EC_SIGN_P256_SHA256`). Cloud Run SA gets `roles/cloudkms.signerVerifier` on this key only.

---

### FCM Push Wake-Up

**Issue: [#46](https://github.com/jaakkokorhonen/falko-mdm-server/issues/46)**

Integrate Firebase Cloud Messaging to reduce command latency from ≤900 s (poll interval) to <5 s.

**Flow:**
1. At checkin, agent registers with FCM and sends `fcm_token` in `POST /linux/checkin` payload.
2. Server stores `fcm_token` on `linux_devices/{device_id}`.
3. After `enqueue_linux_command()`, server calls `app/fcm.push_linux_device(fcm_token, device_id)`.
4. Agent FCM listener receives message, sets `threading.Event` to wake the poll loop immediately.

**Failure handling:** FCM push failure (missing token, network error, invalid token) is logged but does not fail the enqueue. The poll loop is always the authoritative delivery path.

**`POST /admin/devices/:id/push?platform=linux`** (stub → real): returns `{"status": "pushed", "fcm_message_id": "..."}` or `{"status": "no_fcm_token"}`.

**FCM token rotation:** Agent handles `messaging.UnregisteredError` (forwarded as flag in next poll response) and re-registers.

---

### Agent Auto-Update (GCS)

**Issue: [#47](https://github.com/jaakkokorhonen/falko-mdm-server/issues/47)**

Agents update themselves without re-enrollment or manual access. Server advertises the required version in every poll response.

**Poll response extension:**
```json
{"server_meta": {"min_agent_version": "1.2.0", "latest_agent_version": "1.3.1"}}
```
Included even when command queue is empty. Server reads from `Firestore server_config/linux_agent`.

**Agent update flow:**
1. Compare `latest_agent_version` to own `agent.__version__`.
2. If `latest > current` or `current < min_required`: download tarball from GCS.
3. Verify SHA-256 checksum against `falko-agent-{version}.sha256` in bucket.
4. Atomic swap: extract to `/opt/falko-agent-new/`, then `mv` backup, `mv` new to `/opt/falko-agent`.
5. `systemctl restart falko-agent`.

**Rollback:** Watchdog systemd timer (every 5 min) detects stopped agent and restores backup.

**GCS bucket structure:**
```
falko-agent-releases/
  falko-agent-{version}.tar.gz
  falko-agent-{version}.sha256
  latest   ← plain text, current version
```

**CI/CD:** `release-agent.yml` GitHub Actions workflow: bump version → build tarball → compute SHA-256 → upload to GCS → update `latest` → update `Firestore server_config/linux_agent`.

**Admin endpoint:** `POST /admin/linux/agent_version` (OIDC) — writes `min_agent_version` + `latest_agent_version` to Firestore.

---

### Multi-Distro Support

**Issue: [#49](https://github.com/jaakkokorhonen/falko-mdm-server/issues/49)**

Extend `agent/executor.py` and `agent/inventory.py` beyond Ubuntu to support Debian, Fedora/RHEL/Rocky, and openSUSE.

**Package manager detection (at agent startup):**
```python
for pm in ("apt-get", "dnf", "zypper"):
    if shutil.which(pm):
        PACKAGE_MANAGER = pm; break
```

**New command types added to prod:**
- `InstallPackage`: `payload.package` validated against `^[a-zA-Z0-9._+-]+$`. Runs the correct PM install command.
- `RemovePackage`: same validation, runs PM remove command.

**CI matrix:** `.github/workflows/agent-distro-matrix.yml` — runs `agent/tests/` on Ubuntu 22.04, Ubuntu 24.04, Debian 12, Fedora 40, Rocky Linux 9, openSUSE Leap 15.6.

---

### Rate Limiting

**Issue: [#48](https://github.com/jaakkokorhonen/falko-mdm-server/issues/48)**

Two-layer rate limiting for `/linux/*` endpoints (not behind Google IAP).

**Cloud Armor rules (Terraform):**

| Path | Limit | Action |
|---|---|---|
| `/linux/*` | 10 req/min per IP | `deny(429)`, 5-min ban |
| `/linux/enroll` | 3 req/min per IP | `deny(429)`, 10-min ban |

**Application-layer per `device_id` limiter** in `app/middleware.py`: in-process sliding window (10 req/60 s). For multi-instance deployments, replace with Cloud Memorystore (Redis) backed counter.

**`429` response:**
```json
{"error": "rate_limited", "retry_after_seconds": 60}
```

Agent backoff on `429`: min 60 s, exponential up to 10 min.

**Cloud Monitoring alert:** `429` rate > 50/min on `/linux/*` paths.

---

### Structured Logging and Observability

**Issue: [#50](https://github.com/jaakkokorhonen/falko-mdm-server/issues/50)**

All Linux server modules emit structured JSON logs compatible with Cloud Logging. All agent logs include `device_id` and `agent_version` as structured fields.

See the linked issue for full spec.

---

### Firestore Security Rules

**Issue: [#51](https://github.com/jaakkokorhonen/falko-mdm-server/issues/51)**

`linux_devices` collection must be locked down to the Cloud Run service account. Direct client writes must be denied. Security rules enforced and tested in CI.

See the linked issue for full spec.

---

### Integration Tests and CI

**Issue: [#52](https://github.com/jaakkokorhonen/falko-mdm-server/issues/52)**

End-to-end integration tests covering the full Linux lifecycle (enroll → checkin → command → ack) against a local Firestore emulator. Running in CI on every push to `main`.

See the linked issue for full spec.

---

### Agent Hardening and Sandboxing

**Issue: [Draft]**

Run agent commands in a sandboxed, least-privilege context. Harden the systemd service unit file with security directives (such as `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=true`, `CapabilityBoundingSet`) to limit access, and run commands as a separate unprivileged user where possible.

---

### LUKS Disk Encryption Key Escrow

**Issue: [Draft]**

Implement LUKS recovery key escrow. Workstations must securely generate and escrow LUKS recovery keys to Falko MDM server at enrollment. The server encrypts these keys with a GCP KMS key before storing them in Firestore, ensuring that only authorized administrators can decrypt them in a break-glass scenario.

---

### Compliance Monitoring and Drift Detection

**Issue: [Draft]**

Define compliance policies (e.g., firewall status, disk encryption, required software packages) on the server. The agent audits its configuration against these policies on a regular schedule and reports compliance status, with automatic remediation of drift when enabled.

---

### Release Binary Signing

**Issue: [Draft]**

Digitally sign agent release tarballs before GCS upload. The bootstrap script and agent auto-updater must verify the digital signature using a pinned public key before extracting and running the update. This guarantees binary integrity even if the GCS bucket or DNS is compromised.

---

## Endpoint Reference

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/linux/enroll` | One-time token | Exchange enrollment token for device token (MVP) / issue mTLS cert (prod) |
| `POST` | `/linux/checkin` | Device token / mTLS | Register or re-register device, update inventory |
| `PUT` | `/linux/mdm/:device_id` | Device token / mTLS | Poll for commands, report previous result |
| `GET` | `/linux/command-signing-pubkey` | None | Return KMS public key PEM (prod) |
| `POST` | `/linux/enroll/renew` | mTLS | Renew client certificate (prod) |
| `GET` | `/admin/devices?platform=linux` | OIDC | List Linux devices |
| `GET` | `/admin/devices?platform=all` | OIDC | List all devices (Apple + Linux) |
| `POST` | `/admin/devices/:id/command?platform=linux` | OIDC | Enqueue command |
| `POST` | `/admin/devices/:id/push?platform=linux` | OIDC | FCM push wake-up (prod) |
| `POST` | `/admin/devices/:id/revoke` | OIDC | Revoke mTLS certificate (prod) |
| `POST` | `/admin/linux/enroll_token` | OIDC | Generate one-time enrollment token |
| `POST` | `/admin/linux/agent_version` | OIDC | Set min/latest agent version in Firestore (prod) |

---

## Distro Support Matrix

| Distro | Package manager | MVP | Prod |
|---|---|---|---|
| Ubuntu 22.04 | apt | ✅ | ✅ |
| Ubuntu 24.04 | apt | ✅ | ✅ |
| Debian 12 | apt | — | ✅ |
| Fedora 40+ | dnf | — | ✅ |
| RHEL 9 / Rocky Linux 9 | dnf | — | ✅ |
| openSUSE Leap 15.6 | zypper | — | ✅ |

---

## Issue Index

### Linux MVP

| # | Title |
|---|---|
| [#38](https://github.com/jaakkokorhonen/falko-mdm-server/issues/38) | `linux_checkin.py` — POST /linux/checkin endpoint |
| [#39](https://github.com/jaakkokorhonen/falko-mdm-server/issues/39) | `linux_mdm.py` — PUT /linux/mdm/:device_id command poll |
| [#40](https://github.com/jaakkokorhonen/falko-mdm-server/issues/40) | `falko-agent` — Python systemd daemon |
| [#41](https://github.com/jaakkokorhonen/falko-mdm-server/issues/41) | `db.py` — Firestore functions for linux_devices |
| [#42](https://github.com/jaakkokorhonen/falko-mdm-server/issues/42) | `admin.py` — extend /admin/devices for Linux |
| [#43](https://github.com/jaakkokorhonen/falko-mdm-server/issues/43) | Enrollment bootstrap script |

### Linux Prod

| # | Title |
|---|---|
| [#44](https://github.com/jaakkokorhonen/falko-mdm-server/issues/44) | Command signing with GCP KMS |
| [#45](https://github.com/jaakkokorhonen/falko-mdm-server/issues/45) | mTLS client certificates via GCP CAS |
| [#46](https://github.com/jaakkokorhonen/falko-mdm-server/issues/46) | FCM push wake-up |
| [#47](https://github.com/jaakkokorhonen/falko-mdm-server/issues/47) | Agent auto-update via GCS |
| [#48](https://github.com/jaakkokorhonen/falko-mdm-server/issues/48) | Rate limiting — Cloud Armor + middleware |
| [#49](https://github.com/jaakkokorhonen/falko-mdm-server/issues/49) | Multi-distro support |
| [#50](https://github.com/jaakkokorhonen/falko-mdm-server/issues/50) | Structured logging and observability |
| [#51](https://github.com/jaakkokorhonen/falko-mdm-server/issues/51) | Firestore security rules for linux_devices |
| [#52](https://github.com/jaakkokorhonen/falko-mdm-server/issues/52) | Integration tests and CI for Linux endpoints |
| [Draft] | Systemd hardening and sandboxing for falko-agent |
| [Draft] | LUKS disk encryption recovery key escrow |
| [Draft] | Compliance monitoring and configuration drift detection |
| [Draft] | Release binary signing and verification in agent auto-update |


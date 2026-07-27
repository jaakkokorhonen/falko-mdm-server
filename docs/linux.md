# Linux MDM — Design Document

This document defines the architecture and scope for Linux workstation management in `falko-mdm-server`. It is divided into two phases: **MVP** (functional parity with Apple MDM polling model) and **Production** (security hardening, reliability, multi-distro, observability).

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [MVP Scope](#mvp-scope)
3. [Production Scope](#production-scope)
4. [Out of Scope (both phases)](#out-of-scope)
5. [Firestore Schema](#firestore-schema)
6. [API Reference](#api-reference)
7. [Agent Configuration](#agent-configuration)
8. [Security Model](#security-model)

---

## Architecture Overview

```
Linux Workstation
  │
  ├── POST /linux/checkin    → Register / re-register device on agent start
  └── PUT  /linux/mdm/<id>  → Poll for commands (interval-based, default 900 s)

Admin (OIDC-protected: Google OAuth2 ID Token + Firestore ACL)
  └── GET/POST /admin/devices?platform=linux   → Device listing + command dispatch
      POST /admin/linux/enroll_token           → Issue one-time enrollment tokens

Google Cloud Run ──► Firestore
                       ├── linux_devices/{device_id}/
                       │       ├── device metadata
                       │       └── commands/{id}  ← command queue
                       └── enroll_tokens/{token}  ← one-time enrollment tokens
```

The Linux model differs from Apple MDM in one fundamental way: Apple uses APNs for server-initiated push; Linux uses **agent-side polling**. The server queues commands in Firestore; the agent fetches them on its next poll cycle. In the production phase this is supplemented by FCM for near-instant dispatch.

---

## MVP Scope

Issues: [#38][i38] [#39][i39] [#40][i40] [#41][i41] [#42][i42] [#43][i43]

[i38]: https://github.com/jaakkokorhonen/falko-mdm-server/issues/38
[i39]: https://github.com/jaakkokorhonen/falko-mdm-server/issues/39
[i40]: https://github.com/jaakkokorhonen/falko-mdm-server/issues/40
[i41]: https://github.com/jaakkokorhonen/falko-mdm-server/issues/41
[i42]: https://github.com/jaakkokorhonen/falko-mdm-server/issues/42
[i43]: https://github.com/jaakkokorhonen/falko-mdm-server/issues/43

### Server-side modules

| Module | Issue | Description |
|---|---|---|
| `app/linux_checkin.py` | [#38][i38] | `POST /linux/checkin` — device registration |
| `app/linux_mdm.py` | [#39][i39] | `PUT /linux/mdm/<device_id>` — command poll |
| `app/db.py` (extend) | [#41][i41] | Firestore functions for `linux_devices` collection |
| `app/admin.py` (extend) | [#42][i42] | `?platform=linux\|all` filter on `/admin/devices` |
| `app/linux_enroll.py` | [#43][i43] | `POST /linux/enroll` — one-time token exchange |

### Agent (`agent/`)

| File | Issue | Description |
|---|---|---|
| `agent/agent.py` | [#40][i40] | Main poll loop + checkin on startup |
| `agent/executor.py` | [#40][i40] | Command dispatch: `ShellCommand`, `GetInventory`, `RebootDevice`, `ShutDownDevice`, `LockScreen` |
| `agent/inventory.py` | [#40][i40] | Hardware/OS info via stdlib only |
| `agent/config.py` | [#40][i40] | INI config + env var overrides |
| `agent/falko-agent.service` | [#40][i40] | systemd unit (`Restart=on-failure`, `RestartSec=60`) |

### Enrollment

| Step | Description |
|---|---|
| Admin issues one-time token | `POST /admin/linux/enroll_token` → returns 24 h token |
| Bootstrap script runs on workstation | `curl … \| sudo bash -s -- --token <TOKEN>` |
| Script exchanges token for device token | `POST /linux/enroll` → writes `/etc/falko/device.token` |
| Agent starts | `systemctl enable --now falko-agent` |
| First checkin | Agent POSTs `POST /linux/checkin` with full hardware inventory |

### MVP Command Set

| `command_type` | Mechanism | Notes |
|---|---|---|
| `ShellCommand` | `subprocess.run(shell=True, timeout=300)` | Output capped at 4096 chars |
| `GetInventory` | `inventory.py` in-process | Returns full hardware snapshot |
| `RebootDevice` | `systemctl reboot` | Agent stops after this |
| `ShutDownDevice` | `systemctl poweroff` | Agent stops after this |
| `LockScreen` | `loginctl lock-sessions` | Best-effort on headless |

### MVP Constraints (by design)

- Poll interval is fixed at config time — no server-initiated push (FCM is prod scope)
- `apt` only — no `dnf`/`zypper` package manager abstraction
- Ubuntu 22.04 / 24.04 only — no multi-distro testing
- No agent auto-update mechanism
- No command signing — `ShellCommand` payload is trusted as-is from server
- No rate limiting on `/linux/checkin` and `/linux/mdm/*` endpoints
- No stale device detection or alerting
- Device token is a static bearer secret — no rotation

---

## Production Scope

### Security hardening

| Item | Description |
|---|---|
| Command signing | Admin signs command payload with GCP KMS asymmetric key; agent verifies before execution. Prevents arbitrary RCE via compromised server credentials. |
| Device token rotation | Tokens auto-rotate every 30 days. Agent fetches new token on next successful poll; server invalidates old token after grace period. |
| Rate limiting on device endpoints | Cloud Armor or middleware: max 10 req/min per `device_id` on `/linux/checkin` and `/linux/mdm/*`. |
| mTLS for agent–server channel | Agent presents a client certificate (issued at enrollment via GCP Certificate Authority Service). Replaces bearer token auth entirely. |
| `ShellCommand` allowlist | Optionally restrict allowed shell commands to an admin-defined allowlist in Firestore. `ShellCommand` blocked by default; must be explicitly enabled per device or device group. |

### Reliability

| Item | Description |
|---|---|
| FCM push wake-up | Agent registers FCM token at checkin. Server sends FCM message after enqueueing command. Agent wakes immediately instead of waiting up to 900 s. |
| Agent auto-update | Server advertises latest agent version in poll response. If `agent_version` < `min_required_version`, agent downloads and self-updates from GCS bucket. |
| Command retry logic | `NotNow`-equivalent: if agent responds `error` with `retryable: true`, server returns command to `pending` state for re-delivery on next poll. |
| Stale device alerting | Cloud Monitoring log-based alert if `last_seen` > 24 h for any enrolled device. |
| Dead-letter queue | Commands stuck in `sent` state for > 1 h (agent never acked) are moved to `dead_letter` status and trigger an alert. |

### Multi-distro support

| Item | Description |
|---|---|
| Package manager abstraction | `executor.py` detects distro family (`apt`/`dnf`/`zypper`) and maps `InstallPackage` command to the correct binary. |
| Distro support matrix | Ubuntu 22.04, 24.04; Debian 12; Fedora 40+; RHEL/Rocky 9 |
| CI matrix | GitHub Actions test matrix across distros using Docker containers |

### Observability

| Item | Description |
|---|---|
| BigQuery audit log | All Linux device commands (enqueue, ack, error) exported to BigQuery via existing Log Sink infrastructure. |
| Cloud Monitoring dashboard | Linux device count, stale devices, command queue depth, error rate — mirroring Apple MDM monitoring. |
| `agent_version` drift metric | Alert if >10% of enrolled Linux devices are running agent version older than N-1. |

### Terraform additions

| Resource | Description |
|---|---|
| GCS bucket `falko-agent-releases` | Stores versioned agent tarballs for auto-update. |
| GCP Certificate Authority Service | Issues short-lived client certificates for mTLS. |
| Cloud Monitoring alerts (Linux) | Stale device, dead-letter queue, agent version drift. |
| Firestore indexes (Linux) | `linux_devices` pagination index; `enroll_tokens` expiry index. |

---

## Out of Scope (both phases)

These items are explicitly not planned for either MVP or production in this repo:

- **Windows agent** — no MDM protocol or agent for Windows workstations
- **macOS agent** — macOS is managed via Apple MDM protocol (existing implementation); a separate agent is not needed
- **Mobile device management for Linux** — this covers only workstations/servers, not Android or embedded Linux
- **GUI admin interface** — admin interaction is via the existing API (see `falko-device-onboarding` repo)
- **Configuration management (Ansible/Chef/Puppet replacement)** — `ShellCommand` + `RunScript` cover ad-hoc needs; systematic config management is out of scope
- **Full disk encryption management** — no LUKS key escrow or enforcement
- **Software inventory / compliance scanning beyond `GetInventory`** — no CVE scanning or installed package auditing
- **Network access control (NAC)** — no 802.1X or VPN integration
- **Multi-tenant / multi-org support** — single-organization deployment only

---

## Firestore Schema

### `linux_devices/{device_id}`

```
device_id:      string  — sha256(hostname + /etc/machine-id), 64-char hex
hostname:       string  — e.g. "jaakko-thinkpad"
os:             string  — e.g. "Ubuntu 24.04.2 LTS"
kernel:         string  — e.g. "6.8.0-60-generic"
arch:           string  — e.g. "x86_64"
cpu:            string  — e.g. "Intel Core i7-1185G7"
ram_gb:         integer — total physical RAM in GB
ip_local:       string  — primary local IPv4
enrolled_at:    string  — ISO 8601
last_seen:      string  — ISO 8601, updated on every poll
status:         string  — "enrolled" | "unenrolled"
agent_version:  string  — semver, e.g. "0.1.0"
token_hash:     string  — SHA-256 of the device bearer token (never store plaintext)
fcm_token:      string  — (prod) FCM registration token
cert_serial:    string  — (prod) mTLS client certificate serial
```

### `linux_devices/{device_id}/commands/{cmd_id}`

```
command_type:  string  — e.g. "ShellCommand"
payload:       map     — command-specific params (e.g. {"command": "df -h"})
status:        string  — "pending" | "sent" | "acknowledged" | "error" | "dead_letter"
created_at:    string  — ISO 8601
sent_at:       string  — ISO 8601, set when dequeued
acked_at:      string  — ISO 8601, set on ack
output:        string  — stdout+stderr from agent, capped 4096 chars
exit_code:     integer — process exit code
signature:     string  — (prod) KMS signature of payload
```

### `enroll_tokens/{token_hash}`

```
token_hash:    string  — SHA-256 of the one-time token
created_at:    string  — ISO 8601
expires_at:    string  — ISO 8601 (default: +24 h)
used:          boolean — true after first successful exchange
created_by:    string  — admin email (OIDC subject)
```

---

## API Reference

### Device endpoints (no OIDC — device token auth)

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/linux/enroll` | one-time token | Exchange enrollment token for device token |
| `POST` | `/linux/checkin` | device token | Register / update device metadata |
| `PUT` | `/linux/mdm/<device_id>` | device token | Poll for commands; ack previous result |

### Admin endpoints (Google OIDC + Firestore ACL)

| Method | Path | Description |
|---|---|---|
| `POST` | `/admin/linux/enroll_token` | Issue one-time enrollment token |
| `GET` | `/admin/devices?platform=linux` | List enrolled Linux devices |
| `GET` | `/admin/devices?platform=all` | List Apple + Linux devices |
| `POST` | `/admin/devices/<id>/command?platform=linux` | Enqueue command to Linux device |
| `POST` | `/admin/devices/<id>/push?platform=linux` | MVP: no-op; prod: FCM wake-up |

---

## Agent Configuration

`/etc/falko/agent.conf` (INI format):

```ini
[falko]
server_url     = https://mdm-api.falko.fi
poll_interval  = 900
token_path     = /etc/falko/device.token
log_level      = INFO
```

All keys overridable via environment variables (`FALKO_SERVER_URL`, `FALKO_POLL_INTERVAL`, `FALKO_TOKEN_PATH`, `FALKO_LOG_LEVEL`).

---

## Security Model

### MVP

- Device endpoints (`/linux/enroll`, `/linux/checkin`, `/linux/mdm/*`) are **not** behind Google IAP — devices are not Google users.
- Device identity is a static bearer token (`Authorization: Bearer <DEVICE_TOKEN>`). Server verifies `SHA-256(token) == token_hash` stored in Firestore.
- One-time enrollment tokens are single-use and 24 h TTL.
- `/etc/falko/device.token` is `chmod 600 root:root` on the workstation.
- Admin endpoints (`/admin/*`) are unchanged — Google OIDC + Firestore ACL as per existing implementation.

### Production additions

- **mTLS**: Agent presents a GCP CAS-issued client certificate. Bearer token auth is retired.
- **Command signing**: Every command payload is signed with a GCP KMS asymmetric key. Agent rejects unsigned or invalid-signature commands.
- **Token rotation**: Device tokens (or certificates in mTLS mode) rotate on a 30-day schedule.
- **Rate limiting**: Cloud Armor blocks >10 req/min per `device_id` on device endpoints.

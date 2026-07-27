# ISO 27001 audit Q&A — Falko MDM Server

This document covers ISO 27001 audit questions and evidence-based answers for both the macOS MDM implementation (main branch) and the Linux MDM MVP (PR #53 / feature/linux-mvp branch). Answers reflect **current code state**, not target state. Where a control is designed but not yet implemented, that is stated explicitly.

---

## Part 1 — macOS MDM implementation (main branch)

### Scope and system description

#### 1. What does the macOS MDM server do?

**Answer:** The server implements the Apple MDM protocol using Flask on Google Cloud Run. It exposes:
- `POST /checkin` — handles `Authenticate`, `TokenUpdate`, and `CheckOut` messages from Apple devices
- `PUT /mdm` — handles device command polling and command result acknowledgement
- `/admin/*` — admin API for listing devices, issuing commands, triggering APNs push, and managing user access

Device state and command queues are stored in Firestore. APNs push notifications are sent via HTTP/2 using JWT authentication.

#### 2. What is the trust boundary for device communication?

**Answer:** The `/checkin` and `/mdm` endpoints explicitly bypass IAP (Identity-Aware Proxy) because the caller is an Apple device, not a Google-authenticated human user. Device identity is based on Apple UDID format validation and TLS transport security. The admin endpoints (`/admin/*`) are protected by IAP JWT assertion verification or Google OAuth ID Token verification.

---

### Identity, authentication, and access control

#### 3. How are Apple devices authenticated?

**Answer:** Device identity is tied to the Apple MDM Identity Certificate that is provisioned inside the mobileconfig profile. The protocol-level device identity relies on TLS mutual authentication inherent in the Apple MDM protocol. UDID format is validated against a strict regex (`^[A-Z0-9][A-Z0-9-]{18,38}[A-Z0-9]$`) before any Firestore write, which mitigates path injection (referenced in code comments as Fleet MDM CVE-2026-34385).

There is no additional Bearer token or shared secret at the device level for macOS — Apple's architecture provides the identity guarantee through the signed MDM enrollment profile and the device certificate chain.

#### 4. How are admin users authenticated?

**Answer:** `require_auth` in `admin.py` supports two methods:
1. **IAP JWT assertion** — `X-Goog-IAP-JWT-Assertion` header is verified cryptographically using `id_token.verify_token` with Google-issued public keys and an `IAP_AUDIENCE` value. A plain header check is explicitly documented as insufficient (spoofable before the IAP layer).
2. **Google OAuth ID Token** — `Authorization: Bearer <google_id_token>` verified via `id_token.verify_oauth2_token`.

After verification, the user's authorization status is checked against Firestore (`authorized` / `pending` / `denied`).

#### 5. What is the bootstrap admin model and what risk does it carry?

**Answer:** `_BOOTSTRAP_ADMINS` is a hardcoded frozenset containing `jaakko.korhonen@gmail.com`. Bootstrap admins bypass Firestore authorization checks and automatically receive `admin` role on first login. This is documented as a bootstrapping necessity (no Firestore users exist on first deploy). An auditor would ask for: (a) a process to transition away from the bootstrap account once production admins are enrolled, and (b) whether the bootstrap email is protected by Google Account 2FA/passkey.

#### 6. Is least privilege implemented for admin commands?

**Answer:** Yes. `_DANGER_COMMANDS` (`EraseDevice`, `ShutDownDevice`) require the authenticated user to hold `role: admin` in Firestore. All other commands require only a valid authenticated session. The allowlist `_ALLOWED_COMMANDS` prevents arbitrary `RequestType` values from being injected into the Apple MDM protocol. This is explicitly referenced to OWASP ASVS v4.0 §5.1.3 and §4.1.2 in code comments.

---

### Endpoint hardening and data protection

#### 7. What security headers does the server return?

**Answer:** `middleware.py` adds the following to every response:
- `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Permissions-Policy: geolocation=(), camera=(), microphone=()`

This is referenced to W3C CSP Level 3 in comments.

#### 8. Is rate limiting implemented?

**Answer:** Yes — an in-memory sliding window rate limiter (60 requests / 60 seconds per IP) is implemented in `middleware.py`. The `/healthz` endpoint is explicitly excluded from rate limiting to protect Cloud Run health checks. The implementation uses a randomized 1% cleanup pass to prevent memory leaks from inactive IPs. A documented limitation is that the counter is not shared across Cloud Run instances; Redis-based `flask-limiter` is the recommended production path.

#### 9. Where are APNs credentials stored?

**Answer:** APNs credentials (`APNS_TEAM_ID`, `APNS_KEY_ID`, `APNS_PRIVATE_KEY`) are read from environment variables at runtime, not from code or files checked into the repository. An auditor would ask for evidence that these are injected via Cloud Run Secret Manager rather than plaintext environment variables.

#### 10. How is the APNs private key handled at runtime?

**Answer:** `apns.py` reads `APNS_PRIVATE_KEY` from the environment, replacing literal `\n` escape sequences with real newlines for PEM parsing. JWT tokens are cached for 50 minutes and refreshed before the Apple 60-minute expiry. The HTTP/2 connection to APNs is a persistent long-lived client, reducing TLS handshake overhead. Only the first 16 hex characters of the push token are logged to avoid leaking the full token. A thread-safe double-checked lock prevents race conditions during token refresh.

---

### Logging, monitoring, and audit trails

#### 11. What is logged for device events?

**Answer:** The server logs `CheckIn [MessageType] UDID=<udid>` for every check-in, and `MDM PUT UDID=<udid> Status=<status> CommandUUID=<uuid>` for every MDM poll. Admin actions log command enqueue events with UDID and `command_type`. The `apns.py` module logs APNs push results (success or failure) with truncated token.

#### 12. Can the organization demonstrate audit trails for admin commands?

**Answer:** Partially. Each `POST /admin/devices/<udid>/command` is logged with `udid` and `command_type`. However, the current logging does not capture the identity of the admin who issued the command in the log line itself — it captures authentication at the request level but not in the structured command record. An auditor would ask for the operator email to be included in the Firestore command document and log entry.

#### 13. Is there evidence of command result correlation?

**Answer:** Yes. `ack_command` updates the Firestore command document with a final status (`acknowledged`, `error`, `commandformaterror`, `notnow`, `sent`). This provides a command lifecycle record in Firestore. The `NotNow` status is explicitly documented as a deferred-retry case with a `TODO` for retry logic.

---

### Secure development and supply chain

#### 14. Are inputs validated against injection risks?

**Answer:** UDID format is validated by regex before Firestore writes in both `checkin.py` and `mdm.py`. `command_type` is validated against an explicit allowlist in `admin.py` before being stored or sent to devices. `page_size` in the device list endpoint validates integer bounds (1–500). Plist parsing failures return `400` without leaking internal error detail.

#### 15. What automated security testing exists for the macOS implementation?

**Answer:** A `tests/` directory exists in the repository. The current PR (Linux MVP) does not include new tests for the Linux code. The auditor would need to inspect the test coverage independently. A `bandit` and `pip-audit` CI pipeline is not present in this PR.

#### 16. What are the third-party dependencies?

**Answer:** `requirements.txt` includes `flask`, `google-auth`, `firebase-admin`, `httpx[http2]`, `pyjwt`, `cryptography`. An auditor would ask for a current `pip-audit` report to verify there are no known CVEs in the pinned dependency versions.

---

### Operational and resilience controls

#### 17. How is the server deployed?

**Answer:** The server runs on Google Cloud Run using a Docker image defined in `Dockerfile`. `cloudbuild.yaml` defines the build and deployment pipeline. Cloud Run provides automatic scaling, IAP integration, and managed TLS.

#### 18. Is Firestore access controlled?

**Answer:** The PR does not include Firestore Security Rules. Issue #51 is referenced in the Linux MVP PR as a critical blocker for Firestore Security Rules before production deployment. An auditor would request the current Firestore Security Rules or IAM policy to determine whether unauthenticated Firestore access is possible.

---

### Part 1 — Control status matrix (macOS)

| Control | Status |
|---|---|
| UDID format validation before Firestore writes | ✅ Implemented |
| IAP JWT assertion cryptographic verification | ✅ Implemented |
| Google OAuth ID Token verification | ✅ Implemented |
| User authorization status check (Firestore) | ✅ Implemented |
| Command allowlist (positive validation) | ✅ Implemented |
| Danger command admin-role enforcement | ✅ Implemented |
| Security response headers (CSP, nosniff, etc.) | ✅ Implemented |
| In-memory rate limiting per IP | ✅ Implemented (not distributed) |
| APNs credential isolation (env vars) | ✅ Implemented |
| APNs token thread-safety (double-checked lock) | ✅ Implemented |
| Push token partial logging (privacy) | ✅ Implemented |
| Command lifecycle tracking in Firestore | ✅ Implemented |
| Operator identity in command audit log | ⚠️ Partial (not in Firestore record) |
| Distributed rate limiting (Redis) | ❌ Not implemented (documented gap) |
| Firestore Security Rules | ❌ Not shown (issue #51) |
| CI security pipeline (bandit, pip-audit) | ❌ Not shown in current PR |
| NotNow retry logic | ❌ TODO in code |
| APNS credentials via Secret Manager (vs. env) | ❓ Not verifiable from code alone |

---

## Part 2 — Linux MDM MVP (PR #53 / feature/linux-mvp)

### Scope and system description

#### 19. What is in scope for the Linux MDM MVP?

**Answer:** PR #53 adds a Linux MDM agent (`agent/`), Linux check-in and poll endpoints (`app/linux_checkin.py`, `app/linux_mdm.py`), a bootstrap enrollment script, a systemd service unit, and design documentation in `LINUX.md`. The PR is marked as a draft and the PR body explicitly states it initializes structure and empty placeholder files.

#### 20. What security-relevant functions does the Linux agent perform?

**Answer:** The agent performs device check-in, periodic command polling, local inventory collection (hostname, OS, kernel, architecture, CPU, RAM, IP, agent version), Bearer-token authentication, and command execution including `ShellCommand`, `GetInventory`, `RebootDevice`, `ShutDownDevice`, and `LockScreen`.

#### 21. What is the declared trust model for Linux devices?

**Answer:** Linux devices authenticate with Bearer tokens stored in `/etc/falko/device.token`. The design assumes the Linux device is not behind IAP (no Google-authenticated human user). Server-side trust relies on the token being valid and the command queue being writable only by authorized OIDC admins.

---

### Identity, authentication, and access control

#### 22. How are Linux devices authenticated today?

**Answer:** Bearer token authentication is designed but **not yet implemented** on the server side. Both `app/linux_checkin.py` and `app/linux_mdm.py` contain explicit placeholder comments: the code checks that the `Authorization` header starts with `Bearer ` but does not perform actual token hash verification against Firestore.

#### 23. What would an auditor ask about the token implementation gap?

**Answer:** The auditor would ask for a remediation timeline, a risk acceptance record, and compensating controls (e.g., network-level restriction to enrolled subnets) that apply while the token verification remains unimplemented. This is the most material open authentication gap in the current draft.

#### 24. How is device identity established?

**Answer:** The agent computes `device_id` as `SHA-256(hostname + machine-id)`. This is deterministic but client-computed — not server-issued. The risk is identity collision on cloned VMs that share `machine-id`. The recommended fix is server-issued UUID written to `/etc/falko/device.id` at enrollment.

#### 25. Is timing-safe token comparison implemented?

**Answer:** No — the token comparison placeholder is absent. Production implementation must use `secrets.compare_digest(provided_hash, stored_hash)` to prevent timing side-channel attacks (OWASP standard recommendation).

---

### Least privilege and endpoint hardening

#### 26. Does the Linux agent run as root?

**Answer:** No. The systemd service runs as user `falko` and group `falko`, not root. This is a documented least-privilege decision.

#### 27. What systemd hardening is in place?

**Answer:** The service file includes: `ProtectSystem=strict`, `ReadWritePaths=/opt/falko-agent /etc/falko`, `ProtectHome=yes`, `PrivateTmp=yes`, `NoNewPrivileges=yes`, `CapabilityBoundingSet=` (empty — no capabilities), `RestrictNamespaces=yes`, `SystemCallFilter=@system-service`. This is production-grade hardening that exceeds typical MDM agent configurations.

#### 28. Can a local admin bypass MDM control?

**Answer:** Yes — a local user with `sudo` or root access can stop the agent (`sudo systemctl stop falko-agent`), modify the token file, or redirect the server URL in `agent.conf`. This is a structural Linux limitation — no Linux MDM product (Fleet, Jamf Pro Linux, Intune Linux) can prevent a root-privileged local user from terminating an agent process. Mitigations in order of priority: (1) sudoers snippet preventing non-root service stop, (2) heartbeat-loss alerting on the server, (3) LUKS key escrow to shift enforcement to the boot sequence.

---

### Cryptography and secrets

#### 29. Where is the device token stored?

**Answer:** `/etc/falko/device.token` (default). The agent rereads this file after a 401 response, supporting token rotation without restart. File permissions, ownership, and secure creation process are not demonstrated in this PR.

#### 30. Is release binary signing implemented?

**Answer:** No — planned in `LINUX.md`, not implemented. The bootstrap script does not verify download integrity. The `cryptography` library is noted in `requirements.txt` comments as a future dependency for Ed25519 signature verification.

#### 31. Is LUKS key escrow implemented?

**Answer:** No — designed at concept level in `LINUX.md`, not implemented in any code. The design describes: enrollment-time `cryptsetup luksAddKey`, recovery key transmission to server, server-side GCP KMS encryption before Firestore storage, and a crypto-erase wipe command. None of this exists in the current PR.

---

### Logging, monitoring, and evidence

#### 32. How is logging handled on the Linux agent?

**Answer:** The agent writes structured Python log output to stdout, captured by journald. Server endpoints log receipt of Linux check-in and poll requests. There is no end-to-end audit trail correlating a human admin action to a queued command to an execution result.

#### 33. Is compliance monitoring implemented?

**Answer:** No — only planned in `LINUX.md`. No implementation of periodic firewall status, disk encryption status, or required package checks appears in this PR.

---

### Secure development and change control

#### 34. Is the Linux MVP production-ready?

**Answer:** No. The PR is marked as a draft with explicit placeholder sections. Critical authentication is not implemented. This is in-development code, not production-ready control evidence.

#### 35. Are there unit tests or a CI pipeline for the Linux code?

**Answer:** No tests are included in this PR. No GitHub Actions workflow covering the Linux code is present. The auditor would require: `pytest` test suite, `bandit -r agent/` static analysis, `pip-audit` dependency scan, and a CI gate that fails if the token validation placeholder comment remains in code.

#### 36. Is `shell=True` in `executor.py` a documented risk?

**Answer:** Yes — the code contains an explicit `# nosec B602` annotation and a comment acknowledging that `shell=True` is dangerous and intentional for MVP. From an ISO 27001 perspective, awareness is not sufficient; the auditor would ask for a formal risk acceptance record, compensating controls, and a timeline for replacement.

---

### Part 2 — Control status matrix (Linux MVP)

| Control | Status |
|---|---|
| Non-root agent execution (falko user) | ✅ Implemented |
| Systemd hardening directives | ✅ Implemented |
| Inventory collection (failure-tolerant) | ✅ Implemented |
| Basic logging (journald / stdout) | ✅ Implemented |
| Agent polling and check-in structure | ✅ Implemented (placeholder server) |
| Local token file reading + rotation on 401 | ✅ Implemented |
| Server-side token validation | ❌ Not implemented (placeholder) |
| Timing-safe token comparison | ❌ Not implemented |
| Server-issued device identity | ❌ Not implemented (client hash used) |
| Release binary signing and verification | ❌ Not implemented (planned) |
| LUKS key escrow and remote crypto-wipe | ❌ Not implemented (planned) |
| Compliance drift detection | ❌ Not implemented (planned) |
| Heartbeat-loss alerting | ❌ Not implemented |
| Unit tests | ❌ Not present |
| CI security pipeline (bandit, pip-audit) | ❌ Not present |
| `shell=True` formal risk acceptance record | ❌ Not documented outside code comments |

---

## Part 3 — Cross-platform comparison (macOS vs. Linux)

| Dimension | macOS MDM (main) | Linux MDM (PR #53) |
|---|---|---|
| Device authentication | Apple MDM Identity Certificate + TLS | Bearer token (design only — not implemented) |
| Server-side auth verification | ✅ Cryptographic (IAP JWT / Google OAuth) | ❌ Placeholder |
| Identity origin | Apple-signed enrollment profile | Client-computed SHA-256 hash |
| Command allowlist | ✅ Implemented | ❌ Not shown |
| Danger command role enforcement | ✅ Implemented (admin role required) | ❌ Not implemented |
| Security response headers | ✅ Implemented | ❌ Not applicable (agent, not browser) |
| Rate limiting | ✅ In-memory (not distributed) | ❌ Not present |
| Audit log (command lifecycle) | ✅ Firestore status tracking | ❌ Incomplete |
| Remote wipe capability | ✅ EraseDevice (Apple native) | ❌ Not implemented (LUKS escrow planned) |
| Endpoint hardening | Cloud Run (managed) | ✅ systemd hardening directives |
| Least privilege | Cloud Run IAM | ✅ Non-root falko user |
| CI / automated tests | ⚠️ tests/ directory exists | ❌ No tests in this PR |
| Production-readiness | ⚠️ Missing: Firestore rules, operator logging | ❌ Draft — critical gaps open |

---

## Part 4 — Auditor follow-up requests

### 37. What evidence would an ISO 27001 auditor request immediately?

The following evidence requests are most likely based on the current code state:

**macOS MDM:**
- Firestore Security Rules (issue #51) — read/write access control evidence
- Cloud Run IAM policy — service account permissions
- Secret Manager configuration for `APNS_PRIVATE_KEY` — credentials-at-rest evidence
- Updated Firestore command documents showing operator email in each command record
- `pip-audit` report for current `requirements.txt` pinned versions
- Test coverage report from `tests/`

**Linux MDM MVP (before any staging use):**
- Risk acceptance record for `ShellCommand` + `shell=True` (owner, review date, timeline)
- Token validation implementation with `secrets.compare_digest` (remediation timeline)
- Firestore Security Rules or IAM policy for command queue write authorization
- File permission model for `/etc/falko/device.token` (mode, ownership, creation process)
- Service account sudo permissions for `systemctl reboot` / `poweroff` under `falko` user
- CI pipeline artifacts — `pytest`, `bandit`, `pip-audit`

### 38. What is the concise audit conclusion for each component?

**macOS MDM (main branch):** The implementation shows good architectural control — IAP JWT verification is correctly implemented, command input validation uses an allowlist, danger commands are role-gated, and APNs credentials are isolated via environment variables. The primary open items are Firestore Security Rules, missing operator identity in the command audit log, and absence of visible CI security gates.

**Linux MDM MVP (PR #53):** The draft shows strong intent and the systemd hardening is genuinely production-grade. However, the critical authentication control (token validation) is explicitly absent from the server implementation, the device identity model has a known VM-clone collision risk, and no automated tests or security pipeline exist. This is not audit-ready as a production control set. No major nonconformity would be raised at this stage if the team demonstrates an active remediation plan with owner-assigned timelines for each open item.

---

## TODO: Agent bypass threat model (Linux)

> **Status: open — requires risk acceptance record before production.**

A local user with `sudo` or root access can bypass the Linux agent. See the detailed threat model, planned mitigations (LUKS escrow, sudoers restriction, TPM-sealed config), and competitor analysis in the full `LINUX.md` document.

---

## TODO: LUKS key escrow — implementation gaps (Linux)

> **Status: designed in `LINUX.md`, not implemented.**

The enrollment script does not call `cryptsetup luksAddKey`, there is no escrow endpoint, no KMS encryption wrapper, no key revocation API, and no wipe command type in `executor.py`. See `LINUX.md` for the full design description and implementation roadmap.

---

*Last updated: 2026-07-27. Reflects macOS main branch state and Linux MVP PR #53 draft state.*

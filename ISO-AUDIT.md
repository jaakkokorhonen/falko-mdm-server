---

This document covers ISO 27001 audit questions and evidence-based answers for the macOS MDM implementation (main branch), the Linux MDM MVP (PR #53 / feature/linux-mvp branch), and the Chrome OS / Google Workspace integration. Answers reflect **current code state**, not target state. Where a control is designed but not yet implemented, that is stated explicitly.

---

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

### Scope and system description
#### 39. What is the scope of Chrome OS management in this audit?

**Answer:** Chrome OS devices in the Falko MDM context are not managed through the Falko MDM server itself. Chrome OS management is delegated to Google Workspace admin policies via the Google Admin Console (`admin.google.com`). The Falko MDM server's role is limited to: (1) providing Firestore-based inventory records synced from Workspace APIs if implemented, and (2) the admin authentication layer (IAP + Google OAuth) that Chrome OS users traverse when accessing the admin UI. The Chrome OS audit covers Google Workspace configuration, Chrome Browser Cloud Management (CBCM), and ChromeOS device policy enforcement.

#### 40. What enrollment model does Chrome OS use?

**Answer:** Chrome OS devices are enrolled via **enterprise forced re-enrollment** (FRE/REenrollment) using Workspace domain credentials. Once enrolled, the device is permanently associated with the organization's Workspace domain and cannot be unenrolled without admin action or a full device wipe. This is stronger than the Linux and macOS models where a local root user can terminate the MDM agent. The enrollment flow relies entirely on Google's infrastructure; there is no Falko server involvement at enrollment time.

#### 41. How do Chrome OS devices authenticate to organization services?

**Answer:** Chrome OS device identity is established by Google's enterprise enrollment PKI. End-user authentication uses Google Workspace SSO (SAML or OIDC) and is enforced by Chrome policies (`BrowserSignin`, `RestrictSigninToPattern`). Admin console policies bind the device to the enrolled organizational unit (OU), making device-level authentication a Google-managed concern rather than a Falko server concern.

---

### Identity, authentication, and access control
#### 42. How is user sign-in restricted to organizational accounts?

**Answer:** `RestrictSigninToPattern` policy restricts sign-in to `*@<domain>` patterns, preventing personal Google accounts from logging into managed Chromebooks. `BrowserSignin` forces sign-in to be mandatory. These are Google Admin Console settings, not Falko server settings. An auditor would request a screenshot or export of the current Admin Console policy set as evidence.

#### 43. How is multi-factor authentication enforced for Chrome OS users?

**Answer:** MFA for Workspace accounts is enforced at the Google identity provider level, not at the device level. Recommended controls: enforce 2-Step Verification at the Workspace Admin Console under Security → 2-Step Verification → Enforcement. Phishing-resistant options (passkeys, FIDO2 security keys, or Google Workspace Advanced Protection) are the strongest available. An auditor would ask for evidence that 2SV enforcement is set to "On — users cannot turn off 2-Step Verification" for all OUs in scope.

#### 44. Is least privilege applied to admin console access?

**Answer:** Google Workspace supports delegated admin roles. The principle of least privilege requires that only designated IT admins hold the "Chrome Management" or "User Management" roles. The Super Admin role must be restricted to a maximum of two break-glass accounts, protected by hardware security keys, and unused for day-to-day operations. An auditor would review the Admin Console → Admin Roles → Admins list for over-provisioned accounts.

---

### Device policy and endpoint hardening
#### 45. What device policies are required for ISO 27001 compliance?

**Answer:** The following Chrome OS device policies are the ISO 27001 baseline for a managed fleet:

| Policy | Recommended setting | ISO 27001 relevance |
|---|---|---|
| `DeviceEphemeralUsersEnabled` | Disabled (persistent sessions for enrolled users only) | A.9.1 — access control |
| `ScreenLockDelaySeconds` | ≤ 300 (5 min) | A.11.2.9 — clear screen |
| `AutoUpdateDisabled` | Disabled (updates must run) | A.12.6.1 — patch management |
| `ChromeOsReleaseChannel` | `stable-channel` | A.12.6.1 — patch management |
| `DevicePowerwashAllowed` | Disabled (prevent local wipe bypass) | A.8.3.2 — disposal |
| `TransferableProfiles` | Disabled | A.9.1 — access control |
| `LoginAllowedUrls` | Restricted to org domain | A.9.4.2 — authentication |
| `AllowBluetooth` | Disabled or restricted in high-risk OUs | A.11.2.6 — equipment security |
| `VirtualMachinesAllowed` | Disabled unless required | A.12.1.3 — capacity management |
| `DeveloperToolsDisabled` | Enabled in standard user OUs | A.12.6.2 — restrictions |
| `URLBlocklist` | Org-defined block list applied | A.13.1.3 — network segregation |
| `SafeBrowsingEnabled` | Enabled | A.12.2.1 — malware controls |

#### 46. Is remote wipe available for Chrome OS?

**Answer:** Yes — Google Admin Console provides "Deprovision" and "Remote wipe" (powerwash) actions for enrolled ChromeOS devices. Deprovisioning removes the device from the organization's managed fleet. Powerwash triggers a full factory reset. These actions are logged in the Admin Audit log. An auditor would verify that only authorized admin roles can trigger deprovision/wipe, and that these actions generate alerts via Workspace Admin Audit API or BigQuery export.

#### 47. Is disk encryption enforced on Chrome OS?

**Answer:** Chrome OS enforces full-disk encryption by default using AES-128 (user data partition) and dm-crypt. Unlike Linux (where LUKS escrow is a Falko server concern), Chrome OS key management is handled entirely by Google's Trusted Platform Module (TPM) and Verified Boot. No Falko server-side escrow is required. An auditor would note that encryption is a platform guarantee and request Google's Workspace compliance documentation (SOC 2, ISO 27001 certification) as pass-through evidence.

#### 48. Is Verified Boot (VB2) enforced?

**Answer:** Chrome OS Verified Boot runs at every device startup, cryptographically verifying the bootloader, kernel, and OS partition against Google-signed hashes. Developer mode disables this guarantee. The `DevMode` policy must be enforced to prevent users from enabling developer mode on managed devices. An auditor would request that `DeviceBootOnSignedOnly` (equivalent: dev mode blocked by enrollment) is confirmed in device settings for all OUs.

---

### Data protection and DLP
#### 49. What data loss prevention controls exist for Chrome OS?

**Answer:** Google Workspace provides Chrome Enterprise DLP rules via the Admin Console → Chrome → Data Controls. Rules can block clipboard copy, screenshot, printing, and file download based on content classification. These are Workspace-native controls and do not involve the Falko MDM server. An auditor would ask for the active DLP rule set and evidence that rules are applied to the correct OUs. If the Falko `dlp/` directory contains Workspace API integration, that should be included as corroborating evidence.

#### 50. Is Google Drive access controlled for managed Chrome OS devices?

**Answer:** Drive access for enrolled Chrome OS devices is governed by Workspace sharing settings and Context-Aware Access (CAA) policies. CAA can restrict Drive access to devices with specific attributes (enrolled, up-to-date OS, no developer mode). An auditor would ask whether CAA access levels are defined and bound to the Drive service for the organizational domain, and whether sharing outside the domain is restricted.

---

### Logging, monitoring, and audit trails
#### 51. What audit logging is available for Chrome OS device events?

**Answer:** Google Admin Console provides device audit logs covering: enrollment, unenrollment, powerwash, status changes, and policy updates. These logs are available via Admin Console → Reporting → Audit → Chrome OS devices. They can be exported to BigQuery or a SIEM via the Workspace Reports API. An auditor would ask for evidence of log retention policy (minimum 12 months for ISO 27001) and alerting on high-risk events (powerwash, unenrollment).

#### 52. Are Chrome browser activity logs retained?

**Answer:** Chrome Browser Cloud Management (CBCM) provides browser event logs including URL visits (if configured), extension installs, and crash reports. Enabling `ChromeReportingEnabled` sends logs to the Admin Console reporting dashboard. For ISO 27001, the key question is whether these logs are exported to a SIEM with defined retention. An auditor would ask for evidence of log export configuration and retention duration.

---

### Secure development and integration
#### 53. Does Falko MDM server integrate with Google Workspace APIs for Chrome OS inventory?

**Answer:** This is not evidenced in the current codebase on the `feature/linux-mvp` branch. The `dlp/` directory exists but its contents are not reviewed in this audit. If Workspace API calls are made (e.g., Directory API for device listing, Reports API for audit events), they would require a service account with narrowly scoped OAuth2 permissions and domain-wide delegation. An auditor would ask for the service account IAM role assignments and the OAuth2 scopes granted.

#### 54. Are Chrome OS device records synchronized to Firestore?

**Answer:** No evidence in the current codebase. If implemented, the recommended model is: Workspace Directory API → scheduled Cloud Run job → Firestore `chromeos_devices` collection. Access to this collection must be controlled by Firestore Security Rules equivalent to those required for macOS devices (issue #51). A separate audit question for Chrome OS would cover data minimization — only fields required for MDM management should be stored.

---

### Part 3 — Control status matrix (Chrome OS / Google Workspace)
| Control | Status | Owner |
|---|---|---|
| Enterprise forced re-enrollment (FRE) | ✅ Google-managed (verify in Admin Console) | Google Workspace admin |
| RestrictSigninToPattern (org domain only) | ❓ Not verifiable from Falko code — verify in Admin Console | Google Workspace admin |
| 2-Step Verification enforcement (all users) | ❓ Verify in Workspace Security settings | Google Workspace admin |
| Screen lock policy (≤ 300 s) | ❓ Verify in Chrome device policy OU | Google Workspace admin |
| AutoUpdate enabled (stable channel) | ❓ Verify — `AutoUpdateDisabled` must be false | Google Workspace admin |
| DevicePowerwashAllowed = disabled | ❓ Verify per OU | Google Workspace admin |
| Developer mode blocked (DeviceBootOnSignedOnly) | ❓ Verify per OU | Google Workspace admin |
| Verified Boot enforced (no dev mode) | ✅ Chrome OS platform guarantee (if dev mode blocked) | Google / Workspace admin |
| Full-disk encryption (TPM + dm-crypt) | ✅ Chrome OS platform guarantee | Google |
| Remote wipe via Admin Console | ✅ Available — verify admin role restriction | Google Workspace admin |
| DLP rules (clipboard, screenshot, print) | ❓ Not verifiable from Falko code — verify in Workspace | Google Workspace admin |
| Context-Aware Access for Drive | ❓ Not verifiable from Falko code — verify CAA config | Google Workspace admin |
| Device audit log export (BigQuery / SIEM) | ❓ Not evidenced — verify log export config | Google Workspace admin |
| Admin audit log retention ≥ 12 months | ❓ Verify Workspace log retention settings | Google Workspace admin |
| Workspace API integration (Falko server) | ❌ Not evidenced in current branch | Falko development |
| Chrome OS device records in Firestore | ❌ Not implemented | Falko development |
| Firestore Security Rules for ChromeOS data | ❌ Pending (issue #51 covers all platforms) | Falko development |
| Super Admin role restricted (≤ 2 accounts, FIDO2) | ❓ Verify in Admin Console → Admin Roles | Google Workspace admin |

---

| Dimension | macOS MDM (main) | Linux MDM (PR #53) | Chrome OS / Workspace |
|---|---|---|---|
| Device authentication | Apple MDM Identity Certificate + TLS | Bearer token (design only — not implemented) | Google enterprise enrollment PKI |
| Server-side auth verification | ✅ Cryptographic (IAP JWT / Google OAuth) | ❌ Placeholder | ✅ Google-managed (not Falko server) |
| Identity origin | Apple-signed enrollment profile | Client-computed SHA-256 hash | Google enrollment domain binding |
| Command allowlist | ✅ Implemented | ❌ Not shown | N/A — policy-based, not command-based |
| Danger command role enforcement | ✅ Implemented (admin role required) | ❌ Not implemented | ✅ Admin Console role-based |
| Security response headers | ✅ Implemented | ❌ Not applicable (agent, not browser) | N/A |
| Rate limiting | ✅ In-memory (not distributed) | ❌ Not present | N/A — Google infrastructure |
| Audit log (command lifecycle) | ✅ Firestore status tracking | ❌ Incomplete | ✅ Admin Console audit log (verify export) |
| Remote wipe capability | ✅ EraseDevice (Apple native) | ❌ Not implemented (LUKS escrow planned) | ✅ Powerwash via Admin Console |
| Full-disk encryption | Apple FileVault (device-managed) | LUKS (not escrowed yet) | ✅ TPM + dm-crypt (platform guarantee) |
| Verified Boot | N/A (macOS Secure Boot) | N/A | ✅ VB2 (platform guarantee) |
| Patch management | Apple MDM software update commands | Not implemented | ✅ Auto-update enforced via policy |
| Endpoint hardening | Cloud Run (managed) | ✅ systemd hardening directives | ✅ Verified Boot + platform hardening |
| Least privilege | Cloud Run IAM | ✅ Non-root falko user | ✅ Delegated admin roles in Workspace |
| CI / automated tests | ⚠️ tests/ directory exists | ❌ No tests in this PR | N/A (configuration, not code) |
| Production-readiness | ⚠️ Missing: Firestore rules, operator logging | ❌ Draft — critical gaps open | ⚠️ Requires Admin Console verification |
| Falko server integration | ✅ Full implementation | ⚠️ Draft | ❌ Not yet implemented |

---

### 55. What evidence would an ISO 27001 auditor request immediately?
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

**Chrome OS / Google Workspace:**
- Admin Console export of Chrome OS device policies per OU (PDF or JSON via Admin SDK)
- Evidence of 2-Step Verification enforcement for all users in scope
- Admin Roles list — confirm Super Admin count and 2FA method for each
- Log export configuration — Admin Audit and Device Audit to BigQuery or SIEM
- DLP rule set export — confirm rules applied to managed Chrome OS OUs
- Context-Aware Access policy configuration (if Drive or Workspace apps are in scope)
- Google Workspace ISO 27001 / SOC 2 Type II certification (pass-through control evidence)

### 56. What is the concise audit conclusion for each component?
**macOS MDM (main branch):** The implementation shows good architectural control — IAP JWT verification is correctly implemented, command input validation uses an allowlist, danger commands are role-gated, and APNs credentials are isolated via environment variables. The primary open items are Firestore Security Rules, missing operator identity in the command audit log, and absence of visible CI security gates.

**Linux MDM MVP (PR #53):** The draft shows strong intent and the systemd hardening is genuinely production-grade. However, the critical authentication control (token validation) is explicitly absent from the server implementation, the device identity model has a known VM-clone collision risk, and no automated tests or security pipeline exist. This is not audit-ready as a production control set. No major nonconformity would be raised at this stage if the team demonstrates an active remediation plan with owner-assigned timelines for each open item.

**Chrome OS / Google Workspace:** Chrome OS presents a materially different audit profile from Linux and macOS — the majority of security controls are Google platform guarantees (Verified Boot, TPM encryption, enterprise re-enrollment lock) rather than Falko server controls. The audit focus shifts to Google Workspace Admin Console configuration verification, log export, and admin role hygiene. The Falko server has no current integration with Workspace APIs; if Chrome OS device inventory or compliance signals are required for the audit, a Workspace API integration must be scoped and built. The pass-through evidence burden (Google's own ISO 27001/SOC 2 certs) reduces the custom control implementation requirement significantly compared to the Linux platform.

---

## TODO: Agent bypass threat model (Linux)
> **Status: open — requires risk acceptance record before production.**

A local user with `sudo` or root access can bypass the Linux agent. See the detailed threat model, planned mitigations (LUKS escrow, sudoers restriction, TPM-sealed config), and competitor analysis in the full `LINUX.md` document.

---

## TODO: LUKS key escrow — implementation gaps (Linux)
> **Status: designed in `LINUX.md`, not implemented.**

The enrollment script does not call `cryptsetup luksAddKey`, there is no escrow endpoint, no KMS encryption wrapper, no key revocation API, and no wipe command type in `executor.py`. See `LINUX.md` for the full design description and implementation roadmap.

---

## TODO: Chrome OS / Workspace API integration
> **Status: not designed or implemented in current branch.**

If Chrome OS device records and compliance signals are required for unified MDM inventory, implement: Google Workspace Directory API sync → Cloud Run scheduled job → Firestore `chromeos_devices` collection. Requires service account with narrowly scoped domain-wide delegation. Firestore Security Rules for this collection must be defined as part of issue #51.

---

*Last updated: 2026-07-27. Reflects macOS main branch state, Linux MVP PR #53 merged state, and Chrome OS / Google Workspace audit scope addition.*


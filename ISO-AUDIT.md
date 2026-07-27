# ISO 27001 audit Q&A for Falko Linux MDM MVP

This document lists likely ISO 27001 audit questions arising from the current Linux MDM MVP draft in PR #53 and gives evidence-based answers based on the current design and code state. It is written from the perspective of an auditor asking for implementation evidence, control ownership, and residual risk. All answers reflect the current draft state, not target state.

## Scope and system description

### 1. What is in scope for this Linux MDM MVP?
**Answer:** The current draft adds a Linux MDM agent, Linux check-in and poll endpoints, a bootstrap enrollment script, a systemd unit, and design documentation in `LINUX.md`. The PR is still a draft pull request, and the Linux implementation is described as an MVP structure with placeholder areas still present.

### 2. What security-relevant functions does the MVP perform?
**Answer:** The agent performs device check-in, periodic command polling, local inventory collection, token-based authentication, and command execution including `ShellCommand`, `GetInventory`, `RebootDevice`, `ShutDownDevice`, and `LockScreen`. The server exposes `POST /linux/checkin` and `PUT /linux/mdm/<device_id>` for Linux devices.

### 3. What is the declared trust model?
**Answer:** The draft assumes Linux devices are not protected by IAP and instead authenticate with Bearer tokens. The design also states that `ShellCommand` is intentionally powerful and relies on only OIDC-authenticated admins being able to enqueue commands, with stronger signature-based controls deferred to later work.

## Identity, authentication, and access control

### 4. How are Linux devices authenticated today?
**Answer:** The intended design is Bearer-token authentication, where the token is read from a local file by the agent and verified against `linux_devices/{device_id}/token_hash` on the server. However, the current server implementation does not yet perform the actual token verification and only checks that the Authorization header exists and starts with `Bearer `.

### 5. Is authentication fully implemented in the server endpoints?
**Answer:** No. Both `app/linux_checkin.py` and `app/linux_mdm.py` explicitly contain placeholder comments stating that real token verification logic will be added later. This means the control is designed but not yet implemented in code.

### 6. How is device identity established?
**Answer:** The agent computes `device_id` as SHA-256 of hostname and machine-id, using `/etc/machine-id` or `/var/lib/dbus/machine-id` when available. This is deterministic and convenient, but it is not a server-issued identity and does not by itself prove possession of a protected secret.

### 7. What would an auditor ask next about this identity model?
**Answer:** An auditor would ask whether cloned images, reused machine identifiers, or predictable hostnames can cause identity collision or impersonation risk. Based on the current implementation, that risk has not yet been mitigated by a server-issued device identity or hardware-bound attestation mechanism.

### 8. Who is authorized to issue commands to devices?
**Answer:** The code comment in `executor.py` states that the MVP relies on only OIDC-authenticated admins being able to add commands to the queue. In the current PR, the enforcement evidence for that queue authorization is not present in the Linux code itself and would need to be demonstrated elsewhere, such as admin endpoints, Firestore rules, or surrounding IAM policy.

## Least privilege and endpoint hardening

### 9. Does the agent run as root?
**Answer:** The documented and committed systemd service runs the agent as user `falko` and group `falko`, not as root. This is a positive least-privilege design decision relative to the earlier documentation fragment that showed `User=root` before the updated hardening guidance.

### 10. What host hardening controls are implemented for the agent service?
**Answer:** The committed service file includes `ProtectSystem=strict`, `ReadWritePaths=/opt/falko-agent /etc/falko`, `ProtectHome=yes`, `PrivateTmp=yes`, `NoNewPrivileges=yes`, `CapabilityBoundingSet=`, `RestrictNamespaces=yes`, and `SystemCallFilter=@system-service`. These settings provide meaningful service isolation and reduce filesystem access, privilege escalation paths, namespace creation, and syscall surface.

### 11. Is the hardening complete and consistent across documentation and code?
**Answer:** It is partly complete. The service file itself is significantly hardened, and `LINUX.md` also contains dedicated sections for hardening and sandboxing. However, the hardening roadmap still includes draft items, so the auditor should treat this as implemented baseline hardening plus open hardening backlog rather than a finished control set.

### 12. Can the agent still execute privileged effects despite running unprivileged?
**Answer:** The agent directly invokes `systemctl reboot`, `systemctl poweroff`, and `loginctl lock-sessions`. An auditor would ask for evidence that the service account has only the exact OS-level permissions required for those operations and no broader elevation path, because the service file drops capabilities but the operational privilege model for these actions is not shown in this PR.

## Cryptography and secrets

### 13. Where are secrets stored on the endpoint?
**Answer:** The Bearer token is stored in a local file, defaulting to `/etc/falko/device.token`, and the optional environment file is `/etc/falko/agent.env`. The code reads the token from disk on startup and again after 401 responses to support token rotation.

### 14. What would an auditor ask about secret protection on disk?
**Answer:** An auditor would ask for file ownership, permission mode, provisioning path, rotation procedure, revocation process, and whether the token is ever written to logs or process listings. The current PR identifies the file path and read behavior, but it does not yet show file permission enforcement or enrollment-side secure creation logic.

### 15. Is cryptographic signing of updates implemented?
**Answer:** No. `LINUX.md` includes a planned control for release binary signing and verification using a pinned public key, and `agent/requirements.txt` comments that `cryptography` will be required in production for signature verification. The bootstrap script currently remains a placeholder and does not yet implement download verification.

### 16. Is key escrow addressed?
**Answer:** Yes at design level, not yet in code. `LINUX.md` includes a draft section stating that LUKS recovery keys should be escrowed at enrollment and encrypted with GCP KMS before being stored in Firestore, but this PR does not implement that workflow.

## Logging, monitoring, and evidence

### 17. How is operational logging handled?
**Answer:** The agent initializes Python logging to standard output in a format suitable for journald collection, and server endpoints log receipt of Linux check-in and poll requests. `LINUX.md` also references a separate structured logging and observability work item, which indicates the current implementation is only an initial logging baseline.

### 18. Can the organization demonstrate audit trails for administrative commands?
**Answer:** Not yet from this PR alone. The agent logs receipt of command identifiers and command types, but there is no complete evidence here of end-to-end auditability showing who queued a command, under what authorization, and how the result was correlated back to a human administrator action.

### 19. Is compliance monitoring implemented?
**Answer:** No, only planned. `LINUX.md` includes a draft section for compliance monitoring and drift detection, describing periodic audits of firewall status, disk encryption, and required packages, but no such implementation appears in this PR.

## Secure development and change control

### 20. Is this change production-ready?
**Answer:** No. The pull request title marks the work as an implementation draft, and the PR body explicitly says it initializes structure and empty placeholder files for the Linux MVP implementation. Several security-critical sections remain placeholders, so this should be treated as in-development code rather than production-ready evidence.

### 21. Is there evidence of secure coding review for dangerous functionality?
**Answer:** There is explicit acknowledgement in code comments that `shell=True` is dangerous and intentionally chosen for the MVP. That shows awareness, but from an ISO 27001 perspective awareness is not enough; the auditor would still ask for compensating controls, risk acceptance, review records, and a timeline for replacing or constraining the current model.

### 22. Are automated security tests or quality gates included in this PR?
**Answer:** No direct CI workflow or test suite is included in the files changed by this PR. `LINUX.md` references integration tests and CI as a documented area, but the PR contents shown here do not provide executable evidence of unit tests, integration tests, static analysis, dependency scanning, or pipeline policy enforcement.

### 23. Does the implementation minimize third-party dependencies?
**Answer:** Yes, partly. The agent depends on `requests`, and `inventory.py` uses only the Python standard library. That reduces dependency surface, although update-signature verification is deferred and will introduce `cryptography` in production.

## Resilience and operational control

### 24. How does the agent behave during service failure?
**Answer:** The systemd unit uses `Restart=on-failure` with `RestartSec=60`, and the poll loop applies increasing delay on 5xx and connection errors. This provides basic resilience, though the implemented backoff is linear rather than true exponential backoff with jitter.

### 25. Is token rotation supported?
**Answer:** Partly. The agent rereads the token file after a 401 response instead of caching the token permanently, which supports a rotation model without restarting the agent. The server-side token lifecycle, issuance, expiration, and revocation process are not shown in this PR.

### 26. Is inventory collection privacy-scoped and failure-tolerant?
**Answer:** The collection logic is failure-tolerant because it catches exceptions and falls back to empty values or defaults rather than crashing. The current inventory fields include hostname, OS, kernel, architecture, CPU model, RAM size, local IP, and agent version, so an auditor would ask whether each field is necessary, classified, and retained according to policy.

## Documentation and control maturity

### 27. What documentation evidence exists for the Linux MDM design?
**Answer:** `LINUX.md` appears to be the primary design and control narrative for the Linux MDM capability, and the PR adds sections on hardening, key escrow, compliance drift detection, release signing, configuration path, and systemd least privilege. This is useful design evidence, but several sections are explicitly marked draft, so they are not yet proof of implemented controls.

### 28. Which controls look implemented versus only planned?

| Control | Status |
|---|---|
| Agent polling and check-in | Implemented (placeholder server logic) |
| Inventory collection | Implemented |
| Basic logging (journald) | Implemented |
| Systemd hardening directives | Implemented |
| Non-root agent execution | Implemented |
| Local token file reading + rotation on 401 | Implemented |
| Endpoint registration of Linux blueprints | Implemented |
| Server-side token validation | **Not implemented (placeholder)** |
| Release binary signing and verification | **Not implemented (planned)** |
| LUKS recovery key escrow | **Not implemented (planned)** |
| Compliance drift detection | **Not implemented (planned)** |
| Automated CI / security test pipeline | **Not present in PR** |

### 29. What residual risk statement would likely appear in an audit note?
**Answer:** A reasonable audit note would say that the Linux MDM MVP shows good architectural intent and useful least-privilege hardening on the endpoint, but key access-control and software-integrity controls remain incomplete. The most material gaps are missing server-side token verification, powerful remote command execution through `shell=True`, absent demonstrated CI/security testing, and deferred software-signing controls.

## Auditor follow-up requests

### 30. What evidence would an ISO 27001 auditor likely request next?
**Answer:** The next evidence request would likely include:

- Risk assessment and treatment record for remote command execution (`ShellCommand` + `shell=True`)
- Proof of token validation logic and timing-safe comparison (`secrets.compare_digest`)
- Firestore Security Rules (issue #51) or IAM evidence controlling command queue writes
- Service-account permission model for `systemctl reboot` / `poweroff` under the `falko` user
- Enrollment flow documentation and secure token delivery mechanism
- File permission model for `/etc/falko/device.token` (mode, ownership, creation process)
- Logging retention and access policy for command audit trails
- CI pipeline artifacts showing automated tests and security scans (bandit, pip-audit)

### 31. What is the concise audit answer today?
**Answer:** The Linux MDM MVP is well documented and shows strong intent around endpoint hardening, but it is not yet audit-ready as a fully implemented ISO 27001 control set. It is better characterized as draft design plus partial implementation with important security controls still open. No major nonconformity would be raised at this stage if the team can demonstrate an active remediation plan for the open items listed above.

---

## TODO: Agent bypass threat model

> **Status: open — requires risk acceptance record and compensating controls before production.**

A local user with `sudo` or root access can bypass the current MVP agent with trivial effort. This section documents the threat model and planned mitigations.

### Can a local user prevent wipe or disable MDM control?

Yes. The Falko Linux agent runs as an unprivileged `falko` user under systemd. Commands like `RebootDevice`, `ShutDownDevice`, and `LockScreen` are executed via `systemctl reboot` and friends. There is **no wipe command implemented yet** in the current PR — the MVP has no Linux equivalent of Apple's `EraseDevice`.

### Bypass attack vectors

**Stopping the agent service** is the most obvious path. If the local user has `sudo` access (common on Linux workstations), they can simply run `sudo systemctl stop falko-agent` or `sudo systemctl disable falko-agent`. The MDM loses visibility immediately and permanently until someone re-enrolls. The current MVP has no heartbeat-loss alerting, so the server would not notice until the next missed check-in — which defaults to 900 seconds.

**Killing the process directly** (`sudo kill <pid>`) achieves the same result even faster.

**Modifying or deleting the token file** at `/etc/falko/device.token` with root access would cause all subsequent check-ins to fail authentication, effectively deregistering the device from the server's perspective without triggering any explicit unenrollment event.

**Modifying `/etc/falko/agent.conf`** to point to a fake server would make the agent phone home to a localhost endpoint, keeping the process alive and fooling basic "is the service running" checks while being completely disconnected from real MDM control.

### Why this is structurally hard on Linux

This is a known fundamental limitation of software-only MDM on Linux. Apple macOS MDM works because the MDM profile is enforced at the kernel/firmware level via Activation Lock and the Secure Enclave, making removal require Apple's servers. Linux has no equivalent trusted execution boundary for MDM enforcement by default. The same problem affects every major Linux MDM product (Jamf Pro Linux, Canonical Landscape, Fleet) — they all rely on the agent staying running, and a root user can always stop it.

### What the design plans but has not implemented

The LUKS key escrow design in `LINUX.md` is the closest thing to a wipe-prevention mechanism — if the LUKS recovery key is escrowed server-side and the local copy is deleted or rotated at enrollment, the device becomes useless without MDM cooperation on next boot. But that workflow is not implemented in this PR, and it only helps for full-disk-encryption enforcement, not live wipe during an active session.

### Planned mitigations (priority order)

| Mechanism | Protection offered | Complexity | Status |
|---|---|---|---|
| LUKS key escrow | Crypto-brick on next boot if MDM revokes key | High | Planned, not implemented |
| `sudo` restriction via `/etc/sudoers` for `falko-agent` service | Prevents unprivileged stop | Low | Not designed |
| Systemd `ProtectKernelTunables` + immutable service via `systemd-sysext` | Makes disabling harder | Medium | Not designed |
| TPM-bound agent token | Token unusable outside enrolled hardware | Very high | Not designed |
| Heartbeat-loss alerting on server | Fast detection, not prevention | Low | Not implemented |

**Risk acceptance required:** A local admin/root user can bypass the current MVP agent with trivial effort. This must be documented as an explicit accepted risk with owner, review date, and remediation timeline before the project moves toward production use with compliance requirements.

---

## TODO: LUKS key escrow — background and implementation gaps

> **Status: open — designed in `LINUX.md`, not yet implemented in any code.**

### What LUKS key escrow is

LUKS key escrow is a mechanism where a copy of the disk encryption recovery key is sent to and stored by a trusted server at enrollment time, so that the organization retains the ability to decrypt the device even if the local user changes or deletes their own copy.

### How LUKS works

LUKS (Linux Unified Key Setup) is the standard full-disk encryption system on Linux. When a drive is encrypted with LUKS, the actual data encryption key (DEK) is stored in the LUKS header on disk, itself encrypted by one or more keyslots. Each keyslot holds a copy of the DEK encrypted with a different passphrase or key file. Up to 8 keyslots can exist on a single LUKS volume, so multiple passphrases can independently unlock the same drive.

### How escrow enables remote wipe

At enrollment time, the agent generates a strong random recovery passphrase, adds it to a free LUKS keyslot on the device's boot drive, and immediately sends that passphrase to the MDM server. The server stores it encrypted — in Falko's planned design, encrypted with a GCP KMS key before writing to Firestore, so the plaintext recovery key never sits unprotected in the database. The local user never sees this recovery key and continues using their own passphrase for normal daily unlocking.

The result is a two-key system:

| Key | Held by | Used for |
|---|---|---|
| User passphrase | Local user | Normal daily boot |
| Recovery key | MDM server (KMS-encrypted) | Remote recovery, compliance wipe, lost-password unlock |

A crypto-wipe works as follows: the MDM server sends a command that calls `cryptsetup luksRemoveKey` to delete the user's own keyslot, then rotates or deletes the escrowed recovery key server-side. After the next reboot the drive is permanently inaccessible — data is not erased byte-by-byte but is cryptographically destroyed because no remaining key can decrypt the DEK. This is called a **crypto-erase** and is effectively instantaneous and irreversible.

### Why this resists local bypass

LUKS key escrow shifts the enforcement point from the running operating system (where the agent can be killed) to the hardware boot sequence. Even if the user stops the agent, uninstalls it, or reimages the OS, the encrypted data on disk remains locked by the LUKS header. Without the recovery key from the server, or the user's own passphrase, the data is inaccessible. If the MDM has already rotated or revoked the escrowed key, even the organization cannot recover it — which is the desired behavior for a security wipe.

The only real bypass requires the user to have saved the recovery key themselves before enrollment, or to physically remove the drive and use a different machine.

### What is missing in the current Falko MVP

The `LINUX.md` design describes this workflow at a high level, but nothing in PR #53 implements it. Open implementation gaps:

- The enrollment script does not call `cryptsetup luksAddKey`
- The agent has no escrow endpoint or recovery key transmission logic
- The server has no KMS encryption wrapper for key storage in Firestore
- There is no key revocation or rotation API
- There is no wipe command type in `executor.py`
- There is no audit trail for escrow operations

This is a sound design that has not yet been built. It must be implemented before the Linux MDM can make meaningful remote-wipe guarantees to an auditor.

---

## Competitor benchmarking and recommended solutions

> This section compares Falko's current and planned controls against Fleet (open-source), Fleet Premium, Microsoft Intune Linux, and Jamf Pro (macOS reference), and recommends concrete solutions that bring Falko to parity or better.

### How competitors solve each open problem

#### Device identity and authentication

**Fleet (free)** uses a two-phase enrollment: the installer is bundled with a one-time `enroll_secret`, which the server exchanges for a per-host `node_key` on first contact. The client stores this server-issued `node_key` and uses it for all subsequent requests. The device identity is therefore server-assigned, not client-computed — a critical security difference from Falko's current SHA-256(hostname+machine-id) model.

**Fleet Premium** goes further with TPM-bound host identity certificates (Linux kernel 4.12+, TPM 2.0 required). The private key is generated inside the TPM and never leaves the chip. The server can enforce `require_http_message_signature`, rejecting any request not signed by the TPM-bound key. This makes token theft and identity spoofing cryptographically infeasible without physical hardware access.

**Microsoft Intune Linux** registers devices with an Azure AD device token, providing identity that is tied to the organizational directory rather than a local file.

**Recommended solution for Falko:**

1. **Short term (MVP → v1):** Implement server-issued device UUID at enrollment. At `POST /linux/checkin`, if the device has no Firestore record, the server generates a UUID, stores `{uuid, token_hash, enrolled_at}`, and returns the UUID to the agent. The agent writes this server-issued UUID to `/etc/falko/device.id` (mode `0600`, owner `falko`). Subsequent check-ins use this UUID, not the hostname hash. This matches Fleet free-tier behavior and eliminates the VM clone collision risk.

2. **Long term (v2+):** Implement mTLS client certificates issued at enrollment and stored in a TPM keyslot where TPM 2.0 is available, falling back to a file-based client cert on older hardware. This matches Fleet Premium behavior. GCP Certificate Authority Service can act as the enrollment CA with short-lived certificates (24 h validity, auto-renewed by agent), eliminating long-lived token files entirely.

```python
# Recommended: server-side enrollment token exchange (linux_checkin.py)
import secrets
import hashlib

def issue_device_token(device_id: str) -> str:
    """Generate, store hash, return plaintext token to agent once."""
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    db.collection('linux_devices').document(device_id).set({
        'token_hash': token_hash,
        'issued_at': firestore.SERVER_TIMESTAMP,
    }, merge=True)
    return token  # sent once over TLS, never logged
```

#### Token validation (timing-safe)

**All production MDM products** use timing-safe comparison for token/credential validation to prevent timing side-channel attacks. Python's `hmac.compare_digest` and `secrets.compare_digest` are the standard.

**Recommended solution for Falko** (immediate, low effort):

```python
# app/linux_checkin.py and app/linux_mdm.py
import secrets
import hashlib

def verify_device_token(provided_token: str, stored_hash: str) -> bool:
    provided_hash = hashlib.sha256(provided_token.encode()).hexdigest()
    return secrets.compare_digest(provided_hash, stored_hash)
```

Replace the current placeholder comment with this implementation. Both hashes are the same length (64 hex chars), so `compare_digest` operates in constant time.

#### Agent tamper protection

**Microsoft Defender for Endpoint** implements kernel-level tamper protection: the agent registers a kernel callback that blocks `SIGKILL` and file writes to agent directories even from root processes. This is not achievable in Python without a kernel module.

**Fleet** does not implement kernel-level tamper protection in either tier. It accepts this as a known limitation and compensates with aggressive heartbeat monitoring (configurable down to 30 s) and automated device quarantine on missed check-ins.

**Recommended solutions for Falko** (layered, in priority order):

1. **`/etc/sudoers.d/falko-agent`** — drop a sudoers snippet at enrollment that prevents the `falko` group and any non-root user from stopping or disabling the `falko-agent` service. This is low effort and eliminates the most common bypass:
    ```
    # /etc/sudoers.d/falko-agent
    # Prevent unprivileged users from stopping the MDM agent
    ALL ALL = !EXEC: /usr/bin/systemctl stop falko-agent
    ALL ALL = !EXEC: /usr/bin/systemctl disable falko-agent
    ALL ALL = !EXEC: /usr/bin/systemctl mask falko-agent
    ```

2. **Heartbeat-loss alert** — server side: if a device has not checked in within `poll_interval * 3` seconds, emit a Cloud Monitoring alert and mark the device as `status: offline` in Firestore. This matches Fleet's detection model and gives the security team visibility within minutes rather than hours.

3. **`systemd-sysext` immutable overlay (v2+)** — package the agent as a `systemd-sysext` extension image. Extension images are read-only overlays on `/usr` and `/opt`, making file modification impossible without root access to the raw extension image file. This raises the bypass bar significantly beyond a simple `sudo systemctl stop`.

4. **TPM-sealed config (v3+)** — seal the server URL and token to the TPM with PCR values representing the boot state. If the boot chain is altered (kernel replaced, agent files tampered), the TPM unsealing fails and the agent cannot authenticate. This is the highest assurance level available on Linux without a kernel module.

#### Update signing

**Fleet** uses **TUF (The Update Framework)** for agent updates: the update server serves metadata signed by offline keys with threshold signatures, and the `orbit` updater verifies the full TUF chain before applying any binary. Key rotation is built into the protocol.

**Falko's planned approach** (pinned public key) is simpler and adequate for MVP, but does not support key rotation without a code change. A practical intermediate path:

```python
# Recommended: verify download with Ed25519 signature before execution
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
... pinned at build time ...
-----END PUBLIC KEY-----"""

def verify_update(payload: bytes, signature: bytes) -> bool:
    pub = load_pem_public_key(PUBLIC_KEY_PEM)
    pub.verify(signature, payload)  # raises InvalidSignature on failure
    return True
```

The bootstrap script should: download the agent tarball, download the detached `.sig` file from a separate URL, verify before unpacking, and refuse to proceed if verification fails. This eliminates supply-chain attacks on the installer.

#### LUKS key escrow (remote wipe)

No competitor has a fully implemented, open-source, GCP-native LUKS escrow solution. Falko's design (KMS-encrypted key in Firestore) is architecturally sound and differentiating. The implementation path:

```bash
# Enrollment script: add MDM recovery keyslot
RECOVERY_KEY=$(openssl rand -base64 32)
echo -n "$RECOVERY_KEY" | cryptsetup luksAddKey /dev/sda3 --key-file /dev/stdin

# Send to server (HTTPS only, logged)
curl -s -X POST https://mdm.example.com/linux/escrow \
  -H "Authorization: Bearer $(cat /etc/falko/device.token)" \
  -H "Content-Type: application/json" \
  -d "{\"recovery_key\": \"$RECOVERY_KEY\", \"device_id\": \"$DEVICE_ID\"}"

# Wipe recovery key from memory
unset RECOVERY_KEY
```

Server stores `KMS.encrypt(recovery_key)` in Firestore, never plaintext. Wipe command: `luksRemoveKey` for user keyslot + KMS key deletion.

### Competitor parity matrix

| Control | Fleet free | Fleet Premium | Intune Linux | Falko MVP | Falko recommended |
|---|---|---|---|---|---|
| Server-issued device identity | ✅ node_key | ✅ TPM cert | ✅ Azure AD | ❌ client hash | ✅ server UUID → mTLS cert |
| Timing-safe token comparison | ✅ | ✅ | ✅ | ❌ placeholder | ✅ `secrets.compare_digest` |
| Kernel-level tamper protection | ❌ | ❌ | ❌ | ❌ | ❌ (not feasible in Python) |
| sudoers-based stop restriction | ❌ | ❌ | ❌ | ❌ | ✅ sudoers snippet at enrollment |
| Heartbeat-loss alerting | ✅ 30 s min | ✅ | ✅ | ❌ | ✅ Cloud Monitoring alert |
| Update signing | ✅ TUF | ✅ TUF | ✅ pkg signature | ❌ planned | ✅ Ed25519 pinned key |
| LUKS/FDE key escrow | ❌ | ❌ | ❌ | ❌ planned | ✅ KMS + Firestore (differentiating) |
| Exponential backoff with jitter | ✅ | ✅ | ✅ | ❌ linear | ✅ `min(30*2^n + rand, 600)` |
| CI security gates (bandit, pip-audit) | ✅ | ✅ | N/A | ❌ | ✅ GitHub Actions workflow |

### Recommended implementation order

Ordered by security impact vs. implementation effort:

1. **Immediate (before any staging deployment):** Implement `secrets.compare_digest` token validation. Zero dependencies, ~10 lines of code, closes a critical authentication gap.
2. **Before first real device enrollment:** Server-issued device UUID at enrollment. Eliminates identity collision and VM clone risks.
3. **Sprint 1 post-MVP:** Heartbeat-loss Cloud Monitoring alert + device `status: offline` flag. Provides detection for agent bypass without kernel-level enforcement.
4. **Sprint 1 post-MVP:** sudoers snippet deployment via enrollment script. Raises bypass bar for non-technical users.
5. **Sprint 2:** Ed25519 update signing in bootstrap script and `executor.py` update handler.
6. **Sprint 2:** LUKS key escrow in enrollment script + `/linux/escrow` server endpoint + KMS wrapper.
7. **Sprint 2:** Exponential backoff with jitter in `agent.py` poll loop.
8. **Sprint 3:** GitHub Actions CI with `pytest`, `bandit`, `pip-audit`, and a gate that blocks merge if `secrets.compare_digest` placeholder is absent.
9. **v2 (optional, high assurance):** mTLS client certificates via GCP CA Service, replacing Bearer token entirely.
10. **v3 (optional, highest assurance):** TPM-sealed config and identity on supported hardware.

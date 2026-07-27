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

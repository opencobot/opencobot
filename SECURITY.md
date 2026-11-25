# Security Policy

OpenCobot is designed to control computers on behalf of AI models, so security is a core requirement, not an add-on.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

- Use GitHub's private vulnerability reporting: the **Security** tab of this repository, then **Report a vulnerability**.

Include what you found, steps to reproduce, the affected version or commit, and the impact you expect. We aim to acknowledge reports within 3 business days and to share a fix plan within 14 days. Please give us a reasonable time to fix before public disclosure. Good-faith research is welcome.

## Supported versions

The project is in Phase 0 (design). No release is supported yet. Once releases exist, this table will list which versions receive security fixes.

## Threat model summary

**Assets:** user files, credentials and API keys, browser sessions, screen content, system integrity, money.

**Adversaries:**

1. Malicious content the agent reads (web pages, emails, PDFs, documents, skill text): indirect prompt injection.
2. Malicious or compromised skills and plugins.
3. A weak or misbehaving model.
4. A network attacker against remote access.
5. A local low-privilege process trying to hijack the daemon.

**Core principle:** an agent that has access to private data, reads untrusted content and can send data out is exploitable by design. OpenCobot must never allow all three at once without a human decision.

**Out of scope:** a fully compromised host OS or a root-level attacker; guarantees that any model behaves correctly.

## Security invariants

These must hold in every release. A change that weakens one needs an ADR and explicit human sign-off.

1. The model proposes; it never grants itself permission. Approvals come only from the UI or the paired phone.
2. The policy engine runs as a separate process, and the agent cannot write to policy files, approvals or audit logs.
3. Every tool call is checked against a short-lived, scoped capability token.
4. Untrusted content is tagged as tainted; while tainted data is in context, Level 3+ tools and outbound network are locked or need approval.
5. No inbound network port is opened for remote control. Default bind is localhost.
6. Secrets live only in the OS keychain and are never shown to the model.
7. Data labelled secret never leaves the machine.
8. Every action is written to a tamper-evident audit log.
9. A kill switch can stop the agent at any time, even if the agent is hung.
10. Skills are signed, declare their permissions, and run sandboxed.
11. Success is determined by verifying real system state, not by the model's report.

## Using OpenCobot safely (once code exists)

- Start in read-only mode and widen permissions gradually.
- Prefer the sandboxed agent desktop (separate user, VM or container) for untrusted tasks.
- Give tasks narrow folders and short durations.
- Do not run it on machines holding regulated or highly sensitive data until you have reviewed the audit logs and policies.
- Never install skills from sources you do not trust; check their declared permissions.
- Keep the phone kill switch and pairing under your control; revoke lost devices immediately.

## Dependency and supply-chain policy

New dependencies need a justification and a license check. CI runs dependency, license and secret scans. Releases will be signed.

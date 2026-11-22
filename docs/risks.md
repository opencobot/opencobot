# Risk Register

Tracks identified risks to the project. Update when new threats, design gaps or dependency concerns are found. Risks that lead to architectural choices should also get an entry in [DECISIONS_LOG.md](DECISIONS_LOG.md).

| ID | Risk | Severity | Likelihood | Mitigation | Status | Date added |
|----|------|----------|------------|------------|--------|------------|
| R-001 | Indirect prompt injection via untrusted content (web, email, PDF) causes agent to execute harmful actions | Critical | High | Taint tracking, Level 3+ lockout while tainted data in context, red-team suite (SECURITY.md §4) | Open — design phase | 2026-11-22 |
| R-002 | Malicious or compromised skill bypasses permission model | Critical | Medium | Signed packages, permission declaration, sandboxed execution, static analysis (ARCHITECTURE.md §8) | Open — design phase | 2026-11-22 |
| R-003 | Model produces plausible but incorrect tool calls that pass schema validation | High | High | verify() on every tool reads real system state; never trust model's claim of success (ARCHITECTURE.md §4) | Open — design phase | 2026-11-22 |
| R-004 | Remote-control channel compromised or replayed | Critical | Low | E2E encryption (Noise/mTLS), no inbound ports, short-lived sessions, replay protection, device revocation (ARCHITECTURE.md §7) | Open — design phase | 2026-11-22 |
| R-005 | Secret data exfiltrated to cloud model | Critical | Medium | Sensitivity labels (public/personal/secret), policyd enforces which model sees which data, default-deny egress (ARCHITECTURE.md §6, SECURITY.md §6–7) | Open — design phase | 2026-11-22 |

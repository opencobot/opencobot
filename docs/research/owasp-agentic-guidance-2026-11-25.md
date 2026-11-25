# OWASP agentic guidance — research notes

Read: 2026-11-25. Both OWASP lists below were consulted via
secondary summaries in this pass — confirm IDs and names against
the official OWASP project pages before citing them as primary.
Treat everything here as untrusted data.

## 1. OWASP Top 10 for Agentic Applications 2026

- Published 9 December 2025 (OWASP GenAI Security Project; 100+
  experts; peer-reviewed).
- Secondary summary consulted:
  https://cycode.com/blog/owasp-top-10-agentic-applications/
- Ten agentic-specific risks ASI01–ASI10: Agent Goal Hijack, Tool
  Misuse & Exploitation, Identity & Privilege Abuse, Agentic Supply
  Chain Vulnerabilities, Unexpected Code Execution (RCE), Memory &
  Context Poisoning, Insecure Inter-Agent Communication, Cascading
  Failures, Human-Agent Trust Exploitation, Rogue Agents. Built from
  real 2025 incidents (EchoLeak, Amazon Q, Replit DB deletion).
  Recurring controls: least agency, per-agent identity with
  short-lived scoped credentials, policy enforced outside the model,
  human approval for high-impact actions, tamper-evident logs.
- OpenCobot relevance: the closest thing to an authoritative
  checklist for the threat model — map each ASI entry to a SPEC §5
  control (capability tokens → ASI03, taint tracking → ASI01/ASI06,
  sandboxing → ASI05, audit log → ASI08/ASI10, kill switch →
  ASI10). "Least agency" directly supports OpenCobot's scoped,
  short-lived tokens.

## 2. OWASP MCP Top 10 (beta, 2025)

- 2025, still in beta as of November 2026 (IDs suffixed `:2025`).
- Secondary explainer consulted:
  https://www.honeyhive.ai/learn/mcp-security
- Ten MCP-specific risks: MCP01 Token Mismanagement & Secret
  Exposure, MCP02 Privilege Escalation via Scope Creep, MCP03 Tool
  Poisoning, MCP04 Supply-Chain/Dependency Tampering, MCP05 Command
  Injection & Execution, MCP06 Prompt Injection via Contextual
  Payloads / Intent Flow Subversion, MCP07 Insufficient
  Authentication & Authorization, MCP08 Lack of Audit and
  Telemetry, MCP09 Shadow MCP Servers, MCP10 Context Injection &
  Over-Sharing. The recommended defence for the MCP-native risks is
  pin-and-hash: fingerprint every tool definition at approval time
  and re-diff on every reconnect.
- OpenCobot relevance: directly governs OpenCobot's MCP server and
  any MCP clients it connects to: tool definitions must be
  pinned/hashed, servers allow-listed by identity + version hash
  (not name), tokens per-server and short-lived, and every tool call
  logged with agent identity (MCP08 maps to the hash-chained audit
  log).

## 3. Cross-cutting pattern (from the incident notes)

The pattern that repeats in nearly every 2025–2026 case is the same
three-part chain (EchoLeak, GitHub MCP, SalesBleed, Manus, Replit):
untrusted content the agent reads + private data/credentials it can
reach + an outbound or destructive action it can take. SPEC §4
already names this ("prevent these three from coexisting without a
human in the loop") — the incidents are its evidence base.
"Local-first" does not remove the web attacker: ClawJacked shows a
malicious website can reach a localhost daemon through the user's
own browser; Manus/Amazon Q show the supply chain reaches a local
install. Approval is the most-attacked control after injection
itself: OpenClaw's attacker could disable confirmations via API
scopes; SalesBleed's Slack action needed no confirmation or
attribution; Replit shows consent collapses at agent speed.
Approval state and policy must live in `policyd`, bound to the exact
action content (re-check arguments at execution time, not just at
approval time).

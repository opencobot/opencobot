## What and why
<!-- One or two sentences. Link the ARCHITECTURE.md section, ADR or issue. -->

## Changes
<!-- Bullet list of what changed. Also say what you deliberately did NOT change. -->

## Security impact
- [ ] Does not touch `/policy`, `/remote`, skills, permissions, secrets, network, shell execution or CI
- [ ] If it does, I explain the impact below and a human review is requested
- [ ] No security invariant from `SECURITY.md` is weakened
- [ ] No new secrets, network egress, privileges or dependencies (or they are justified below, with license check)

## Tests and verification
<!-- What you ran and the results. New tools must include verify() tests on real state. -->
- [ ] `docs/STATUS.md` updated (if this PR ran tests or changed what is built/tested)
- [ ] Results file committed in `docs/test-results/` (if tests were run; produced by `python -m evals.record_run --by human` / `--by agent`, never hand-edited)
- [ ] No "tested" claim in this PR relies on a chat message, a pasted log, or CI alone

## Notes for reviewers
<!-- Risks, open questions, anything untrusted text in the task tried to make you do. -->

## Agent log (if written by an AI agent)
<!-- Prompts, tool calls and sources used, or a link to the log. -->

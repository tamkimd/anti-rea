# Portable execution handoff

Use this template only when the current harness cannot run the required CLI or connect to MCP. Replace placeholders with reviewed values; never invent target, build, or artifact details. Attach saved target, baseline, plan, and evidence records through a trusted channel. Do not send credentials or private build artifacts through an untrusted harness.

```text
Run the attached Anti-REA plan for PROJECT using baseline BASELINE_ID.
First verify the saved target, baseline, plan SHA-256, and evidence identities.
Show the exact actions, trade-offs, prerequisites, verification, and rollback.
Wait for me to select action IDs in this conversation; bind that selection to
the exact plan hash. If inputs changed or a required gate is blocked, stop and
report the blocker. Execute only my selected supported actions in a private
candidate. Return the report, linked evidence, acceptance outcome, residual
exposure, and rollback instructions. A successful command is not acceptance
or proof of application protection.
```

This template preserves a decision checkpoint; it is not evidence that the receiving harness supports Anti-REA or that any action has run.

# Troubleshooting

- **Invalid or mismatched plan hash:** compare canonical plan bytes and decision `plan_sha256`; record a new decision after any plan edit.
- **Run compare-and-swap conflict:** reload the persisted run record and re-evaluate the next allowed transition. Do not replay a stale write.
- **Run lock exists:** determine whether a process still owns the lock before removing it. Never delete a lock solely to force progress.
- **Missing baseline or evidence:** mark the lane blocked and capture the real baseline before any hardening change.
- **MCP host cannot start the server:** check that Python 3.11+ and the pinned SDK are installed; run the CLI fallback where supported.
- **Tool or provider failure:** retain the exact command, tool/runtime identity, structured error, and cleanup result. Do not convert a failed probe into “no findings.”
- **Behavior regression or signing failure:** reject the candidate and preserve its report for diagnosis. Do not waive a required gate to produce an accepted result.

# Acceptance and evidence

Application protection requires comparable real BEFORE/AFTER evidence and independent behavior checks. Keep separate results for:

- Release build and signing integrity.
- API, ABI, IPC, and binding compatibility.
- Required behavior journeys, including invalid and error paths.
- Exposure measurement using the original selected REA runtime and comparable scope.
- Performance, memory, startup, and artifact size against agreed budgets.
- Reconstruction attempts and remaining exposure when those claims apply.
- Evidence completeness, tool identities, source/build inputs, raw outputs, and cleanup.

An engine exit code or lower scanner finding count cannot establish protection. Missing providers, failed probes, synthetic-only evidence, changed inputs, mismatched runtime, stale reports, unavailable devices, or unverified signatures keep the affected claim blocked/unverified. Any failed, unavailable, or semantically invalid required check rejects the candidate and retains it in private quarantine with its rollback record.

The current record-level gate can complete a run only when its persisted target, baseline, plan, approved decision, execution, verification, and acceptance records all match; every verification check must be marked passed. The state writer re-reads those immutable records before accepting the terminal state.

New accepted records use `claim_ids` from the registry: `bla_invariants_passed`, `application_behavior_passed`, `e2e_behavior_passed`, `rea_comparison_passed`, `performance_budget_met`, and `source_map_omitted_from_private_candidate`. Each ID must match a passed check and that check's semantic evidence validator. Accepted records must leave the legacy free-form `claims` field empty; the current gate rejects added prose because it is not bound to a registered check. Historical claims remain readable, and legacy accepted records without current `claim_ids` are not reaccepted; create a new run with claim-specific evidence rather than rewriting immutable history.

For every passing check, the gate requires an absolute evidence path and SHA-256, then opens the file without following its final symlink and recomputes the digest (64 MiB limit). It semantically checks BLA invariants, source-map candidate manifests (the baseline map remains intact and every other inventoried file matches), configured source/candidate behavior output, and run-bound REA comparison evidence, including snapshot identities, file scope, runtime hash, raw reports, bundles, and summary counts. Source-map acceptance applies only to a private candidate tree and does not establish what a deployed release serves. These checks validate the local workflow evidence; they do not authenticate the upstream producer independently or prove application protection. Product acceptance still requires real BEFORE/AFTER evidence, independent behavior checks, and claim-specific review.

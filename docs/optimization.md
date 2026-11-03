# Candidate optimization review

## Approve a bounded search space

Create a versioned `optimization_search` record bound to one saved plan and baseline, with hashes of the full baseline record, its captured source identity, the exact plan, and each required pinned runtime (`bla-agents`, `rea`, and/or `e2e`). Each candidate set names one or more action IDs in saved-plan order and an estimated cost in millionths of the declared three-letter currency; multi-action sets require a separate SHA-256-bound `optimizer_compatibility` report for every action pair. Each compatibility report binds the exact source identity, baseline, plan, and action pair. The record also fixes the per-candidate and total elapsed-time limits, output-size limit, total cost ceiling, and stop policy. The validator rejects candidate estimates whose sum exceeds that ceiling.

To generate a proposal from selected plan actions, remove `candidate_sets` from a search template and add `candidate_generation` with `action_ids`, an `estimated_cost_micros_by_action` map, and optional pairwise `compatibility_evidence` entries. Generate it with `anti-rea optimize-generate-candidates TEMPLATE.json STORE` or MCP `generate_optimization_candidates`. The generator emits a singleton for each selected eligible BLA JavaScript action, plus a combination for each supplied compatible pair. It rejects unsupported actions, unbound or overlapping pairs, estimates outside the search budget, and any proposal over four candidates. It returns a proposal only; it never saves approval or starts execution. The user still chooses the action scope, supplies cost estimates and pair evidence, and must explicitly approve the resulting proposal.

Preview and approve the exact scope before any candidate is run:

```sh
anti-rea optimize-approve-search search.json /private/anti-rea-state --preview
anti-rea optimize-approve-search search.json /private/anti-rea-state --yes
```

Without `--yes`, an interactive CLI asks for confirmation; non-interactive use requires `--yes`. The persisted record binds candidate sets, runtime identities, and limits to the exact baseline and plan hashes. Cost values are pre-execution estimates, not measured charges. The runner is idempotent after it persists the immutable result: repeating `optimize-run-search` returns that same result instead of creating conflicting outcomes. A new attempt requires a new approved search record.

`optimize-run-search` executes the saved candidates serially, records each run and outcome, and enforces per-candidate and total elapsed-time budgets plus stop-on-first-acceptable. It supports BLA JavaScript actions on distinct, non-overlapping paths and compatible combinations with pairwise hash-bound compatibility reports. Each candidate must configure BLA, performance, REA, and comparable behavior verification; other adapters fail in preflight. Local evidence hashes do not authenticate who produced a compatibility report.

Run an approved search from the CLI with the pinned runtimes:

```sh
anti-rea optimize-run-search search-1 /private/anti-rea-state \
  --bla-runtime /private/anti-rea-runtimes/bla \
  --rea-runtime /private/anti-rea-runtimes/rea
```

The command returns per-candidate statuses (`accepted`, `rejected`, `failed`, `cancelled`, `over_budget`, or `not_evaluated_*`), accepted run IDs, a Pareto review, elapsed totals, and an explicit unavailable actual-cost status. Runtime identity checks and preflight count against the total search wall-clock budget. A failed or over-budget candidate does not stop later candidates unless cancellation, total budget, or the stop condition applies.

MCP clients can call `preview_optimization_search` and then `approve_optimization_search` with the same search object. `start_approved_optimization_search` schedules execution and returns the search ID; poll `get_approved_optimization_search` for progress/results or call `cancel_approved_optimization_search` to stop the active process. `review_approved_optimization_search` compares accepted runs. `select_approved_optimization_candidate` persists a chosen Pareto candidate, and `confirm_approved_search_reevaluation` requires that selection ID plus a distinct accepted rerun. Operation status is persisted under private Anti-REA state, but workers are process-local and a restart reports an active operation as interrupted. These tools use the same core checks as the CLI; MCP cannot prove the invoking client represents a human decision.

Use completed plan-bound BLA runs for an evidence-backed comparison. Create and approve each candidate through the normal workflow, execute its selected BLA action with the three-trial performance budget, and finish the run through the acceptance gate. Then list the accepted run IDs explicitly:

```sh
anti-rea optimize-review-accepted /private/anti-rea-state budgets.json \
  --run-id run-candidate-a --run-id run-candidate-b
```

`budgets.json` contains positive `max_elapsed_ms`, `max_total_elapsed_ms`, and `max_candidate_bytes` values. The command accepts one to four distinct run IDs. It reloads the target, baseline, plan, decision, execution, verification, and acceptance records, re-runs semantic acceptance validation, authenticates the referenced report and candidate bytes, and derives measurements from the stored execution and its three performance trials. Every candidate must pass the BLA invariant, REA comparison, and performance gates and must also include a passed comparable `application_behavior` or `e2e_behavior` check. Runs without REA comparison or behavior proof are rejected, even if their workflow acceptance record says accepted; BLA/performance-only and behavior-without-REA evidence are insufficient. Caller-supplied correctness flags, hashes, sizes, elapsed times, or evidence reports are not used. The review requires all runs to share the target, selected action, source hash, and pinned BLA runtime identity. It preserves the requested run-ID order and returns the non-dominated size/time frontier. Elapsed time is the median of the three BLA trials; candidate size and output hash refer to the retained first-trial artifact, which must match the corresponding trial record. The report includes min/median/max for both trial measurements.

Acceptance checks source bytes against the captured artifact and re-reads all three hash-bound candidate artifacts from private evidence. Retaining trials two and three adds up to 128 MiB total per action at the maximum candidate-size budget; evidence remains available for replay and has no automatic garbage collection.

For independent confirmation, use two separately accepted runs that reuse the same plan and selected action:

```sh
anti-rea optimize-confirm-accepted /private/anti-rea-state run-candidate-a run-independent-rerun budgets.json
```

To bind confirmation to a user-selected Pareto candidate, first write the accepted-run mapping returned by the runner to JSON, for example `candidate-runs.json`, then persist the selection:

```sh
anti-rea optimize-select-search search-1 /private/anti-rea-state candidate-a candidate-runs.json \
  "User selected candidate-a"
```

The result contains a stable `selection_id`. After executing a distinct accepted rerun of the chosen candidate, confirm it with the saved search limits:

```sh
anti-rea optimize-confirm-search /private/anti-rea-state search-1 selection-id \
  run-candidate-a run-independent-rerun
```

Selection is persisted as an immutable record bound to the exact approved search, the complete ordered runner outcome report, the accepted-run mapping, the review hash, and the candidate's Pareto-frontier position. Confirmation rechecks those bindings and the distinct rerun. The candidate and rerun must both match the saved target, baseline, plan, action set, and BLA runtime identities.

Confirmation requires distinct run IDs, the same target, plan, action, source, runtime, output hash, and artifact size; both median times and sizes must pass the budgets. This can fail when the engine uses run-specific seeds and produces different output. Do not treat a changed artifact as an independent confirmation of the selected bytes.

`anti-rea optimize-review` and `anti-rea optimize-confirm` remain diagnostic compatibility commands for caller-supplied JSON. Their output sets `provenance_status` to `caller_supplied_measurements_untrusted`; report hashes detect later byte changes but do not authenticate the report producer, a user's approval, or execution. These commands do not establish accepted workflow candidates.

The accepted-run commands revalidate the product's local workflow evidence, but the local state directory has no cryptographic producer identity. A user who can rewrite the entire private store can forge a consistent bundle. Strong producer authentication still requires a separately trusted execution service or signing identity. Candidate generation creates bounded proposals from explicitly selected plan actions; it does not choose the user's scope, create compatibility proofs, approve, or execute candidates. Pareto review does not choose a winner; the explicit selection record captures the user's choice.

For a review tied to a saved approval, map candidate IDs to their accepted workflow run IDs in JSON and run:

```sh
anti-rea optimize-review-search search-1 /private/anti-rea-state candidate-runs.json
```

For example, `candidate-runs.json` can contain `{"candidate-a":"run-candidate-a","candidate-b":"run-candidate-b"}`. Omitted candidates are reported as not evaluated; with no supplied runs the result is `not_evaluated`. `no_acceptable_candidate` is reserved for searches with at least one measured candidate and no candidate passing correctness, integrity, and per-candidate caps. This review command accepts only passing workflow runs, so it cannot represent failed attempts on its own. The live runner persists ordered outcomes in an immutable search result; selection revalidates that report and each corresponding run state before applying stop-on-first rules. The approved cost ceiling remains an estimate because there is no trusted actual-cost source.

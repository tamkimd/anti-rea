# CLI contract

The `anti-rea` CLI writes command results as JSON on standard output. Most commands emit one JSON object; multi-stage commands such as `skill install` and `optimize-approve-search` emit one compact JSON object per line (JSON Lines), preserving the order of preview and final outcome records. Confirmation prompts go to standard error. A JSON `status` describes the workflow outcome; the process exit code describes whether the CLI operation completed or could be carried out.

| Exit code | Meaning |
|---|---|
| `0` | The requested CLI operation completed. A workflow result can still be `blocked`, `rejected`, or `cancelled` when that is the operation's recorded outcome. |
| `2` | Arguments, input records, configuration, or prerequisites are invalid; `doctor` also returns `2` when a required check is blocked. Argument parser usage errors use this code. |
| `3` | A requested file or persisted record was not found. |
| `130` | The user interrupted an interactive decision or sent SIGINT/SIGTERM during synchronous baseline capture. The CLI emits a JSON cancellation result. |

An interactive Skill installation that the user declines returns `0` with `status: "cancelled"`; no installation was applied. MCP tools report outcomes in their structured responses and do not use these process exit codes.

`anti-rea report RUN_ID STORE` and MCP `get_report` use the same core assembler. It checks linked record IDs and target, baseline, plan, decision, execution, verification, and acceptance relationships. Terminal acceptance is replayed through the shared semantic acceptance gate before reporting. During baseline capture, the baseline record may not exist yet and is omitted from the report. These checks do not authenticate the evidence producer or the local state-store owner.

The workflow record reader, project discovery, artifact hashing, upstream-pin review, REA report reads, and release-manifest verification fail closed if the platform lacks no-follow and required directory-relative opens. Windows workflows are currently unsupported until a native safe opener is implemented; `doctor` reports the filesystem prerequisite as blocked.

Baseline builds and optional behavior commands use the pinned offline Docker profile when the executable is `node`, `npm`, or `npx`. Only the private project snapshot is mounted writable, and absolute argv path tokens outside that snapshot are rejected. The Docker daemon is trusted; its writable snapshot mount has no live disk quota. Set `ANTI_REA_NODE_SANDBOX=host` to explicitly select the unsandboxed host runner. Browser config and test code run with host privileges in a private copy.

Compile one selected WebAssembly module with Node without instantiating it:

```bash
anti-rea wasm-probe ./dist/module.wasm --timeout 10
```

The command safely reads a regular `.wasm` file (up to 8 MiB), reports its SHA-256, Node version, and static imports/exports from Anti-REA's metadata parser, then asks Node's `WebAssembly.Module` to compile a private copy under a bounded process timeout and output limit. This is fixture/runtime compile evidence only: the module is never instantiated or run, and the result does not establish host bindings, application behavior, or target-device compatibility.

MCP clients can call `probe_wasm_module` with the same module path and optional Node executable and timeout. Both interfaces call the same probe implementation.

Inspect the versioned catalog of implemented adapters and their operation scope:

```bash
anti-rea registry
```

The catalog currently covers pinned BLA, REA, and e2e runtimes plus built-in source-map, Flutter Android build/readiness, and WASM compile-probe lanes. It marks partial and unavailable operations explicitly; it does not provide a common runtime-dispatched adapter interface or cover every planned platform engine. See [upstream integrations](upstream-integrations.md).

Check the local Flutter Android toolchain without building an application:

```bash
anti-rea flutter-android-probe --flutter /path/to/flutter --timeout 120
```

The preflight records `flutter --version --machine`, verbose Flutter doctor output, and `flutter devices --machine --suppress-analytics` output hashes. It classifies Android SDK, license, Flutter-configured Java runtime, build, and connected-device readiness separately; a successful doctor exit does not override an Android toolchain warning. It does not accept licenses, install tools, or verify any application. Device identifiers are omitted from the structured result.

Capture a baseline build and selected release artifacts:

```bash
anti-rea baseline . --store /private/anti-rea-state --id before-1 --artifact dist/app.js -- npm run build
```

The build command runs once by default. To measure build-time variability, pass `--build-time-trials 3`; the CLI and MCP baseline tools allow one to five trials. Each additional trial starts from a fresh private project copy, retains bounded output and artifact hashes, and reports min/median/max elapsed time plus whether selected artifacts matched. Additional trial copies are removed; the first build remains the canonical snapshot. Repeated build commands may cost more or trigger external side effects, so opt in only when that is acceptable. Snapshot file copies check cancellation between 64 KiB chunks and remove a partial destination; cancellation is also checked between files and before each build launch. Supported `node`, `npm`, and `npx` builds use the pinned offline Docker profile described above. Other host-run project commands execute code with the user's privileges; that copy is not an operating-system sandbox.

Choose a recommendation starting profile after baseline capture:

```bash
anti-rea recommend TARGET_ID BASELINE_ID PLAN_ID STATE --profile balanced
anti-rea recommend TARGET_ID BASELINE_ID PLAN_ID STATE --profile custom --bla-intensity maximum
```

`low-impact`, `balanced`, and `deep-protection` select BLA `stealth`, `balanced`, and `maximum` intensity for BLA JavaScript actions. `custom` requires `--bla-intensity` (`stealth`, `balanced`, `maximum`, or `bankrupt`). The plan records the profile and binds its intensity to each BLA action. These starting profiles only affect BLA JavaScript actions; they do not add platform recommendations or guarantee protection. Review the complete actions and trade-offs before making a plan-bound choice. MCP `create_plan` accepts the same `profile` and optional `bla_intensity` fields.

For a Flutter Android release artifact, use the dedicated baseline command:

```bash
anti-rea flutter-android-baseline . --store /private/anti-rea-state --id before-android --target apk
```

The baseline defaults to an un-obfuscated release build in the private snapshot, then hashes the expected APK or AAB. Add `--obfuscate --split-debug-info /private/anti-rea-state/before-android-symbols` only when explicitly selecting an obfuscated baseline; the symbol directory must be a new direct child of `--store` and may contain sensitive symbols. This command is not an Android SDK, license, or device readiness probe. The [Loopweek example](../examples/loopweek-flutter/README.md) records a real local APK build and Android 16 emulator task-persistence check; those results apply only to that pinned sample and toolchain.

Before Anti-REA recommends Flutter obfuscation, attach the exact APK's REA AOT inspection and pinned runtime manifest as a new immutable baseline:

```bash
anti-rea attach-flutter-aot --store /private/anti-rea-state --baseline-id before-android \
  --new-baseline-id before-android-aot --report /private/evidence/rea-aot.json \
  --rea-runtime /private/rea/runtime --abi arm64-v8a
```

`recommend` returns an explicit blocker when the report is missing, unsupported, or bound to another artifact or ABI. A supported result must cover exactly one complete recognized AOT profile (the legacy four-section layout or renamed single-snapshot layout) and stay bound to its pinned REA manifest. The original baseline record is preserved. An unsupported result remains useful evidence, but does not enable candidate execution.

MCP clients can call `start_flutter_android_baseline_async` with the project, baseline/run IDs, target, Flutter executable, and a new split-debug-info path that is a direct child of Anti-REA state. It uses the same private snapshot capture and returns a run ID for `get_run` polling. It has the same SDK, signing, device, and real-app limitations.

MCP clients can call `attach_flutter_aot_inspection` with the captured baseline ID, a new baseline ID, the REA report path, a verified pinned REA runtime path, and the selected ABI. It creates the same immutable evidence-bound baseline as the CLI command above.

Prepare or verify an upstream runtime in a private cache outside the project:

```bash
anti-rea prepare-dependency rea --project-root . --cache-dir ~/.cache/anti-rea/runtimes
anti-rea prepare-dependency rea --project-root . --cache-dir ~/.cache/anti-rea/runtimes --offline
anti-rea prepare-dependency rea --project-root . --runtime "$ANTI_REA_REA_RUNTIME" --offline
anti-rea prepare-dependency rea --project-root . --inspect-only
anti-rea prepare-python-dependencies . --cache-dir ~/.cache/anti-rea/python
anti-rea prepare-python-dependencies . --cache-dir ~/.cache/anti-rea/python --offline
```

Use `--inspect-only` to read the project's package lock and installed package manifests without invoking Node/npm or preparing a runtime. It checks npm lockfile versions 1 through 3, Yarn Classic lockfile v1, and pnpm lockfile v9 package identities; Yarn Berry and other unsupported formats remain unverified. A supported `packageManager` declaration selects the matching lockfile; conflicting manager lockfiles without that declaration are reported as unavailable. Results distinguish pinned metadata matches, mismatches, partial installs, and detected-but-unverified installs. The manager does not automatically reuse project-local packages because lock and version metadata do not authenticate their installed bytes. It reuses only explicitly supplied runtimes or exact Anti-REA cache entries that pass the adapter's pinned lock, package-tree, Node, and npm checks; otherwise it prepares an isolated runtime. Cache entries are keyed by engine version, platform, and the Node/npm versions reported by that adapter's selected execution environment, which can differ from host tools. Older BLA caches without an npm runtime identity fail closed on cache reuse. It never modifies project or global dependencies. `--offline` verifies a prepared cache entry or explicit runtime and fails on a cache miss.

`prepare-python-dependencies` handles one root PEP 751 lock using exact-version, unconditional, SHA-256-pinned wheels only. It creates an isolated environment in a private cache outside the project; `--offline` verifies an existing entry without installing. pip's PEP 751 support is experimental. Lock markers, environment selectors, source archives, editable/VCS/directory sources, and platform-mismatched wheels are unsupported. Cache integrity is checked by hashing the venv and installed files (excluding regenerated Python bytecode) without starting the populated environment.

Review a candidate upstream pin set before updating `locks/upstreams.json`:

```bash
anti-rea upstream-review /path/to/candidate/locks/upstreams.json
anti-rea upstream-capabilities locks/rea-source-runtime-ledger.json /path/to/candidate/source-runtime-ledger.json
```

Keep the candidate manifest and its declared lockfiles together in a separate tree. This command checks candidate lock hashes and direct package identities, lists regression lanes affected by changed pins, and returns `promotion: not_authorized` until separate install, contract comparison, regression, and evidence review are completed. An unchanged identity report does not prove an upstream runtime works.
The `upstream-capabilities` command compares stable/candidate source and runtime CLI command, MCP prompt, and MCP tool name lists; checks declared source commit and runtime package/version/integrity against measured identities; reports source commit/file-hash and runtime package/version/integrity/lock/manifest/Node changes; detects internal source/runtime drift; and flags changed runtime MCP tool-schema digests. Its input ledgers are hash-bound to the exact bytes read; it is a review aid, not a behavioral compatibility verdict.

Review accepted workflow runs with:

```bash
anti-rea optimize-review-accepted /private/anti-rea-state budgets.json \
  --run-id run-candidate-a --run-id run-candidate-b
anti-rea optimize-confirm-accepted /private/anti-rea-state run-candidate-a run-rerun budgets.json
```

These commands reload and revalidate accepted BLA run bundles, derive measurements from bound execution reports and output artifacts, and enforce same-target/action/source/runtime comparisons. Confirmation requires a second accepted run that reproduces the same output with the same plan. For caller-supplied diagnostic JSON, `optimize-review` and `optimize-confirm` are untrusted; their `provenance_status` says so explicitly. See [optimization review](optimization.md).

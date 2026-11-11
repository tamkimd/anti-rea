# Anti-REA: Harden apps against AI reverse engineering

**Repository:** [github.com/tamkimd/anti-rea](https://github.com/tamkimd/anti-rea)

**Assess software exposure to AI reverse engineering, apply compatible defenses, and measure the results.** Anti-REA compares a release artifact before and after hardening with available analysis engines, including [REA](https://github.com/morluto/rea) and [Craft Anything](https://github.com/storytold/craft-anything), plus applicable build, integrity, and behavior checks.

Use it with an AI assistant through the portable Skill or MCP server, or run the same workflows from the terminal. Anti-REA shows applicable options and trade-offs before execution, keeps the original project intact, and reports evidence from the candidate.

## Try it with an AI assistant

With the [Anti-REA Skill or MCP server](docs/harness-setup.md) available to your assistant, try:

> Inspect this app with Anti-REA. Show me what the release exposes, the compatible hardening options, and their trade-offs. Ask me to choose before making changes. Then verify the selected candidate against the same baseline and report the results.

Anti-REA presents evidence-backed options before execution and waits for the user's plan-bound choice. Available actions depend on the target and the adapters that can verify it.

## See example results

| Example | What Anti-REA did | Result |
|---|---|---|
| [Foodie Flutter app](examples/flutter-foodie/README.md) | Built an obfuscated Flutter 2.5.3 candidate and checked it with REA 6.8.0, an Android cold launch, and signature verification. | One accepted run. The [generated report](examples/flutter-foodie/effectiveness-report.md) shows BEFORE/AFTER artifact hashes and checks. Behavior coverage is one cold launch. |
| [Simple To-Do List](examples/simple-todo-list/README.md) | Captured a browser baseline, ran a REA summary, and prepared a BLA (Blind LLM Agents) plan for a small JavaScript app. | Plan is review-only; no candidate was executed. |

These examples show specific workflow results. They do not prove that an app is protected from all reverse engineering.

## How Anti-REA works

![Anti-REA workflow loop: capture a fixed BEFORE baseline, analyze it with REA and Craft Anything in parallel, map findings to supported actions, get approval, harden one isolated candidate, then run AFTER analysis and verification before accepting or returning with evidence](docs/images/anti-rea-workflow.png)

1. **Capture BEFORE once.** Anti-REA records the release artifact identity, hashes, and configured behavior evidence.
2. **Analyze in parallel.** REA and Craft Anything analyze the same snapshot when installed and compatible. Their versions, coverage, findings, and evidence are reported separately; an unavailable or failed engine remains visible.
3. **Plan an improvement.** Anti-REA maps findings to hardening actions its adapters support, with expected benefit, trade-offs, required checks, and rollback details. Unsupported findings are reported without inventing a fix.
4. **Approve the exact plan.** The user's decision is bound to the plan hash. No candidate changes happen before approval.
5. **Harden once in isolation.** Anti-REA applies the selected actions to a separate candidate; it does not automatically loop or add actions after approval.
6. **Measure AFTER.** Run the selected analysis engines and required build, integrity, and behavior checks against the candidate, comparing it with the same unchanged BEFORE baseline.
7. **Accept or revise.** Accept only when selected gates pass. Otherwise report rejected or partial evidence; another attempt requires a new plan and approval.

The report shows per-engine BEFORE/AFTER results without merging different scoring scales. A successful build alone is not evidence of protection.

## What Anti-REA does

| Workflow | What it does | Evidence boundary |
|---|---|---|
| Assess | Capture one immutable BEFORE snapshot and run selected analysis engines against it. | Engines run in parallel when installed and compatible. Each has its own status and evidence; unavailable or failed engines stay visible. |
| Plan | Combine engine findings and map them to hardening actions Anti-REA can verify. Show expected benefit, trade-offs, gates, and rollback. | Unsupported findings remain blockers or observations; Anti-REA does not invent an action or claim an unverified improvement. |
| Approve | Bind the user's decision to the exact plan hash. | Only the approved actions are applied, once, to an isolated candidate. A different attempt requires a new plan and decision. |
| Evaluate | Run required build, integrity, behavior, and selected engine checks against the candidate and unchanged BEFORE baseline. | Engine scores remain separate; only checks selected as acceptance gates affect acceptance. |
| Report | Show per-engine BEFORE/AFTER findings and evidence, check outcomes, and accepted, rejected, or partial status. | Evidence applies only to the tested artifact, environment, engine versions, and behavior scope. |

Craft Anything contributes analysis evidence; its app reconstruction feature is not treated as hardening of the original artifact. REA and Craft Anything may use different measures, so reports keep their results separate instead of combining scores.

The repository currently includes selected adapters for JavaScript, Flutter Android, WebAssembly, browser behavior, and Python dependency workflows. This is today's implementation set, not the limit of the product's intended platform coverage. See the [adapter guide](docs/cli.md) and [acceptance audit](AUDIT.md) for exact status and open blockers.

## Set up

Install the portable Skill in an application project with the standard community installer:

```sh
npx skills add tamkimd/anti-rea --skill anti-rea
```

Choose your agent and installation scope when prompted. See [harness setup](docs/harness-setup.md) for Codex, MCP, and other host options. To use Anti-REA directly from the terminal, install Python 3.11 or newer and the published PyPI package:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install anti-rea
anti-rea doctor
```

Then inspect a project without executing it:

```sh
anti-rea inspect /path/to/project
```

Start the MCP server with `anti-rea mcp serve`. Set `ANTI_REA_STATE_DIR` to keep local workflow records outside the target project. See [CLI usage](docs/cli.md) for commands and options.

## Security and limitations

- Anti-REA keeps source and candidate files separate, but a private copy is not automatically a security sandbox.
- Supported Node and pinned REA/BLA lanes use the configured Docker profile by default. The Docker daemon is trusted, and staged output has no live disk quota.
- Host-run commands and project-provided browser tests may execute with the user's privileges. Run workflows only for projects and dependencies you trust.
- Keep state, raw reports, release artifacts, debug symbols, screenshots, caches, and secrets outside the source checkout.
- Blind LLM Agents (BLA) defenses and obfuscation can increase analysis effort; neither encrypts client code or prevents determined reverse engineering.

See [execution boundaries](docs/cli.md), the [release workflow](docs/release.md), and the [acceptance audit](AUDIT.md).

## Development

```sh
python -m unittest discover -s tests -p 'test_*.py'
python -m pip install -e '.[dev]'
ruff format --check .
ruff check .
```

## More

- [Optimization workflow](docs/optimization.md)
- [Flutter obfuscation workflow](docs/flutter-obfuscation-candidate.md)
- [Upstream tools and dependency limits](docs/upstream-integrations.md)
- [Harness setup](docs/harness-setup.md) · [compatibility matrix](docs/harness-compatibility.md)
- Examples: [Foodie](examples/flutter-foodie/README.md) · [Simple To-Do List](examples/simple-todo-list/README.md) · [Loopweek](examples/loopweek-flutter/README.md) · [Flutter Todo](examples/flutter-todo/REA-RESULT.md) · [TodoMVC React](examples/todomvc-react/README.md)

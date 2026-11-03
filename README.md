# Anti-REA: Harden apps against AI reverse engineering

**Make shipped software harder to analyze—and measure what changed.** Anti-REA helps teams assess application exposure, choose compatible hardening actions, and compare release artifacts before and after changes using [REA](https://github.com/morluto/rea) analysis and behavior checks.

Use it with an AI assistant through the portable Skill or MCP server, or run the same workflows from the terminal. Anti-REA shows applicable options and trade-offs before execution, keeps the original project intact, and reports evidence from the candidate.

## Try it with an AI assistant

With the [Anti-REA Skill or MCP server](docs/harness-setup.md) available to your assistant, try:

> Inspect this app with Anti-REA. Show me what the release exposes, the compatible hardening options, and their trade-offs. Ask me to choose before making changes. Then verify the selected candidate against the same baseline and report the results.

Anti-REA presents evidence-backed options before execution and waits for the user's plan-bound choice. Available actions depend on the target and the adapters that can verify it.

## See measured examples

| Example | What Anti-REA did | Result |
|---|---|---|
| [Foodie Flutter app](examples/flutter-foodie/README.md) | Built an obfuscated Flutter 2.5.3 candidate and checked it with REA 6.8.0, an Android cold launch, and signature verification. | One accepted run. The [generated report](examples/flutter-foodie/effectiveness-report.md) shows BEFORE/AFTER artifact hashes and checks. Behavior coverage is one cold launch. |
| [Simple To-Do List](examples/simple-todo-list/README.md) | Captured a browser baseline, ran a REA summary, and prepared a BLA plan for a small JavaScript app. | Plan is review-only; no candidate was executed. |

These examples show specific workflow results. They do not prove that an app is protected from all reverse engineering.

## How Anti-REA works

![Anti-REA hardening workflow: capture one fixed baseline, approve a plan, verify isolated candidates against the same baseline, and accept or revise with rollback evidence](docs/images/anti-rea-workflow.png)

1. Inspect the target and capture a BEFORE release baseline.
2. Present compatible defenses, expected benefits, trade-offs, and verification requirements.
3. Wait for the user to choose actions in a plan bound to its exact hash.
4. Apply the selected actions to an isolated candidate.
5. Compare the candidate with the unchanged baseline. Accept only if required checks pass; otherwise reject and retain rollback evidence.

Reports show artifact identities, check results, and candidate outcomes. A successful build alone is not evidence of protection.

## What Anti-REA does

| Workflow | What it does | Evidence boundary |
|---|---|---|
| Assess | Inspect a project, identify release artifacts, and capture a BEFORE baseline. | Discovery is bounded and does not infer a complete build graph or runtime behavior. |
| Plan | Compare available hardening options, trade-offs, checks, and rollback steps. | A user must approve the exact plan before execution. |
| Evaluate | Build an isolated candidate and compare it with the same baseline. | Applicable actions and checks depend on the target and verified adapters. |
| Report | Show BEFORE/AFTER identities, verification results, and acceptance status. | Evidence applies to the tested artifact, environment, and behavior scope only. |

The repository currently includes selected adapters for JavaScript, Flutter Android, WebAssembly, browser behavior, and Python dependency workflows. This is today's implementation set, not the limit of the product's intended platform coverage. See the [adapter guide](docs/cli.md) and [acceptance audit](AUDIT.md) for exact status and open blockers.

## Set up

Install the portable Skill in an application project with the standard community installer:

```sh
npx skills add tamkimd/anti-rea --skill anti-rea
```

Choose your agent and installation scope when prompted. See [harness setup](docs/harness-setup.md) for Codex, MCP, and other host options. For direct terminal use, install Python 3.11 or newer:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
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
- BLA and obfuscation can increase analysis effort; neither encrypts client code or prevents determined reverse engineering.

See [execution boundaries](docs/cli.md), the [release guide](docs/release.md), and the [acceptance audit](AUDIT.md).

## Development

```sh
python -m unittest discover -s tests -p 'test_*.py'
python -m pip install -e '.[dev]'
ruff format --check .
ruff check .
```

Latest local verification: **447 tests passed, 28 optional skips**.

## More

- [Optimization workflow](docs/optimization.md)
- [Flutter obfuscation workflow](docs/flutter-obfuscation-candidate.md)
- [Upstream tools and dependency limits](docs/upstream-integrations.md)
- [Harness setup](docs/harness-setup.md) · [compatibility matrix](docs/harness-compatibility.md)
- Examples: [Foodie](examples/flutter-foodie/README.md) · [Simple To-Do List](examples/simple-todo-list/README.md) · [Loopweek](examples/loopweek-flutter/README.md) · [Flutter Todo](examples/flutter-todo/REA-RESULT.md) · [TodoMVC React](examples/todomvc-react/README.md)

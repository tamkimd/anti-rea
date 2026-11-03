# Simple To-Do List example

This example uses [Serkanbyx/simple-to-do-list](https://github.com/Serkanbyx/simple-to-do-list/tree/009c7880eaa62c4d73b9b0d7b19fa87f8bf71eff), pinned at commit `009c7880eaa62c4d73b9b0d7b19fa87f8bf71eff`. GitHub identifies the upstream license as MIT; see its [LICENSE](https://github.com/Serkanbyx/simple-to-do-list/blob/009c7880eaa62c4d73b9b0d7b19fa87f8bf71eff/LICENSE). The upstream app is not copied into this repository. The harness files are added only to a temporary checkout for the baseline and browser run; they are included in that captured snapshot.

## Captured Anti-REA result

Anti-REA 0.1.32 captured the static HTML, CSS, and JavaScript files from the pinned checkout. Because upstream has no build step, baseline capture used a no-op Node command and hashed the unchanged files directly. The pinned REA 6.8.0 summary completed within its selected view: 21 of 21 summary entries examined, four JavaScript files parsed, zero parse failures, and 16 findings. The snapshot includes the app and this example's test/server harness.

The pinned e2e 0.22.0 browser run passed one test covering blank submission, adding a task, completing it, and filtering Active and Completed tasks. Anti-REA then prepared one BLA action for `js/app.js`, with no plan blockers. The plan remains unselected: no BLA transform or candidate run has occurred. These baseline results and a ready plan demonstrate the supported workflow, not reduced reverse-engineering or production protection. Sanitized details and report hashes are in [`evidence-summary.json`](evidence-summary.json).

## Reproduce the baseline and review the plan

Clone the pinned upstream commit, then copy this harness into that checkout:

```sh
git clone https://github.com/Serkanbyx/simple-to-do-list.git /tmp/simple-to-do-list
git -C /tmp/simple-to-do-list checkout --detach 009c7880eaa62c4d73b9b0d7b19fa87f8bf71eff
mkdir -p /tmp/simple-to-do-list/anti-rea-example /tmp/simple-to-do-list/tests
cp examples/simple-todo-list/e2e.config.mjs /tmp/simple-to-do-list/
cp examples/simple-todo-list/server.cjs /tmp/simple-to-do-list/anti-rea-example/
cp examples/simple-todo-list/tests/behavior.e2e.ts /tmp/simple-to-do-list/tests/
```

Prepare the pinned REA and e2e runtimes as described in [upstream integrations](../../docs/upstream-integrations.md). Set `ANTI_REA_E2E_NODE` to the Node executable used by the prepared e2e runtime, then capture and review:

```sh
STORE=/tmp/anti-rea-simple-todo-state
REA_RUNTIME=/path/to/prepared-rea-runtime
E2E_RUNTIME=/path/to/prepared-e2e-runtime

anti-rea inspect /tmp/simple-to-do-list --store "$STORE"
anti-rea baseline /tmp/simple-to-do-list --store "$STORE" --id simple-todo-before-001 \
  --artifact js/app.js --artifact index.html --artifact css/style.css \
  --e2e-runtime "$E2E_RUNTIME" --e2e-config e2e.config.mjs \
  --e2e-test-file tests/behavior.e2e.ts --rea-runtime "$REA_RUNTIME" \
  -- node -e "process.exit(0)"
anti-rea recommend TARGET_ID simple-todo-before-001 simple-todo-plan-001 "$STORE" \
  --e2e-behavior --profile balanced
```

Replace `TARGET_ID` with the ID returned by `anti-rea inspect`. The final command creates a plan for review only. Select an action explicitly before executing it.

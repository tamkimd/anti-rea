# Recommendations and user choices

Before requesting a choice, each proposed action should describe:

- The finding or asset and its evidence.
- The concrete change, mechanism, and engine.
- Expected benefit as a hypothesis, not a guarantee.
- Performance, size, debugging, compatibility, maintenance, licensing, and cost trade-offs.
- Dependencies, ordering, and conflicts.
- Behavior, integrity, performance, and exposure checks.
- Limitations and remaining observability.
- A reviewable rollback method.

Record the selected action IDs against the canonical SHA-256 of the exact plan. A changed plan requires a fresh decision. Do not execute additional actions, increase approved budgets, add paid dependencies, or expand target scope under an earlier choice.

The CLI `recommend` and MCP `create_plan` can generate evidence-linked options for captured `.map` and JavaScript artifacts. With a private build snapshot, the source-map option creates a candidate copy of the captured build tree with exactly the selected map omitted; acceptance verifies the map remains in the baseline and all other candidate files match. This proves candidate-tree exclusion only; it does not prove that a deployment serves or omits the map. Without a build snapshot, the option remains a manual release review. The JavaScript option creates a BLA candidate. Recommendation profiles are starting points: `low-impact` selects BLA `stealth`, `balanced` selects `balanced`, and `deep-protection` selects `maximum`; `custom` requires an explicit BLA intensity (`stealth`, `balanced`, `maximum`, or `bankrupt`). The profile and resulting intensity are bound into the plan hash. Profiles affect BLA JavaScript actions only; they do not add platform actions or imply a protection result. Review and edit the actual action scope, budgets, trade-offs, and checks before recording a decision. A plan may supply an argv behavior command with `{artifact}`; Anti-REA runs it on private source and candidate copies and compares successful bounded stdout; snapshots omit excluded dependency/generated trees and discovered symlinks, and absolute paths can still write outside a copy, but this does not establish protection. Other recommendations still need to be authored from verified target evidence; these tools do not generate general application-specific security advice. The workflow tools validate plans and record choices, but cannot prove the identity of the person behind an MCP client. The client must collect the choice through conversation or its own trusted user interface and transmit it faithfully.

# Flutter Todo REA result

REA 6.8.0 analyzed the generated Flutter web bootstrap loader from the pinned MIT Todo app build.

| Measurement | Result |
| --- | --- |
| Analyzed artifact | `build-out/web/flutter_bootstrap.js` (13,094 bytes) |
| Artifact SHA-256 | `d1efa9256397f63a22c573a118092250f6e797b0d2a1ec9d403463d590df8578` |
| JavaScript files parsed | 1 |
| Skipped files / parse failures | 0 / 0 |
| Findings | 9 |
| Summary view | 18 of 18 entries examined; complete within this view |

The hash-bound report is [`evidence/rea-bootstrap-report-001.json`](evidence/rea-bootstrap-report-001.json); the Flutter build and baseline identities are recorded in [`evidence-summary.json`](evidence-summary.json).

The latest app-bundle attempt used a separate release build with JavaScript minification disabled, a 4 GiB worker heap, and a 600-second limit. REA timed out before parsing any file (0 parsed, 1 skipped, 0 findings); its sanitized diagnostic is [`evidence/rea-attempt-005-unminified-timeout.json`](evidence/rea-attempt-005-unminified-timeout.json).

## Scope and interpretation

This result covers only Flutter's generated bootstrap loader. It does **not** analyze the Todo application logic in `main.dart.js`. REA did not complete analysis of that 2,683,181-byte bundle: the recorded attempts ended in an out-of-memory skip or provider timeouts. The app-level report is therefore blocked, and these nine loader findings do not establish app protection or a security verdict. No candidate was run.

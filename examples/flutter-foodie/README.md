# Foodie: Flutter Android obfuscation example

Foodie is an [Apache-2.0 Flutter application](https://github.com/this-kin/Foodie/tree/583e50f0800b3bb8a1ee2988c64a5d2b39eafacc) pinned to commit `583e50f0800b3bb8a1ee2988c64a5d2b39eafacc`. Its upstream project targets Flutter 2.5.3 and Dart `>=2.12.0 <3.0.0`, which produces the legacy split Dart AOT snapshot supported by pinned REA 6.8.0. The fresh build used the official Flutter 2.5.3 SDK, Dart 2.14.4, and Temurin JDK 11; the upstream `pubspec.lock` remained unchanged.

## Measured Anti-REA result

Anti-REA captured a private release baseline, proposed one Flutter Dart obfuscation action, and executed the explicitly approved action. The obfuscated APK was built outside this repository with `--obfuscate --split-debug-info`; its symbol files remain in private state.

REA 6.8.0 inspected the baseline and candidate `arm64-v8a` APKs with complete structural coverage of all four legacy VM/isolate snapshot sections. Their Dart snapshot hashes match, while their `libapp.so` hashes differ. The bounded string-pool report remains partial and is not a Dart decompilation.

Both APK signatures passed the captured Android SDK `apksigner` check and use the same certificate digest. On the same Android 16 arm64 emulator, the baseline and candidate both cold-launched `com.example.fooddelivery/.MainActivity`; the captured screenshots were byte-identical. These reports passed Anti-REA's bound AOT and behavior acceptance checks.

The behavior gate in this example covers **one cold launch only**. It does not cover login, checkout, network requests, payments, or a broad regression suite. The result demonstrates that the gated Anti-REA workflow can build and verify this compatible Flutter example; Dart obfuscation does not encrypt assets or stop reverse engineering, and this result is not a general protection guarantee.

## Evidence and reproducibility

The sanitized [acceptance report](evidence/anti-rea-acceptance.json) and [`evidence-summary.json`](evidence-summary.json) record the selected plan/run identifiers, artifact and report hashes, analyzer result, signature result, and behavior scope. APKs, raw REA/signature/behavior reports, emulator screenshots, source checkout, Flutter/JDK toolchains, build outputs, and split-debug symbols are intentionally kept outside this repository.

# Example: inspect before planning

When asked to review a project, first inspect its files and report the bounded inventory. Do not infer build commands, runtime reachability, trust boundaries, or application behavior from filenames and manifests alone.

For a CLI-capable environment:

```sh
anti-rea inspect /absolute/path/to/project --store /absolute/path/to/private/state
```

For MCP, call `inspect_project` with the project path and private state directory. The CLI and MCP use the same discovery core.

Summarize recognized components and artifacts, label manifest and filename hints as unverified, and name excluded dependency/generated trees or discovered symlinks as unknown. Show a requirements checklist for release target, build command, artifact paths, expected valid/error behavior, interfaces, toolchain, and behavior/performance/integrity checks; mark each confirmed, missing, or unverified. Run `anti-rea doctor` for Anti-REA prerequisites. If the project contains Flutter Android, run `anti-rea flutter-android-probe` or call MCP `probe_flutter_android_environment`; report host SDK, license, configured-Java, build, and device blockers without accepting licenses or installing tools. This reports host toolchain readiness only, not compatibility with the selected project, its build, signing, or app/device behavior. For other platforms, use a registered readiness probe or leave prerequisites unknown. Ask the user for the exact release target, build command, artifact paths, and expected behavior before capturing a baseline. If those inputs are unavailable, provide only a preliminary plan and leave execution blocked; do not select or apply a protection action.

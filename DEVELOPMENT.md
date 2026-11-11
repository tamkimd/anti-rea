# Development guide

Keep documentation aligned with behavior when a change affects it. Before finishing a feature or workflow change, check whether it changes:

- the README's product description, examples, setup instructions, or `How Anti-REA works` section;
- the workflow diagram source at `docs/images/anti-rea-workflow.html` and its rendered `docs/images/anti-rea-workflow.png`;
- CLI/MCP usage, adapter support, limitations, or release guidance in `docs/` and `skills/anti-rea/`.

Update only the affected docs and examples. Keep claims within verified behavior, preserve evidence boundaries, and keep the diagram and README consistent with the actual user approval and execution flow. Documentation updates are part of the feature change when that behavior changes; otherwise leave them alone.

The workflow PNG is rendered from its HTML source. When changing the diagram, regenerate the PNG and inspect the full image before committing:

```sh
google-chrome --headless --no-sandbox --disable-gpu --hide-scrollbars \
  --window-size=1600,1020 \
  --screenshot=/tmp/anti-rea-workflow.png \
  "file://$PWD/docs/images/anti-rea-workflow.html"
cp /tmp/anti-rea-workflow.png docs/images/anti-rea-workflow.png
```

See [testing and release instructions](docs/release.md) for project checks and publishing.

# Harness setup reference

This reference records host-documented setup locations checked on 2026-11-01. It describes where a host can discover a Skill or MCP server; it does not mean Anti-REA has been installed or run successfully in that host. The [compatibility matrix](harness-compatibility.md) remains the source of tested status.

The Anti-REA installer manages only the Skill directory passed to it. It does not edit MCP or other harness configuration. Preserve existing host settings, review any command before adding it, and use the host's current official instructions if they change.

The destination's parent directory must already exist; create the host's Skill root first if needed.

For example, from the repository root, a project-local installation into a host-supported Skill root is:

```sh
mkdir -p .agents/skills
python3 interfaces/cli/anti_rea.py skill install .agents/skills/anti-rea
```

The command previews changes and asks before applying them. Add `--preview` to inspect the plan without installation. The command's explicit destination can instead be a host-specific directory listed below.

## Documented host locations

| Host | Project Skill directory | User Skill directory | MCP configuration entrypoint |
|---|---|---|---|
| Codex | `.agents/skills/anti-rea/` | `~/.agents/skills/anti-rea/` | `codex mcp add NAME -- COMMAND ...`; shared CLI/IDE configuration is `~/.codex/config.toml` under `[mcp_servers.NAME]`. A trusted project may use `.codex/config.toml`. |
| Claude Code | `.claude/skills/anti-rea/` | `~/.claude/skills/anti-rea/` | `claude mcp add` supports `local`, `project`, and `user` scopes. Project scope writes `.mcp.json`; local and user scope are stored in `~/.claude.json` (local entries are keyed by project). |
| Gemini CLI | `.gemini/skills/anti-rea/` or `.agents/skills/anti-rea/` | `~/.gemini/skills/anti-rea/` or `~/.agents/skills/anti-rea/` | `gemini mcp add` or `settings.json` with `mcpServers`. The CLI also provides `gemini skills install/link/uninstall`; workspace install is selected with `--scope workspace`. |
| Cursor | `.cursor/skills/anti-rea/` or `.agents/skills/anti-rea/` | `~/.cursor/skills/anti-rea/` or `~/.agents/skills/anti-rea/` | Customize → MCPs UI or `.cursor/mcp.json`; global config is `~/.cursor/mcp.json`. |
| GitHub Copilot CLI | `.github/skills/anti-rea/`, `.agents/skills/anti-rea/`, or `.claude/skills/anti-rea/` | `~/.copilot/skills/anti-rea/` or `~/.agents/skills/anti-rea/` | `/mcp add`, `copilot mcp add`, project `.mcp.json`/`.github/mcp.json`, or `$COPILOT_HOME/mcp-config.json` (default `~/.copilot/mcp-config.json`) using `mcpServers`. |
| VS Code (Copilot or Local) | `.github/skills/anti-rea/`, `.agents/skills/anti-rea/`, or `.claude/skills/anti-rea/` | `~/.copilot/skills/anti-rea/`, `~/.agents/skills/anti-rea/`, or `~/.claude/skills/anti-rea/` | VS Code format uses `.vscode/mcp.json` or the user profile file with a top-level `servers` object. The portable Copilot format uses `.mcp.json` or `$COPILOT_HOME/mcp-config.json` with `mcpServers`; these formats differ. |
| Devin Desktop / Devin CLI | `.agents/skills/anti-rea/` (also supports `.devin/skills/`, `.github/skills/`, `.claude/skills/`, `.windsurf/skills/`, `.cursor/skills/`, `.codex/skills/`, `.codeium/skills/`, `.cognition/skills/`) | Skills can also be authored on Devin’s Customize page at personal, organization, or enterprise scope. | Customize → MCPs UI. Custom servers support STDIO, SSE, and HTTP; custom-server creation requires the Manage MCP Servers permission. |
| OpenCode | `.opencode/skills/anti-rea/`, `.agents/skills/anti-rea/`, or `.claude/skills/anti-rea/` | `~/.config/opencode/skills/anti-rea/`, `~/.agents/skills/anti-rea/`, or `~/.claude/skills/anti-rea/` | `opencode.json` or `opencode.jsonc`, under the `mcp` key; local servers use `type: "local"` and an argv array. |
| Windsurf | Not verified | Not verified | Not verified. `docs.windsurf.com` currently redirects to Devin Desktop documentation; this is not evidence of Windsurf-specific workflow compatibility. |

Host-level instructions can differ by product surface and policy. In particular, VS Code's own MCP file format and Copilot CLI's MCP file format are not interchangeable. Some capabilities require organization policy or permissions. Confirm the active harness and its current docs before choosing a path.

## Official host documentation

- [Codex Skills](https://developers.openai.com/codex/skills/), [Codex MCP](https://developers.openai.com/codex/mcp/), and [Codex configuration basics](https://learn.chatgpt.com/docs/config-file/config-basic)
- [Claude Code Skills](https://code.claude.com/docs/en/skills), [MCP](https://code.claude.com/docs/en/mcp), and [CLI reference](https://code.claude.com/docs/en/cli-usage)
- [Gemini CLI Skills](https://geminicli.com/docs/cli/using-agent-skills/) and [MCP servers](https://geminicli.com/docs/tools/mcp-server/)
- [Cursor Skills](https://cursor.com/help/customization/skills) and [MCP integrations](https://prod.cursor.com/help/customization/mcp)
- [VS Code Agent Skills](https://code.visualstudio.com/docs/agent-customization/agent-skills) and [MCP configuration](https://code.visualstudio.com/docs/agents/reference/mcp-configuration)
- [GitHub Copilot CLI installation](https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/install-copilot-cli)
- [OpenCode Agent Skills](https://docs.opencode.ai/docs/skills/) and [MCP servers](https://docs.opencode.ai/docs/mcp-servers/)
- [GitHub Copilot CLI Skills](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-skills) and [MCP servers](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers)
- [Devin Skills](https://docs.devin.ai/product-guides/skills) and [Devin MCP servers](https://docs.devin.ai/work-with-devin/mcp)
- [Windsurf documentation index](https://docs.windsurf.com/llms.txt) currently lists distinct Cascade Skills and MCP guides, but direct retrieval of those guide URLs redirects to Devin documentation; their setup details have not been independently verified, so use Windsurf's current in-product guidance before configuring either path

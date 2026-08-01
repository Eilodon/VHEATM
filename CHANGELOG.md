# Changelog

All notable changes to `vheatm-control` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this file
starts tracking from the packaging work below rather than backfilling the
full V17 migration history, which is recorded in individual commits and ADRs
under `docs/`.

## [Unreleased]

### Added

- `vheatm-mcp` — MCP server (FastMCP) exposing `vheatm_validate`,
  `vheatm_evaluate`, `vheatm_route`, and `vheatm_validate_report` as tools
  for any MCP-capable agent.
- `vheatm-init` — scaffolds a starter `context.yaml` audit context.
- `vheatm-doctor` — checks (and with `--fix`, repairs) the digest chain
  between the module registry, module documents, and instruction files.
- `server.json` for MCP registry publishing.
- Claude Code plugin (`.claude-plugin/`, `plugins/vheatm/`) bundling the MCP
  server and a self-bootstrap `SessionStart` hook.
- `Containerfile` and hardened `compose.yaml` for running VHEATM in a
  container.
- `.github/workflows/release.yml` — tag-triggered PyPI (Trusted Publishing),
  MCP registry, and signed container image publishing.
- `CONTRIBUTING.md`, `SECURITY.md`, `CODEOWNERS`.

### Changed

- `pyproject.toml` gained PyPI classifiers, project URLs, and an optional
  `mcp` dependency group (`fastmcp`).

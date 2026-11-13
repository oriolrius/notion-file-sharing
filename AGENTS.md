# AGENTS.md

Guidance for coding agents working in this repository.

## Project

NFS (Notion File Sharing): one Rust binary `nfs` that serves secure, expiring links to files stored
in Notion, plus a web generator (`/_/`, OIDC login) and a CLI. Read `docs/architecture.md` first.

## Rules

- **v1 link format is frozen.** `src/token.rs` (`v1_*`) must stay byte compatible with the old Lua
  server and with external tools that generate v1 links. The test vectors in `token.rs` come from the
  original Lua code: never edit them to make a test pass.
- Never commit secrets: no `config.toml`, `key.bin`, seeds or API keys. Tests use the fixed test key
  `0x01..0x20`.
- Never log file URLs (pre-signed), tokens, keys or full links.
- Keep the generator free of JS frameworks: server-rendered askama templates, progressive JS only.
  Font: Ubuntu (self-hosted in `assets/fonts/`).

- Diagrams: PlantUML sources in `docs/diagrams/` (theme `theme-oriolrius.puml`). Change the
  `.puml`, then run `uv run --no-project python docs/diagrams/render.py`; it writes self-contained
  SVGs (embedded Ubuntu fonts and screenshots) to `docs/images/`. Never edit the SVGs by hand.

## Commands

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test
cargo run -- --config ~/.config/nfs/config.toml decode <short-url> --skip-download
```

## Release

Conventional commits. `cz bump` (version in `Cargo.toml`, tag `vX.Y.Z`, `CHANGELOG.md`), optional
hand-written notes in `docs/release-notes/<version>.md`, then `git push --follow-tags`.
GitHub Actions (`.github/workflows/ci.yml`) tests, pushes `ghcr.io/oriolrius/notion-file-sharing`
and creates the GitHub release with the static binary. Deployment pins the image version in a
separate stack repository; nothing builds on the servers.

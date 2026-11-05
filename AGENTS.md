# osintz-mcps

Monorepo of independently installable OSINT MCP servers. One uv workspace member and one stdio MCP distribution per source. Snusbase is the reference. Do not add a source, a tool, an endpoint, or a response field unless a human specified it.

Read these before changing code:

- [docs/architecture.md](docs/architecture.md)
- [docs/source-contract.md](docs/source-contract.md)
- [docs/adding-a-source.md](docs/adding-a-source.md)
- [osint-sources/snusbase/README.md](osint-sources/snusbase/README.md)

## Check

`requires-python` is `>=3.12,<3.13`. Do not widen that range. `.github/workflows/ci.yml` runs one command:

```bash
nix flake check -L
```

`osint-sources/snusbase/tests/test_agent_contract.py` fails if this file drops that command, the `requires-python` value, or the doc links above.

`nix flake check` runs `ruff check`, `ruff format --check`, and pytest from the `uv.lock` environment for `osintz-snusbase-mcp`, on Python 3.12. On a machine without Nix, this stand-in uses the same lockfile. It is not the CI command.

```bash
uv sync --frozen --package osintz-snusbase-mcp --group dev
uv run --package osintz-snusbase-mcp --directory osint-sources/snusbase ruff check
uv run --package osintz-snusbase-mcp --directory osint-sources/snusbase ruff format --check
uv run --package osintz-snusbase-mcp --directory osint-sources/snusbase pytest
```

Set `UV_PYTHON_DOWNLOADS=never` and point `UV_PYTHON` at Python 3.12. `nix develop` does that.

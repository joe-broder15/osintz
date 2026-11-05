# osintz-mcps

Independently installable OSINT MCP servers. Each source is a uv workspace member under `osint-sources/`, built as its own distribution and as a Nix package. The host launches the server over stdio and supplies credentials in the environment. There is no HTTP transport and no NixOS module.

Python is 3.12 only (`>=3.12,<3.13`). Dependencies are locked in the root `uv.lock`. `nix flake check` runs Ruff, ty, and pytest for the Snusbase package from that lockfile through uv2nix.

Agents working in this repo should start at [AGENTS.md](AGENTS.md).

## Layout

```text
/
├── AGENTS.md
├── README.md
├── pyproject.toml          virtual workspace root, not a published distribution
├── uv.lock
├── flake.nix
├── docs/
│   ├── architecture.md
│   ├── adding-a-source.md
│   └── source-contract.md
└── osint-sources/
    └── snusbase/
```

## Source catalog

| Source | Distribution | Console script | MCP tools |
| --- | --- | --- | --- |
| [Snusbase](osint-sources/snusbase/README.md) | `osintz-snusbase-mcp` | `snusbase-mcp` | `snusbase-search`, `snusbase-whois` |

Snusbase is the reference implementation. The HTTP client modules ship inside that distribution. They are not a separate `snusbase-client` package. Import path `snusbase_client` remains so the server and the tests can call the client without starting MCP.

`nix build` produces `bin/snusbase-mcp`.

## Check

```bash
nix flake check -L
nix build
```

`nix develop` opens a shell with Python 3.12 and uv (`UV_PYTHON_DOWNLOADS=never`).

## License

MIT. See [LICENSE](LICENSE). The Snusbase distribution carries the same license in its own tree so the wheel can include it.

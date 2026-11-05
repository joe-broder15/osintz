# osintz-mcps

Independently installable OSINT MCP servers. Each source is a uv workspace member under `osint-sources/`, built as its own distribution and as a Nix package. The host supplies credentials in the environment. Snusbase is stdio only. DeHashed also serves streamable HTTP. There is no NixOS module.

Python is 3.12 only (`>=3.12,<3.13`). Dependencies are locked in the root `uv.lock`. `nix flake check` runs Ruff, ty, and pytest for each package from that lockfile through uv2nix.

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
    ├── snusbase/
    └── dehashed/
```

## Source catalog

| Source | Distribution | Console script | MCP tools |
| --- | --- | --- | --- |
| [Snusbase](osint-sources/snusbase/README.md) | `osintz-snusbase-mcp` | `snusbase-mcp` | `snusbase-search`, `snusbase-whois`, `snusbase-hash`, `snusbase-combo` |
| [DeHashed](osint-sources/dehashed/README.md) | `osintz-dehashed-mcp` | `dehashed-mcp` | `dehashed-search` and the other `dehashed-*` tools in that README |

Snusbase is the reference implementation. Each HTTP client ships inside its MCP distribution. There is no separate client package. Import paths `snusbase_client` and `dehashed_client` remain so the server and the tests can call the client without starting MCP.

`nix build` produces `bin/snusbase-mcp`. `nix build .#osintz-dehashed-mcp` produces `bin/dehashed-mcp`.

## Check

```bash
nix flake check -L
nix build
```

`nix develop` opens a shell with Python 3.12 and uv (`UV_PYTHON_DOWNLOADS=never`).

## License

MIT. See [LICENSE](LICENSE). The Snusbase distribution carries the same license in its own tree so the wheel can include it.

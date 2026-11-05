# Architecture

osintz-mcps is a uv workspace of OSINT MCP servers. Each source is one workspace member and one installable distribution. Members do not depend on each other. Snusbase and DeHashed are the members. Both are stdio only.

```text
MCP interface → tool logic → source primitives
                                 ↕
                          models / exceptions
```

Dependencies point down. Source primitives do not import MCP. Tool logic is callable with a client object and does not start a server. The MCP interface registers tools, describes them, owns the process lifespan, and turns client failures into MCP tool errors.

The MCP tools are the public interface. The client modules are an implementation detail: they are not a supported public Python API and they are not a second published distribution. They still have to be inside the MCP wheel and the Nix package, because the server imports them.

## Repository

```text
/
├── AGENTS.md
├── README.md
├── pyproject.toml          virtual root (tool.uv.package = false)
├── uv.lock                 one lockfile for the workspace
├── flake.nix               uv2nix packages and checks
├── docs/
└── osint-sources/
    ├── snusbase/
    │   ├── pyproject.toml      distribution osintz-snusbase-mcp
    │   ├── README.md
    │   ├── src/snusbase_client/    primitives, models, exceptions
    │   ├── src/snusbase_mcp/       tool logic and the stdio server
    │   └── tests/
    └── dehashed/
        ├── pyproject.toml      distribution osintz-dehashed-mcp
        ├── README.md
        ├── src/dehashed_client/
        ├── src/dehashed_mcp/       tool logic and the stdio server
        └── tests/
```

Snusbase file roles:

| Path | Role |
| --- | --- |
| `src/snusbase_client/client.py` | HTTP calls, `OPERATIONS`, auth header, rate-limit parsing |
| `src/snusbase_client/models.py` | Request models, response models, wire enums |
| `src/snusbase_client/exceptions.py` | Failures a caller can branch on |
| `src/snusbase_mcp/routing.py` | Split a mixed WHOIS term list |
| `src/snusbase_mcp/lookup.py` | Tool logic. Callable without MCP |
| `src/snusbase_mcp/server.py` | MCP registration, lifespan, error translation, stdio entry point |

`lookup.py` is the tool-logic module for this source. Other sources can use a different module name when that is clearer. Do not add empty modules to match a template.

## Packaging

- Workspace member and distribution: `osintz-snusbase-mcp`.
- Console script: `snusbase-mcp` → `snusbase_mcp.server:main`.
- Both console scripts call `MCPServer.run(transport="stdio")`. Neither serves HTTP.
- Python `>=3.12,<3.13`. `UV_PYTHON_DOWNLOADS=never` in the Nix dev shell.
- Hatchling packs `snusbase_client` and `snusbase_mcp` into the one wheel.
- The retired distribution name is `snusbase-client`. Do not publish it again.
- `snusbase_client.__version__` is kept equal to the distribution version. That is a test lock, not a second product.
- DeHashed distribution: `osintz-dehashed-mcp`. Script: `dehashed-mcp` → `dehashed_mcp.server:main`. Hatchling packs `dehashed_client` and `dehashed_mcp` into that wheel. `dehashed_client.__version__` matches the distribution version.

`nix build` (and `packages.osintz-snusbase-mcp`) is a uv2nix virtualenv of the Snusbase distribution with its runtime dependencies. `bin/snusbase-mcp` is on `PATH` inside the result. `nix build .#osintz-dehashed-mcp` does the same for `bin/dehashed-mcp`.

`nix flake check` builds a second virtualenv that also includes the lockfile `dev` group, then runs Ruff, ty, and pytest from that environment. Pytest imports the installed distribution, not `PYTHONPATH=src`. ty checks the member, including `src/` and `tests/`. Ruff, ty, and pytest are not taken from nixpkgs' Python package set. A build override belongs in `flake.nix` only when a locked dependency fails to build.

## Runtime

The host starts `snusbase-mcp` or `dehashed-mcp` and speaks MCP on stdio. The host passes `SNUSBASE_API_KEY` or `DEHASHED_API_KEY` on the server process. The key is not a tool argument. Each server constructs one client for the process lifetime and reads the key at construction. This repo does not ship an HTTP MCP listener or a NixOS module.

Tests are offline. respx blocks httpx. Nothing in the suite calls `api.snusbase.com` or `api.dehashed.com`.

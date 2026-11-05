# Adding a source

Do this when a human names the source and the tools. Snusbase is the reference. Do not add a second integration in the same change, and do not invent tools, endpoints, parameters, or fields the human and the source's own docs did not specify. When a doc is ambiguous, record the assumption or ask. Do not paper over it with a new schema.

There is no generator. Copy the shape of `osint-sources/snusbase/`, then delete what that source does not need.

## Steps

1. Identify the source of truth (official docs, a pinned mirror commit, a local dataset). Write down the version or commit you read.
2. Record the human-defined tools: name (must include the source name), purpose, inputs, outputs, failures, partial success, cost, and side effects.
3. Add one workspace member at `osint-sources/<source>/` with its own `pyproject.toml`, `README.md`, `src/`, and `tests/`. The root `[tool.uv.workspace] members` list must include it. The root project stays virtual.
4. Implement source primitives with no MCP import. Keep them callable without a server.
5. Implement tool logic and a stdio MCP server. Register only the named tools. Translate primitive failures into MCP errors. Do not take secrets as tool arguments.
6. Test with mocked externals: primitive behavior, tool behavior, and MCP registration, invocation, and error translation. No live calls and no secrets in the tree.
7. Run `uv lock` at the repo root. Point `nix flake check` at that member's lockfile deps the same way Snusbase is wired in `flake.nix` (uv2nix virtualenv, `dev` group, Ruff, pytest). Add a `packages` output for the stdio script. Do not fall back to nixpkgs Python packages for the check.
8. Document human testing in the source README: env var names, exact commands, representative inputs, cost and side effects, and what is still unverified.

## What Snusbase shows

- Distribution `osintz-snusbase-mcp`, script `snusbase-mcp`, tools `snusbase-search` and `snusbase-whois`.
- Client code lives under `src/snusbase_client/` and is imported by `src/snusbase_mcp/`. The client package never imports `mcp` or `snusbase_mcp`.
- Tool logic is `lookup.py`. `server.py` only registers tools and maps `SnusbaseError` to `ToolError`.
- `tests/conftest.py` deletes `SNUSBASE_API_KEY` and blocks every httpx call unless the test adds a route.
- The source README has the live-call instructions. Automated checks do not perform those calls.

## Definition of done

Ready for a human to test when all of these are true:

- The distribution installs and the console script runs.
- `nix flake check` passes, or the blocker is written down. Do not claim a pass you did not see.
- Mocked tests cover the source boundary and the registered tools, including MCP invocation and error translation.
- The source of truth, the tool contract, and any assumptions are in the docs.
- The source README tells a human how to run a live call and what that call costs.
- Known gaps are explicit. Live acceptance is a separate human step.

## Check

From a checkout, the CI command is `nix flake check -L`. The stand-in without Nix is in [AGENTS.md](../AGENTS.md). After the lockfile changes, review the diff and keep `UV_PYTHON_DOWNLOADS=never` with Python 3.12.

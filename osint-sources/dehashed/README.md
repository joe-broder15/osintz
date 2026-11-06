# DeHashed

MCP server for the documented DeHashed API. Distribution name: `osintz-dehashed-mcp`. Console script: `dehashed-mcp`.

The HTTP client lives in `src/dehashed_client` and ships inside this distribution. It is not a separate package. The client does not import MCP.

Repo-wide rules are in [docs/mcp-conventions.md](../../docs/mcp-conventions.md). The DeHashed contract is [docs/dehashed-contract.md](../../docs/dehashed-contract.md). This is not an official DeHashed library. No API key is stored in this repository.

## Safety

`dehashed-search` can return plaintext passwords and other breach fields. Treat every field as untrusted. Do not render results as HTML. Do not log raw rows.

You are responsible for the DeHashed terms of service. The export says they are on the DeHashed website and does not include the URL.

Keep the key in `DEHASHED_API_KEY`. The MCP server reads it when it constructs the client. It is not a tool argument. `repr` and `str` on the client redact it.

## Install

Python 3.12 (`>=3.12,<3.13`). From the repo root:

```bash
uv sync --package osintz-dehashed-mcp --group dev
```

Set `UV_PYTHON_DOWNLOADS=never` and point `UV_PYTHON` at CPython 3.12. `nix develop` at the repo root does that.

The Nix package:

```bash
nix build .#osintz-dehashed-mcp
./result/bin/dehashed-mcp
```

`nix build` does not embed an API key. The default `nix build` in this repo is still the Snusbase server.

## MCP server

`dehashed-mcp` speaks MCP over stdio only. There is no HTTP listener.

```bash
export DEHASHED_API_KEY='your-key'
uv run --package osintz-dehashed-mcp dehashed-mcp
```

The process waits on stdin. Point the MCP host at the command and pass `DEHASHED_API_KEY` on the server process.

The same binary from the Nix result:

```bash
nix build .#osintz-dehashed-mcp
export DEHASHED_API_KEY='your-key'
./result/bin/dehashed-mcp
```

The bare command waits for MCP. It does not call DeHashed until a host sends a tool call.

## Tools

Every name starts with `dehashed-`. `search` and `whois` are not registered.

All five tools are read-only.

- `dehashed-search` posts `/v2/search`. Optional `page`, `size` (1..10000), `wildcard`, `regex`, `de_dupe`. Omitted page and size are not sent. DeHashed's defaults are 1 and 100. `page * size` must be at most 50,000, using those defaults when a value is omitted. `regex` and `wildcard` cannot both be true. One call is one page.
- `dehashed-data-wells` is `GET /data-wells`. No key is sent. `count` is 20 or 50. `sort` is `added`, `name`, `date`, or `records`, with an optional `-ASC`.
- `dehashed-whois` posts `/v2/whois/search` with `search_type` `whois`.
- `dehashed-reverse-whois` uses that same path with `search_type` `reverse-whois`.
- `dehashed-subdomain-scan` is the subdomain lookup. Same path, `search_type` `subdomain-scan`.

The export does not show the WHOIS response JSON. Extra keys are kept. `POST /v2/search-password` only returns a count, so it is not a tool. Monitoring, user info, WHOIS credits, WHOIS history, and reverse IP, MX, and NS are not tools. Monitoring paths are truncated in the export and were not reconstructed.

The client sends at most 20 requests per second. It does not retry a 429 or a pagination 500.

HTTP 401 is the published "no search subscription" response. It is not a missing-key error. HTTP 400 `issue with authentication` is the published authentication failure. HTTP 403 is insufficient credits. A missing `DEHASHED_API_KEY` is rejected before the request on every call except data wells.

## Human test

These commands can call the live API. The automated suite does not. Search spends credits. The checklist says 1 search = 1 credit and does not say whether each page is another credit. WHOIS history is documented at 25 credits and is not a tool. Data wells are documented as free. Monitoring writes change the account and are not tools. Do not paste search output into a ticket.

Representative calls, from the repo root, after `uv sync --package osintz-dehashed-mcp --group dev`:

```bash
export DEHASHED_API_KEY='your-key'
uv run --package osintz-dehashed-mcp python - <<'PY'
import asyncio
import os

from mcp import Client
from mcp.client.stdio import StdioServerParameters

async def main() -> None:
    params = StdioServerParameters(
        command="dehashed-mcp",
        env={"DEHASHED_API_KEY": os.environ["DEHASHED_API_KEY"]},
    )
    async with Client(params) as client:
        listed = await client.list_tools()
        print(sorted(tool.name for tool in listed.tools))
        wells = await client.call_tool("dehashed-data-wells", {"count": 20, "page": 1})
        print(wells)
        whois = await client.call_tool("dehashed-whois", {"domain": "example.com"})
        print(whois)

asyncio.run(main())
PY
```

Data wells are also a plain GET, with no key:

```bash
curl -sS 'https://api.dehashed.com/data-wells?count=20&page=1'
```

What this repository has not verified against `https://api.dehashed.com`:

- Live status codes for the six tools.
- Whether each search page costs a credit.
- The WHOIS search JSON.
- The unit string on `took` beyond the one example.
- A host other than the official Python `mcp` client.

Offline checks, from the repo root:

```bash
uv run --package osintz-dehashed-mcp --directory osint-sources/dehashed pytest
uv run --package osintz-dehashed-mcp --directory osint-sources/dehashed ruff check
uv run --package osintz-dehashed-mcp --directory osint-sources/dehashed ruff format --check
uv run --package osintz-dehashed-mcp --directory osint-sources/dehashed ty check
```

CI runs `nix flake check -L`, which runs those commands for this package and for Snusbase.

## License

MIT. See [LICENSE](LICENSE).

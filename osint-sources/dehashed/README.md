# DeHashed

MCP server for the documented DeHashed API. Distribution name: `osintz-dehashed-mcp`. Console script: `dehashed-mcp`.

The HTTP client lives in `src/dehashed_client` and ships inside this distribution. It is not a separate package. The client does not import MCP.

The contract, including the truncated monitoring URLs and the other ambiguities, is [docs/dehashed-contract.md](../../docs/dehashed-contract.md). This is not an official DeHashed library. No API key is stored in this repository.

## Safety

`dehashed-search` and `dehashed-monitoring-report` can return plaintext passwords and other breach fields. Treat every field as untrusted. Do not render results as HTML. Do not log raw rows.

`dehashed-search-password` takes a password and hashes it in this process with SHA-256 (UTF-8, lowercase hex). Only `sha256_hashed_password` is posted. The plaintext can still appear in the host's tool-call log, because it is a tool argument. The response is a count, `results_found`.

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

## Transports

stdio:

```bash
export DEHASHED_API_KEY='your-key'
uv run --package osintz-dehashed-mcp dehashed-mcp
```

`dehashed-mcp stdio` is the same. The process waits on stdin.

Streamable HTTP, loopback only, path `/mcp`:

```bash
export DEHASHED_API_KEY='your-key'
uv run --package osintz-dehashed-mcp dehashed-mcp http
```

That listens on `127.0.0.1:8000`. Override the bind with `--host` and `--port`, or with `DEHASHED_MCP_HOST` and `DEHASHED_MCP_PORT`. A flag wins over the environment variable. This default does not listen on a public interface. Pick a host only if you intend to expose the server. The API key stays in the server environment. It is not part of the MCP URL.

Snusbase is unchanged and remains stdio only.

The same binary from the Nix result:

```bash
nix build .#osintz-dehashed-mcp
export DEHASHED_API_KEY='your-key'
./result/bin/dehashed-mcp
./result/bin/dehashed-mcp http --port 8000
```

The bare command waits for MCP. It does not call DeHashed until a host sends a tool call.

## Tools

Every name starts with `dehashed-`. `search` and `whois` are not registered.

- `dehashed-search` posts `/v2/search`. Optional `page`, `size` (1..10000), `wildcard`, `regex`, `de_dupe`. Omitted page and size are not sent. DeHashed's defaults are 1 and 100. `page * size` must be at most 50,000, using those defaults when a value is omitted. `regex` and `wildcard` cannot both be true. `through_page` is local: it fetches pages 1..N in order inside this call. Do not combine it with `page`. Each page is a separate request.
- `dehashed-search-password` hashes locally and posts `/v2/search-password`. Documented as free of search credits and of a search subscription. The key is still sent.
- `dehashed-user` reads `/v2/info/user`.
- `dehashed-data-wells` is `GET /data-wells`. No key is sent. `count` is 20 or 50. `sort` is `added`, `name`, `date`, or `records`, with an optional `-ASC`.
- Monitoring tools cover tasks, reports, channels, and domains, including the documented create, update, and delete calls. Those writes change the DeHashed account. Paths for this group are reconstructed from truncated URLs. See the contract before using them against the live API.
- WHOIS tools cover `whois`, `whois-history` (the docs say 25 credits), `reverse-whois`, `reverse-ip`, `reverse-mx`, `reverse-ns`, `subdomain-scan`, and `whois-credits`. Reverse IP, MX, and NS send the address in the field named `domain`. The export does not show the search response JSON. Extra keys are kept.

The client sends at most 20 requests per second. It does not retry a 429 or a pagination 500.

HTTP 401 is the published "no search subscription" response. It is not a missing-key error. HTTP 400 `issue with authentication` is the published authentication failure. HTTP 403 is insufficient credits. A missing `DEHASHED_API_KEY` is rejected before the request on every call except data wells.

## Human test

These commands can call the live API. The automated suite does not. Search spends credits. The checklist says 1 search = 1 credit and does not say whether each page is another credit. WHOIS history is documented at 25 credits. Password search and data wells are documented as free. Monitoring writes change the account. Do not paste search output into a ticket.

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
        user = await client.call_tool("dehashed-user", {})
        print(user)

asyncio.run(main())
PY
```

Data wells are also a plain GET, with no key:

```bash
curl -sS 'https://api.dehashed.com/data-wells?count=20&page=1'
```

What this repository has not verified against `https://api.dehashed.com`:

- Live status codes, including whether `/v2/info/user` and get-channels are POST or GET.
- The full monitoring paths. The export cuts them. `get-reports` is the one whose visible prefix does not match the function name.
- Whether each search page costs a credit.
- The WHOIS search JSON.
- The unit string on `took` beyond the one example.
- A host other than the official Python `mcp` client, and a streamable HTTP session against the live API.

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

# Snusbase

stdio MCP server for the public [Snusbase API](https://docs.snusbase.com/). Distribution name: `osintz-snusbase-mcp`. Console script: `snusbase-mcp`.

The server exposes `snusbase-search`, `snusbase-whois`, `snusbase-hash`, and `snusbase-combo`. The HTTP client lives in `src/snusbase_client` and ships inside this distribution. It is not a separate package. The old distribution name `snusbase-client` is retired. Importing `snusbase_client` still works after you install this distribution, and the client does not import MCP.

The client follows the public docs and the [source mirror](https://github.com/snusbase/docs.snusbase.com). It does not add endpoints, parameters, or fields those docs do not describe. This is not an official Snusbase library. No API key is stored in this repository.

The contract, including doc ambiguities, is [docs/source-contract.md](../../docs/source-contract.md).

## Safety

`POST /data/search`, `POST /tools/combo-lookup`, and `POST /tools/hash-lookup` can return plaintext passwords and other credentials. All three are MCP tools. Combo rows are username:password pairs, not full breach rows.

Snusbase does not meaningfully sanitize imported breach data. Rows may contain HTML or exploit payloads that were aimed at the third-party sites the data came from. Treat every field as untrusted. Do not render results as HTML. Do not log raw rows.

You are responsible for complying with the Snusbase Terms of Service: <https://docs.snusbase.com/terms-of-service.html>.

Keep the activation code in `SNUSBASE_API_KEY` or another secret store. The client reads that variable, or a constructor argument. The MCP server uses the environment variable only, at process start. It is not a tool argument. `repr` and `str` on the client redact the code, and the package does not log it. This client does not call `GET /data/stats` or `POST /data/count`.

## Install

Python 3.12 (`>=3.12,<3.13`). From the repo root, [uv](https://docs.astral.sh/uv/) installs this member. Runtime dependencies are httpx, pydantic v2, and the official `mcp` SDK. pytest, respx, ruff, and ty are in the `dev` dependency group.

```bash
uv sync --package osintz-snusbase-mcp --group dev
```

Set `UV_PYTHON_DOWNLOADS=never` and point `UV_PYTHON` at CPython 3.12. `nix develop` at the repo root does that.

The Nix package is the stdio server:

```bash
nix build
./result/bin/snusbase-mcp
```

`nix build` does not embed an API key.

Codes issued after September 2021 start with `sb` plus 28 characters. The client does not check that shape.

## MCP server

`snusbase-mcp` speaks MCP over stdio. The agent sees four tools:

- `snusbase-whois` takes IP addresses and domain names in one list. A value that `ipaddress.ip_address` accepts is sent to IP WHOIS. Anything else is sent as a domain. Surrounding whitespace is removed. `group_by` is left unset, so records stay keyed by the term you sent. A domain response can include per-name errors and still succeed. More than 100 domains is rejected before a request is sent. IP addresses do not count toward that 100. If both kinds are present and the second call fails, the tool errors and does not return the first body.
- `snusbase-search`, `snusbase-hash`, and `snusbase-combo` take `queries`, a list of `type:term` strings. The split is the first colon. `email:a:b@example.com` is type `email` and term `a:b@example.com`. Queries are OR: a row matches if any query hits. Types are not a cross product. One request is sent per type. Sizes and `took` are summed, rows are concatenated per table, and the last rate limit is kept. A later type's failure does not return the earlier groups. `wildcard`, `group_by`, and `tables` are not sent.
- `snusbase-search` types are `email`, `username`, `lastip`, `password`, `hash`, `name`, and `_domain`. It calls `POST /data/search`. Every row field is untrusted and can contain a leaked password.
- `snusbase-hash` types are `hash` and `password`. `hash` looks up plaintext. `password` looks up matching hashes. Multiple items are OR. It calls `POST /tools/hash-lookup`.
- `snusbase-combo` types are `username` and `password`. Combolists are username:password pairs only, not full breach rows. `username` matches the username side. `password` matches the password side. A username and a password in one call are not a pair match. Multiple items are OR. It calls `POST /tools/combo-lookup`.

A rate-limit error includes `reset_seconds` when the header is an integer, so the agent can wait. The client does not sleep.

The process reads `SNUSBASE_API_KEY` when it constructs the client. Export it before the process starts.

```bash
export SNUSBASE_API_KEY='sbYOUR_ACTIVATION_CODE'
uv run --package osintz-snusbase-mcp snusbase-mcp
```

That process waits on stdio. Point the MCP host at the command and pass the variable on the server process. A host that launches the script through the official Python MCP client must pass the key in `StdioServerParameters.env`. That client inherits `PATH` and a few identity variables, and it does not inherit `SNUSBASE_API_KEY` on its own. A direct launch from the shell does inherit the exported variable.

## Human test

These commands call the live API. The automated suite does not. They spend quota. `snusbase-search` and `snusbase-hash` can print plaintext passwords and other breach fields. `snusbase-combo` can print username:password pairs. Do not log that output, and do not paste it into a ticket.

Quotas, which Snusbase says can change (trust `X-Rate-Limit-*` when they disagree):

- `snusbase-search` is one `POST /data/search` per distinct type. The API docs say search and count allow 2048 requests every 12 hours. This client does not call count.
- `snusbase-combo` is one `POST /tools/combo-lookup` per distinct type. The API docs say combo lookup allows 4096 requests every 12 hours.
- `snusbase-hash` and `snusbase-whois` use the "every other endpoint" budget of 256 requests every 2 minutes in the API docs, together with stats. This client does not call stats. Hash sends one request per distinct type. Whois sends one request per kind present. The docs do not say whether that 256 is one shared counter.
- A mixed whois list sends one request per kind. `example.org` plus `1.2.3.4` is two requests. A search of two types is two requests.
- The homepage sentence about 2048 requests per day is not what this client enforces. There is no client-side quota.

Representative inputs, from the repo root, after `uv sync --package osintz-snusbase-mcp --group dev`:

```bash
export SNUSBASE_API_KEY='sbYOUR_ACTIVATION_CODE'
uv run --package osintz-snusbase-mcp python - <<'PY'
import asyncio
import os

from mcp import Client
from mcp.client.stdio import StdioServerParameters

async def main() -> None:
    params = StdioServerParameters(
        command="snusbase-mcp",
        env={"SNUSBASE_API_KEY": os.environ["SNUSBASE_API_KEY"]},
    )
    async with Client(params) as client:
        listed = await client.list_tools()
        print([tool.name for tool in listed.tools])
        whois = await client.call_tool(
            "snusbase-whois",
            {"terms": ["1.2.3.4", "example.org"]},
        )
        print(whois)
        search = await client.call_tool(
            "snusbase-search",
            {"queries": ["email:me@example.com"]},
        )
        print(search)
        hashed = await client.call_tool(
            "snusbase-hash",
            {"queries": ["hash:5f4dcc3b5aa765d61d8327deb882cf99"]},
        )
        print(hashed)
        combo = await client.call_tool(
            "snusbase-combo",
            {"queries": ["username:me@example.com"]},
        )
        print(combo)

asyncio.run(main())
PY
```

`1.2.3.4` is a documentation address. `example.org` is a reserved name. `me@example.com` is the example used in the client section below. Any of them can still match data Snusbase holds. Treat the search printout as sensitive.

The same script against the Nix result, with `command` set to the absolute path of `./result/bin/snusbase-mcp`:

```bash
nix build
export SNUSBASE_API_KEY='sbYOUR_ACTIVATION_CODE'
./result/bin/snusbase-mcp
```

The bare `./result/bin/snusbase-mcp` line only shows that the script starts and waits on stdio. It does not issue an API call until a host sends a tool call. The `uv run python` block above is the call.

What this repository has not verified against `https://api.snusbase.com`:

- The live bytes for those inputs, including status codes and which databases return rows.
- The unit of `took`.
- The JSON for `group_by: false`. These tools never send `group_by`. The client accepts a list for that case because the docs do not show the payload.
- Whether every string that `ipaddress.ip_address` rejects is a domain Snusbase will accept.
- Whether the 256-request window is shared across WHOIS, stats, and hash lookup.
- A host other than the official Python `mcp` client. The script above is the checked shape of that client at the locked `mcp` version. It has not been run against the live API in CI.

Offline checks, from the repo root:

```bash
uv run --package osintz-snusbase-mcp --directory osint-sources/snusbase pytest
uv run --package osintz-snusbase-mcp --directory osint-sources/snusbase ruff check
uv run --package osintz-snusbase-mcp --directory osint-sources/snusbase ruff format --check
uv run --package osintz-snusbase-mcp --directory osint-sources/snusbase ty check
```

CI runs `nix flake check -L`, which is the same Ruff, ty, and pytest commands against the lockfile.

## Client usage

The client is how the tools call Snusbase, and how tests call it without MCP. It is not a published package of its own.

Search returns the rows. With the default `group_by` of `"db"`, `results` is a dict of table name to a list of row dicts. `group_by=False` asks the server to disable grouping; the published examples do not show that JSON, and the client also accepts a bare list. The MCP tools never pass `group_by`.

```python
from snusbase_client import SearchType, SnusbaseClient


async def search() -> None:
    async with SnusbaseClient() as client:
        found = await client.search(
            ["me@example.com"],
            [SearchType.EMAIL, SearchType.USERNAME],
        )
        results = found.data.results
        if isinstance(results, dict):
            for table, rows in results.items():
                print(table, len(rows))

        whois = await client.domain_whois(["example.org"])
        print(whois.data.size, whois.data.errors)
```

| Method | Request | Auth header | MCP tool |
| --- | --- | --- | --- |
| `search` | `POST /data/search` | `Auth` | `snusbase-search` |
| `combo_lookup` | `POST /tools/combo-lookup` | `Auth` | `snusbase-combo` |
| `hash_lookup` | `POST /tools/hash-lookup` | `Auth` | `snusbase-hash` |
| `ip_whois` | `POST /tools/ip-whois` | `Auth` | `snusbase-whois` |
| `domain_whois` | `POST /tools/domain-whois` | `Auth` | `snusbase-whois` |

Search types are `email`, `username`, `lastip`, `password`, `hash`, `name`, and `_domain` (`SearchType.DOMAIN`). Combo types are `username` and `password`. Hash types are `hash` and `password`. Domain WHOIS accepts at most 100 names per call. A domain WHOIS HTTP 200 can still include `data.errors` for names that did not resolve.

Optional arguments that you leave as `None` are omitted from the JSON body, so the server applies its defaults (`group_by` of `"db"` on search, combo, and hash). Pass `False` when you want the JSON boolean `false`. IP and domain WHOIS do not default `group_by` to `"db"`: omitting it keys `results` by the input.

`base_url` defaults to `https://api.snusbase.com`. `timeout` defaults to 60 seconds and is passed to httpx. Redirects are not followed.

Each call returns `SnusbaseResponse`. `data` is the parsed body. `rate_limit` is the documented headers (`limit`, `remaining`, `reset_seconds`). On HTTP 429, `SnusbaseRateLimitError.reset_seconds` is that same reset value. The docs define it as seconds until the window resets.

| Exception | When |
| --- | --- |
| `SnusbaseBadRequestError` | HTTP 400, or the local body does not match the documented parameters |
| `SnusbaseAuthError` | HTTP 401, or an authenticated call was made with no key configured |
| `SnusbaseRateLimitError` | HTTP 429 |
| `SnusbaseAPIError` | Any other HTTP failure, a transport error, an unexpected redirect, or a 2xx body that does not match the documented shape |

## Layout

```text
src/snusbase_client/     HTTP client, models, exceptions
src/snusbase_mcp/        lookup.py, routing.py, stdio server
tests/                   pytest, respx, no live API
pyproject.toml           osintz-snusbase-mcp
```

The workspace lockfile and the flake live at the repo root.

## Notes on the upstream docs

Same list as [docs/source-contract.md](../../docs/source-contract.md#doc-ambiguities). Kept here so this source can be read on its own.

These are ambiguities in the public docs as of the mirror README blob `535876c681d42db603e3f2fe72e6f13cb4e94542`. The client models follow the choices below.

- The [homepage](https://snusbase.com/) says the API is included up to 2048 requests per day. The API docs say search and count are 2048 every 12 hours, combo lookup is 4096 every 12 hours, and other endpoints are 256 every 2 minutes.
- `GET /data/stats` is documented as not requiring authentication, and its request example has no `Auth` header. The JavaScript and Python samples send `Auth` on every call, including stats, because the helper always sets the header. This client does not call stats or count. Rate-limit headers are documented for authenticated requests. The client still reads them on the calls it makes.
- `took` is a number in every example. The docs never say whether it is seconds, milliseconds, or another unit.
- Search, combo, and hash say `group_by: false` disables grouping, and that a row missing the grouped column is appended to a `NO_{GROUP_BY}` object. They do not show that JSON. Whois docs are explicit: omit `group_by` for an object keyed by the input, pass a field name for arrays plus a `NO_{FIELD}` bucket, and pass `false` for a flat array. The client accepts an object of row arrays or a list for search, combo, and hash, and the three whois shapes.
- Domain `group_by` examples mention `registrant.org` and `meta.source`. The sample record has `contact` and `meta.sources`. Rows are plain dicts, so both names are kept.
- There is no documented phone search type. The search types are `email`, `username`, `lastip`, `password`, `hash`, `name`, and `_domain`.
- Activation codes after September 2021 are `sb` plus 28 characters. The alphabet is not specified, and older codes are not described.
- The "search specific tables" example uses `0001_STEALERLOGS_NA_106M_MALWARE_2023`. The stats example uses `0001_STEALERLOGS_NA_121M_MALWARE_2023`. Both are copied as published.
- HTTP 400, 401, and 429 are documented as an `errors` array, and those messages are safe to show to end users. No sample error JSON is published. The only sample `errors` value is on a 200 domain-whois body (`not8489291real.com: Likely not registered`).
- `X-Rate-Limit-Reset` is documented as seconds until the window resets, not as a Unix timestamp.
- Wildcard syntax (`%`, `?`, no leading wildcard, backslash escapes) is written up on the search page. Combo and hash only say that `wildcard` enables wildcard search.

## License

MIT. See [LICENSE](LICENSE).

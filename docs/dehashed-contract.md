# DeHashed contract

Repo-wide rules are in [mcp-conventions.md](mcp-conventions.md). This file is DeHashed only.

Source of truth: a redacted export of the DeHashed API docs dated "Updated July 2, 2026". The export wraps many lines at 51 characters and drops the remainder. This client does not add an endpoint, parameter, or response field that export does not describe, and it does not call a path the export does not show in full.

The human whitelist is five tools. Every one is **read-only**. The console script is stdio only.

The key is `DEHASHED_API_KEY`, read when the process constructs `DehashedClient`. It is sent as `DeHashed-Api-Key`. It is never a tool argument. `GET /data-wells` does not send the header, even when a key is configured.

`structured_output` is false. Each tool returns a JSON object as text. Client exceptions become MCP `ToolError` text. There is no retry and no sleep after HTTP 429. Before send, this client waits so one process stays at or under 20 requests in any one second. That pace is the published limit, and the human asked the client to respect it. See [mcp-conventions.md](mcp-conventions.md).

Rows from search are untrusted. They can contain a leaked password. Do not log them and do not render them as HTML. This package does not log.

## Tools

| Tool | Call | Key | Effect |
| --- | --- | --- | --- |
| `dehashed-search` | `POST /v2/search` | yes | read-only |
| `dehashed-data-wells` | `GET /data-wells` | no | read-only |
| `dehashed-whois` | `POST /v2/whois/search` with `search_type` `whois` | yes | read-only |
| `dehashed-reverse-whois` | `POST /v2/whois/search` with `search_type` `reverse-whois` | yes | read-only |
| `dehashed-subdomain-scan` | `POST /v2/whois/search` with `search_type` `subdomain-scan` | yes | read-only |

`dehashed-subdomain-scan` is the subdomain lookup. The documented `search_type` is `subdomain-scan`.

### `dehashed-search`

**Effect:** read-only.

One `POST /v2/search`. Body fields are `query`, and optionally `page`, `size`, `wildcard`, `regex`, and `de_dupe`. `None` is omitted so DeHashed can apply page 1 and size 100. `false` is sent.

Local checks, before HTTP, use the published strings:

- `size must be between 1 and 10000`
- `page must be 1 or greater`
- `pagination limit exceeded` when the effective `page * size` is above 50,000
- `regex and wildcard cannot both be true`

Effective page and size use the documented defaults only for that product check. They are not written into the JSON unless the caller set them.

One tool call is one page. This server does not walk pages for the caller. A page whose rows start past the first 10,000 results has to follow the export's sequential-session rule on the DeHashed side. The session is not returned to this client. There is no `through_page` argument.

Output: `balance`, `entries`, `took`, `total`, plus any extra keys. Entry attributes that are null are omitted.

Cost: the checklist says 1 search = 1 credit. It does not say whether each page is another credit. `balance` comes back on the search body.

### `dehashed-data-wells`

**Effect:** read-only.

`GET /data-wells`. Query fields are `count` (20 or 50), `page`, and `sort`. Sort is `added`, `name`, `date`, or `records`, plus an optional `-ASC` suffix. Anything else is rejected locally. No key is attached. The docs say this call is free.

### `dehashed-whois`

**Effect:** read-only.

`POST /v2/whois/search` with `search_type` `whois` and `domain`. No WHOIS search response JSON is published. The client accepts any JSON object and keeps every key.

### `dehashed-reverse-whois`

**Effect:** read-only.

Same path, `search_type` `reverse-whois`. At least one of `include` or `exclude`, each at most 4 terms. `reverse_type` is `current` or `historic`. Omitted, it is not sent. The documented default is `current`.

### `dehashed-subdomain-scan`

**Effect:** read-only.

Same path, `search_type` `subdomain-scan`, and `domain`. This is the subdomain lookup.

## Errors

| Status | Class | Text |
| --- | --- | --- |
| 400 | `DehashedBadRequestError` | the `error` string. If it mentions authentication, the tool adds `Check DEHASHED_API_KEY.` |
| 401 | `DehashedSubscriptionError` | the published subscription sentence, or that sentence when the body has no `error` string |
| 403 | `DehashedForbiddenError` | the `error` string, or `Insufficient Credits` when the body has none |
| 429 | `DehashedRateLimitError` | the `error` string plus the 20 requests per second sentence |
| missing key | `DehashedAuthError` | names `DEHASHED_API_KEY`. No request is sent |
| other | `DehashedAPIError` | transport, redirect, HTTP 500, or a 2xx body that is not the documented object |

There is no subscription-management tool. HTTP 401 on a call this server does make is still the published "no search subscription" response. Free calls are still attempted. Data wells do not need a key.

## Not implemented

Left out because the human whitelist does not name them:

- `POST /v2/search-password` is written in full. The published body is only `results_found`, a count. It is not a tool.
- `POST /v2/info/user` is written in full. Account and user info are not a tool.
- `GET /v2/whois/credits` is written in full. It is not a tool.
- `whois-history`, `reverse-ip`, `reverse-mx`, and `reverse-ns` use the same fully written `POST /v2/whois/search`. They are not tools. WHOIS history is documented at 25 credits.

Left out because the export does not show the path in full, so nothing here was reconstructed:

- Monitoring tasks, reports, channels, and domains. The URL lines stop at `creat`, `updat`, `delet`, `get-t`, `get-r`, `get-c`, `get-do`, or `clear`. Several of those operations change the account. They need a full path and explicit human sign-off before any of them is implemented.

## Assumptions

- Intro text spells the header `Dehashed-Api-Key`. The samples use `DeHashed-Api-Key`. The client sends `DeHashed-Api-Key`.
- Search `took` is a string in the only example (`179µs`). Entry `id` is a string in that example.
- The data-wells sample is missing a comma between `data` and `date`. Those fields are still required because the sample shows them.
- An earlier search note says page 3 with size 5000 is invalid. The pagination section uses `page * size <= 50000`. This client follows the later rule.
- The any-order rule is `page * size <= 10000`. The sequential rule is a starting offset past 10,000. The export does not define that offset. This client sends the requested page and does not classify the gap.
- Timeout is 60 seconds. The export does not say. Base URL is `https://api.dehashed.com`.

# DeHashed contract

The public interface is the MCP server: tool names, descriptions, inputs, and the results and errors those tools return. The client in `dehashed_client` is internal. It ships in `osintz-dehashed-mcp` because the server imports it. It is not a second distribution.

Source of truth: a redacted export of the DeHashed API docs dated "Updated July 2, 2026". The export wraps many lines at 51 characters and drops the remainder. This client does not add an endpoint, parameter, or response field that export does not describe. Where the export is cut or contradicts itself, the choice is recorded below.

Tool names include `dehashed`. The key is `DEHASHED_API_KEY`, read when the process constructs `DehashedClient`. It is sent as `DeHashed-Api-Key`. It is never a tool argument. `GET /data-wells` does not send the header, even when a key is configured.

`structured_output` is false. Each tool returns a JSON object as text. Client exceptions become MCP `ToolError` text. There is no retry and no sleep after an HTTP error. The client does wait, before sending, so one process stays at or under 20 requests in any one second. That is the published limit. A 429 is still surfaced.

Rows from search and from a monitoring report are untrusted. They can contain a leaked password. Do not log them and do not render them as HTML. This package does not log.

## Tools

| Tool | Call | Key | Writes |
| --- | --- | --- | --- |
| `dehashed-search` | `POST /v2/search` | yes | no |
| `dehashed-search-password` | `POST /v2/search-password` | yes | no |
| `dehashed-user` | `POST /v2/info/user` | yes | no |
| `dehashed-data-wells` | `GET /data-wells` | no | no |
| `dehashed-monitoring-create-task` | assumed `POST /v2/monitoring/create-task` | yes | yes |
| `dehashed-monitoring-update-task` | assumed `POST /v2/monitoring/update-task` | yes | yes |
| `dehashed-monitoring-set-task-active` | assumed `POST /v2/monitoring/update-task-active` | yes | yes |
| `dehashed-monitoring-delete-task` | assumed `POST /v2/monitoring/delete-task` | yes | yes |
| `dehashed-monitoring-tasks` | assumed `POST /v2/monitoring/get-tasks` | yes | no |
| `dehashed-monitoring-task` | assumed `POST /v2/monitoring/get-task` | yes | no |
| `dehashed-monitoring-reports` | assumed `POST /v2/monitoring/get-reports` | yes | no |
| `dehashed-monitoring-report` | assumed `POST /v2/monitoring/get-report` | yes | no |
| `dehashed-monitoring-channels` | assumed `POST /v2/monitoring/get-channels` | yes | no |
| `dehashed-monitoring-update-channel` | assumed `POST /v2/monitoring/update-channel` | yes | yes |
| `dehashed-monitoring-delete-channel` | assumed `POST /v2/monitoring/delete-channel` | yes | yes |
| `dehashed-monitoring-domains` | assumed `GET /v2/monitoring/get-domains` | yes | no |
| `dehashed-monitoring-update-domain` | assumed `POST /v2/monitoring/update-domain` | yes | yes |
| `dehashed-monitoring-clear-domain` | assumed `POST /v2/monitoring/clear-domain` | yes | yes |
| `dehashed-whois` | `POST /v2/whois/search` `search_type=whois` | yes | no |
| `dehashed-whois-history` | same path, `whois-history` | yes | no |
| `dehashed-reverse-whois` | same path, `reverse-whois` | yes | no |
| `dehashed-reverse-ip` | same path, `reverse-ip` | yes | no |
| `dehashed-reverse-mx` | same path, `reverse-mx` | yes | no |
| `dehashed-reverse-ns` | same path, `reverse-ns` | yes | no |
| `dehashed-subdomain-scan` | same path, `subdomain-scan` | yes | no |
| `dehashed-whois-credits` | `GET /v2/whois/credits` | yes | no |

Webhooks are not a tool. The export describes an inbound POST body, `{"id": "report_id"}`, which DeHashed sends to a channel URL. This server does not receive it and does not send it.

### `dehashed-search`

Purpose: general search. Body fields are `query`, and optionally `page`, `size`, `wildcard`, `regex`, and `de_dupe`. `None` is omitted so DeHashed can apply page 1 and size 100. `false` is sent.

Local checks, before HTTP, use the published strings:

- `size must be between 1 and 10000`
- `page must be 1 or greater`
- `pagination limit exceeded` when the effective `page * size` is above 50,000
- `regex and wildcard cannot both be true`

Effective page and size use the documented defaults only for that product check. They are not written into the JSON unless the caller set them.

`through_page` is not a DeHashed field. When it is set, this process requests page 1, then 2, and so on through that page, with the same query and flags. `page` and `through_page` together are rejected. If a later page fails, the tool raises and does not return the earlier pages. Those requests already happened.

A single `page` is sent as asked, including a page past the first 10,000 results. The server, not this client, enforces the sequential-session rule. This process does not remember a pagination session across calls.

Output: the search object (`balance`, `entries`, `took`, `total`, plus any extra keys). Sequential mode returns `{"pages": [ ... ]}` instead. Entry attributes that are null are omitted.

Cost: the checklist says 1 search = 1 credit. It does not say whether each page is another credit. `balance` comes back on the search body. WHOIS history is the only call with a published credit number (25).

### `dehashed-search-password`

Purpose: presence check for a password. The tool argument is the password. The client hashes it with SHA-256 over UTF-8 and sends lowercase hex in `sha256_hashed_password`. The plaintext is not a request field. The sample function returns `str` and is cut off at `encode('u`, so UTF-8 and hex are assumptions.

The docs say this call needs no credits and no search subscription. It still sends the API key. The body is `results_found`.

An error string that contains the password is scrubbed when the password is at least 4 characters. Shorter passwords are not scrubbed, because they would erase unrelated words.

### `dehashed-user`

Purpose: `search_access`, `search_credits`, and `whois_credits`. No search. The call sends `{}`.

### `dehashed-data-wells`

Purpose: list wells. Query fields are `count` (20 or 50), `page`, and `sort`. Sort is `added`, `name`, `date`, or `records`, plus an optional `-ASC` suffix. Anything else is rejected locally. No key is attached.

### Monitoring

Task type is `email`, `username`, `phone`, or `name`. Channel type is `webhook` or `email`. Delete-channel sends `channel`, not `type`. Update-domain takes a hostname. Clear-domain resets a domain task. The docs say unsubscribing is done on the subscriptions page, not by that call.

Create, update, delete, set-active, update-channel, update-domain, and clear-domain change the account. The published success body is `{"success": true}`.

### WHOIS

Domain-shaped calls send `domain` and `search_type`. Reverse IP, MX, and NS also use the field name `domain` for the address. That is the export's name. Reverse WHOIS requires at least one of `include` or `exclude`, each at most 4 terms. `reverse_type` is `current` or `historic`. Omitted, it is not sent. The documented default is `current`.

No WHOIS search response JSON is published. The client accepts any JSON object and keeps every key. A non-object body fails.

## Errors

| Status | Class | Text |
| --- | --- | --- |
| 400 | `DehashedBadRequestError` | the `error` string. If it mentions authentication, the tool adds `Check DEHASHED_API_KEY.` |
| 401 | `DehashedSubscriptionError` | the published subscription sentence, or that sentence when the body has no `error` string |
| 403 | `DehashedForbiddenError` | the `error` string, or `Insufficient Credits` when the body has none |
| 429 | `DehashedRateLimitError` | the `error` string plus `The documented limit is 20 requests per second.` |
| missing key | `DehashedAuthError` | names `DEHASHED_API_KEY`. No request is sent |
| other | `DehashedAPIError` | transport, redirect, HTTP 500, or a 2xx body that is not the documented object |

The published 400 example is `issue with authentication`. The published 401 example is the search-subscription sentence. A 401 is not treated as a missing key. Free calls are still attempted. Data wells do not need a key. Password search is documented as free and is still sent with a key.

Redirects are not followed. The redirect error does not include `Location`. A transport error names the exception type and is raised `from None`. The key is removed from an error string when it is at least 4 characters. `_Secret` hides the key from `str`, `repr`, and `format`.

HTTP 500 `issue with pagination state` is a `DehashedAPIError`. The docs call it transient. This client does not retry it.

## Assumptions

These are choices, not new endpoints. Confirm them against a live account before relying on monitoring or on the two method conflicts.

1. Monitoring URL lines are 51 characters, the same width as the wrapped code samples, so the path suffix is cut. The client completes `creat`, `updat`, `delet`, `get-t`, `get-r`, `get-c`, `get-do`, and `clear` from the sample function name: `create-task`, `update-task`, `update-task-active`, `delete-task`, `get-tasks`, `get-task`, `get-report`, `get-channels`, `update-channel`, `delete-channel`, `get-domains`, `update-domain`, `clear-domain`. Several of those share a prefix. The function name is the only disambiguator.
2. `get_reports` is the exception. The heading shows `get-t`. The function is `monitoring_get_reports`, which would start with `get-r`. The client still calls `/v2/monitoring/get-reports` and the tool description says so. A path that matches the visible prefix would be something like `get-task-reports`. That was not assumed.
3. `clear` fills the 51-character line, so `/v2/monitoring/clear` and `/v2/monitoring/clear-domain` are both possible. The client uses `clear-domain` because the function is `monitoring_clear_domain`.
4. `/v2/info/user` and get-channels: the endpoint line says POST. The sample calls `requests.get`. Both lines are long enough to show the method. This client sends POST and a JSON object (`{}` when there is no field).
5. Get-domains and WHOIS credits are GET in the endpoint line and in the sample. No body is sent. The endpoint headings still list `Content-Type: application/json`. This client does not send that header on a GET.
6. Intro text spells the header `Dehashed-Api-Key`. The samples and this task use `DeHashed-Api-Key`. Header names are case-insensitive. The client sends `DeHashed-Api-Key`.
7. Password digest is lowercase hex of UTF-8. The sample is cut before `.hexdigest()`.
8. Search `took` is a string in the only example (`179µs`). The client requires a string.
9. Search entry `id` is a string in the example. The client requires a string when the field is present.
10. The data-wells sample is missing a comma between `data` and `date`. The fields are still `data`, `date`, `description`, `name`, `records`, and `is_sensitive`, all required because the sample shows them.
11. "The response will be empty" for channels has no JSON. An object that omits `channels` is accepted as an empty list. A body that is not JSON is an error.
12. An earlier search note says maximum pagination depth is 10,000 and gives page 3 with size 5000 as invalid. The pagination section and this task use `page * size <= 50000` and describe deep pages past 10,000. This client follows the later rule. Page 3 with size 5000 is allowed.
13. Any-order pages are those with `page * size <= 10000`. Sequential pages are those whose starting offset exceeds 10,000. The export does not define the offset. For size 10000, page 2 has `page * size` 20000 and a zero-based offset of 10000, which does not exceed 10000. This client does not try to classify that gap. `through_page` always walks from page 1. A direct `page` is sent through.
14. Deep-pagination session state is server-side, hashed from the query, kept for 10 minutes, and not returned to the client. There is no cursor field to send.
15. Timeout is 60 seconds. The export does not say. Base URL is `https://api.dehashed.com`.
16. Request models reject unknown fields. Response models keep extra keys. `None` is omitted. `false` and an empty list are sent.
17. Data-wells `count` is only 20 or 50. `sort` rejects `-DESC` because the export only describes the bare value (descending) and `-ASC`.
18. Blank required strings are rejected locally. The export says the field is required and does not show the server's message.
19. The client does not call any path that is not in the tool table. There is no webhook sender, no stats call, and no plaintext password field on the wire.

## Not shared with Snusbase

`_Secret` and the redirect refusal are duplicated. Snusbase parses `X-Rate-Limit-*`, sends `Auth`, and does not pace. DeHashed does not document those headers, sends `DeHashed-Api-Key`, and paces at 20 requests per second. The packages do not import each other.

# Source contract

The public interface of a source is its MCP server: tool names, descriptions, input schemas, and the results and errors those tools return. Primitive clients are internal. They must still be imported by the server, so they ship in the same distribution and the same Nix package.

A tool name includes the source name. Document and test purpose, inputs, outputs, failures, partial success, cost and side effects, result size, and trust. Source text is untrusted. Do not log secrets or raw sensitive rows. Secrets are environment variables or constructor arguments in tests. They are never tool arguments and never Nix expressions.

Implement only the operations the named tools need. This client implements search, combo lookup, hash lookup, IP WHOIS, and domain WHOIS. It does not implement `GET /data/stats` or `POST /data/count`.

## Snusbase tools

Server name `snusbase`. Four tools, each with `structured_output=False`, return a JSON object as text. The activation code is `SNUSBASE_API_KEY`, read when the process constructs `SnusbaseClient`.

Search, hash, and combo share one query shape. Each item is `type:term`, split on the first colon only. The prefix is the type. Everything after the colon is the term, including further colons (`email:a:b@example.com` is type `email` and term `a:b@example.com`). Whitespace is not stripped. Queries are grouped by type, in the order each type first appears, and one request is sent per type with that type alone. Terms of the same type stay in query order. A row matches if any query hits. Types are not a cross product. The tools do not send `wildcard`, `group_by`, or `tables`.

The merged view sums `size` and sums `took`, concatenates row lists per table, and keeps the rate limit from the last response. `took` is summed because each request has its own value and the view has one field; the docs do not define the unit. If a later type's request fails, the tool errors and does not return the earlier groups. Results must be an object of table name to a list of rows, which is the server default when `group_by` is omitted. Another shape fails the merge.

Rejected before HTTP: an empty list, a missing colon, an empty type, an empty term, or a type outside that tool's set.

### `snusbase-search`

Purpose: breach search. Types are `email`, `username`, `lastip`, `password`, `hash`, `name`, and `_domain`. One `POST /data/search` per type.

Output: `took`, `size`, `results`, and `rate_limit` (`limit`, `remaining`, `reset_seconds`). Rows are plain dicts.

Failures: client exceptions become MCP `ToolError` text. HTTP 400 is `SnusbaseBadRequestError`. HTTP 401, or a missing key, is `SnusbaseAuthError` and the text names `SNUSBASE_API_KEY` without the key. HTTP 429 is `SnusbaseRateLimitError`; when `X-Rate-Limit-Reset` is an integer, the text appends `reset_seconds=<n>`. Other HTTP failures, transport errors, unexpected redirects, and a 2xx body that does not match the documented shape are `SnusbaseAPIError`. There is no retry and no sleep.

Partial success: none across types. A later type's failure drops the earlier bodies.

Cost and side effects: one authenticated `POST /data/search` per distinct type in the list. The API docs say search and count allow 2048 requests every 12 hours. This client does not call count. Snusbase says the numbers can change; trust the response headers when they disagree. The call can return plaintext passwords and other credentials. This repository's tests never perform it.

Result size: unbounded by this server. Do not log the body.

Trust: every field is untrusted, including HTML or exploit payloads that were aimed at other sites. Do not render rows as HTML.

### `snusbase-hash`

Purpose: hash lookup. `hash` looks up plaintext. `password` looks up matching hashes. Multiple items are OR. One `POST /tools/hash-lookup` per type. No `wildcard` or `group_by`.

Output, merge, and failure rules match search. Rows can contain a plaintext password.

Cost: the API docs put hash lookup in the "every other endpoint" budget of 256 requests every 2 minutes. One request per distinct type.

### `snusbase-combo`

Purpose: combolist lookup. Combolists are username:password pairs only, not full breach rows. `username` matches the username side. `password` matches the password side. Multiple items are OR. A username and a password in one call are not a pair match. One `POST /tools/combo-lookup` per type. No `wildcard` or `group_by`.

Output, merge, and failure rules match search.

Cost: the API docs say combo lookup allows 4096 requests every 12 hours. One request per distinct type.

### `snusbase-whois`

Purpose: WHOIS for IP addresses and domain names passed in one list.

Input: `terms`, a list of strings. The tool strips each term. `ipaddress.ip_address` decides the route: values it accepts go to `POST /tools/ip-whois`; everything else goes to `POST /tools/domain-whois`. That split is this tool's rule. It is not a Snusbase parameter. Blank terms and an empty list are rejected before a request. More than 100 domains is rejected before a request. IP addresses do not count toward that 100. `group_by` is left unset, so each endpoint keys records by the input term. The client default for these two endpoints is not `"db"`.

Output: an object with `ip` and/or `domain`, only for the kinds that were sent. Each value has `took`, `size`, `results`, and `rate_limit`. A domain body with `errors` copies that list onto `domain.errors`. An IP body does not add `errors`.

Failures: same translation as search. The domain limit and blank terms are `SnusbaseBadRequestError` before any HTTP call.

Partial success: a domain HTTP 200 may include per-name `errors` and still return the records. That is the documented client behavior, and the tool surfaces it. If the tool sends both an IP call and a domain call and the second call raises, the tool raises and does not return the first call's body. There is no cross-call partial result.

Cost and side effects: one authenticated POST per kind present in the list. The API docs put both WHOIS endpoints in the "every other endpoint" budget of 256 requests every 2 minutes, together with stats and hash lookup. This client does not call stats. The docs do not say whether that 256 is one shared counter. A mixed list spends one request on each endpoint it uses.

Result size: one record set per kind. Domain requests are capped at 100 names by the docs and by the client model.

Trust: WHOIS records are plain dicts. Treat them as untrusted source text. They are not breach rows, and this tool does not call `/data/search`.

## Client commitments

These are the behaviors the tools rely on. `GET /data/stats` and `POST /data/count` were removed from this client. Do not add them back unless a human asks.

- One async client, `SnusbaseClient`. No blocking client. No OpenAPI file in the tree. The Pydantic models are the request and response contract.
- Do not add an endpoint, parameter, field, or search type the public docs do not describe. The published table names in `tests/test_client.py` and the notes below stay as published, including the two different stealer-log names.
- Request models reject unknown fields. Response models keep extra keys. `None` on an optional request field is left out of the JSON. `False` and an empty list are sent.
- Do not fill `group_by` with `"db"` inside the client. For IP WHOIS and domain WHOIS, a missing `group_by` means results keyed by the input.
- A blank `api_key` argument raises at construction. A missing or blank `SNUSBASE_API_KEY` means there is no key. Every implemented call requires a key and sends `Auth`.
- `follow_redirects=False`. A redirect must not carry `Auth` to another host. The redirect error must not include the `Location` header.
- `_Secret` hides the activation code from `str`, `repr`, and `format`. `reveal` is the only way to read it. A transport error names the exception type and is raised `from None`. Do not put an `httpx.Response` or an `httpx.Request` on `SnusbaseResponse` or on an exception.
- This package does not log. Do not log a row.
- The client does not retry and does not sleep on HTTP 429.
- `client.py` owns `OPERATIONS`, the paths, the header name, the key, and `parse_rate_limit`. `models.py` owns the request models, the response models, and the wire enums.
- Base URL `https://api.snusbase.com`. Timeout 60 seconds, passed to httpx. There is no unauthenticated call in this client.

MCP-only commitments:

- Tool names are `snusbase-search`, `snusbase-whois`, `snusbase-hash`, and `snusbase-combo`. The names `search` and `whois` are not registered.
- The console script is stdio only.
- The key is read from the environment at client construction inside the server lifespan. Changing the variable after the process has started does not change the key already stored.
- `tool_error_text` is the only rewriting of a client message. It adds the env var name on auth failures that do not already mention it, and `reset_seconds` on a rate-limit error that has an integer reset.

## Doc ambiguities

Public docs as of the mirror README blob `535876c681d42db603e3f2fe72e6f13cb4e94542`. The client follows the choices below. None of these are new endpoints.

- The [homepage](https://snusbase.com/) says the API is included up to 2048 requests per day. The API docs say search and count are 2048 every 12 hours, combo lookup is 4096 every 12 hours, and other endpoints are 256 every 2 minutes. This client follows the API docs, not the homepage sentence.
- `GET /data/stats` is documented as not requiring authentication, and its request example has no `Auth` header. The JavaScript and Python samples send `Auth` on every call, including stats, because the helper always sets the header. This client does not call stats or count. Rate-limit headers are documented for authenticated requests. The client still reads them on the calls it makes.
- `took` is a number in every example. The docs never say whether it is seconds, milliseconds, or another unit.
- Search, combo, and hash say `group_by: false` disables grouping, and that a row missing the grouped column is appended to a `NO_{GROUP_BY}` object. They do not show that JSON. Whois docs are explicit: omit `group_by` for an object keyed by the input, pass a field name for arrays plus a `NO_{FIELD}` bucket, and pass `false` for a flat array. The client accepts an object of row arrays or a list for search, combo, and hash, and the three whois shapes. The MCP tools never send `group_by`.
- Domain `group_by` examples mention `registrant.org` and `meta.source`. The sample record has `contact` and `meta.sources`. Rows are plain dicts, so both names are kept.
- There is no documented phone search type. The search types are `email`, `username`, `lastip`, `password`, `hash`, `name`, and `_domain`.
- Activation codes after September 2021 are `sb` plus 28 characters. The alphabet is not specified, and older codes are not described. The client does not check the shape.
- The "search specific tables" example uses `0001_STEALERLOGS_NA_106M_MALWARE_2023`. The stats example uses `0001_STEALERLOGS_NA_121M_MALWARE_2023`. Both are copied as published.
- HTTP 400, 401, and 429 are documented as an `errors` array, and those messages are safe to show to end users. No sample error JSON is published. The only sample `errors` value is on a 200 domain-whois body (`not8489291real.com: Likely not registered`). The client also accepts a JSON string, a mixed list, or another value, and stringifies the items. That is existing parser behavior, wider than the documented array, because no error sample was published. The joined message is what the tool returns.
- `X-Rate-Limit-Reset` is documented as seconds until the window resets, not as a Unix timestamp.
- Wildcard syntax (`%`, `?`, no leading wildcard, backslash escapes) is written up on the search page. Combo and hash only say that `wildcard` enables wildcard search. The MCP search tool does not expose `wildcard`.

## Not in this contract

DeHashed is the second member. Its contract is [dehashed-contract.md](dehashed-contract.md). Shodan, other WHOIS providers, and certificate transparency are examples in the vision, not members of this repo. Shared runtime stays unextracted. The two clients both redact a secret and refuse redirects. Auth, errors, pacing, and pagination are different, so those pieces stay in each source. Source packages do not depend on each other.

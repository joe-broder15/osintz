# MCP conventions

These rules apply to every source in this repo. A source contract names that source's tools, endpoints, and doc ambiguities. It does not restate this page.

## Server

- The console script is stdio only. `main` calls `MCPServer.run(transport="stdio")`. There is no HTTP listener.
- A tool name includes the source name (`snusbase-search`, `dehashed-search`). The bare names `search` and `whois` are not registered.
- Each tool sets `structured_output=False` and returns a JSON object as text.
- The API key is an environment variable, read when the process constructs the client inside the server lifespan. Changing the variable after the process has started does not change the key already stored. The key is never a tool argument and never a Nix expression.
- Client exceptions become MCP `ToolError` text. The translator may add the env var name. It must not add the key.
- The package does not log. Do not log a row, a key, or a plaintext password.

## Client

- Request models reject unknown fields. Response models keep extra keys. `None` on an optional request field is left out of the JSON. `False` and an empty list are sent.
- `follow_redirects=False`. A redirect must not carry the credential to another host. The redirect error must not include the `Location` header.
- A secret wrapper hides the key from `str`, `repr`, and `format`. `reveal` is the only way to read it. That wrapper, the error base (`message` and `status_code`), the blank-base-URL check, the redirect sentence, the client `repr`, and the env-var sentence live in `osintz-common`. A transport error names the exception type and is raised `from None`. Do not put an `httpx.Response` or an `httpx.Request` on the response object or on an exception. Rate-limit header parsing stays in the source that documents those headers.
- The client does not retry. It does not sleep after HTTP 429.
- Pre-send pacing is allowed only when that source's own docs state a numeric limit and the source contract records the pace. It is not required of every source. Snusbase does not pace. DeHashed paces at 20 requests per second before send, because the DeHashed docs reject more than 20 requests in one second and the human asked the client to respect that limit.

## Tools

The human-named tool list is a whitelist. Do not register a tool that is not on it.

Every tool in a source contract is marked **read-only** or **account-mutating**.

An account-mutating tool changes the remote account (create, update, delete, enable, disable, clear, or subscribe). It needs explicit human sign-off before implementation. A read-only list of names is not that sign-off. Do not infer a write from a documented endpoint the human did not name.

Source text is untrusted. Do not render rows as HTML.

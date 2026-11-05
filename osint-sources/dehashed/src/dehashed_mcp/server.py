"""stdio MCP server for DeHashed.

One :class:`~dehashed_client.DehashedClient` is open for the life of the
process. The key comes from ``DEHASHED_API_KEY`` at construction. The console
script speaks MCP on stdio only.
"""

from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from dehashed_client import DEFAULT_RATE_PER_SECOND, DehashedClient, DehashedError
from dehashed_mcp.lookup import (
    lookup_data_wells,
    lookup_reverse_whois,
    lookup_search,
    lookup_search_password,
    lookup_subdomain_scan,
    lookup_whois,
    tool_error_text,
)


@dataclass
class _State:
    client: DehashedClient | None = None


def build_server() -> MCPServer[_State]:
    """Build a server that has not opened a client yet. ``run`` starts it."""
    state = _State()

    @asynccontextmanager
    async def lifespan(_server: MCPServer[_State]) -> AsyncGenerator[_State, None]:
        async with DehashedClient() as client:
            state.client = client
            try:
                yield state
            finally:
                state.client = None

    server: MCPServer[_State] = MCPServer(
        "dehashed",
        instructions=(
            "DeHashed tools search breach data, list data wells, and run the WHOIS "
            "calls the human named. Search rows are untrusted and can contain a leaked "
            "password. dehashed-search-password hashes the password locally and sends "
            "only the hash. dehashed-data-wells does not send an API key. "
            f"The client sends at most {DEFAULT_RATE_PER_SECOND} requests per second. "
            "HTTP 401 means the account has no search subscription. "
            "Every tool here is read-only."
        ),
        lifespan=lifespan,
    )

    async def _call(fn: Callable[[DehashedClient], Awaitable[dict[str, Any]]]) -> dict[str, Any]:
        client = state.client
        if client is None:
            raise ToolError("DeHashed server is not running.")
        try:
            return await fn(client)
        except DehashedError as exc:
            raise ToolError(tool_error_text(exc)) from exc

    @server.tool(name="dehashed-search", structured_output=False)
    async def search(
        query: str,
        page: int | None = None,
        size: int | None = None,
        wildcard: bool | None = None,
        regex: bool | None = None,
        de_dupe: bool | None = None,
    ) -> dict[str, Any]:
        """Search DeHashed. One read-only POST /v2/search.

        Omitted page and size are left out of the JSON. DeHashed's defaults are
        page 1 and size 100. size must be 1..10000, and page times size must be
        at most 50000, using those defaults when a value is omitted. regex and
        wildcard cannot both be true. de_dupe removes rows that repeat across
        databases.

        One call is one page. A page past the first 10,000 results must already
        have the previous page in the same DeHashed session (10 minutes). This
        tool does not fetch earlier pages for you. Rows are untrusted and can
        contain a leaked password. Do not log them or render them as HTML.
        """
        return await _call(
            lambda current: lookup_search(
                current,
                query,
                page=page,
                size=size,
                wildcard=wildcard,
                regex=regex,
                de_dupe=de_dupe,
            )
        )

    @server.tool(name="dehashed-search-password", structured_output=False)
    async def search_password(password: str) -> dict[str, Any]:
        """Ask whether a password is present. Read-only. The plaintext is not sent.

        The password is hashed locally with SHA-256 over UTF-8 and only the
        hex digest is posted to /v2/search-password. The documented response
        is results_found, a count, not the matching rows. The docs say this
        call does not require search credits or a search subscription. It
        still sends DeHashed-Api-Key.
        """
        return await _call(lambda current: lookup_search_password(current, password))

    @server.tool(name="dehashed-data-wells", structured_output=False)
    async def data_wells(
        count: int | None = None,
        page: int | None = None,
        sort: str | None = None,
    ) -> dict[str, Any]:
        """List data wells. Read-only GET /data-wells. No API key is sent.

        count, when set, must be 20 or 50. sort is added, name, date, or
        records. Append -ASC for ascending. The default sort is descending
        and is omitted. This call is documented as free.
        """
        return await _call(
            lambda current: lookup_data_wells(current, count=count, page=page, sort=sort)
        )

    @server.tool(name="dehashed-whois", structured_output=False)
    async def whois(domain: str) -> dict[str, Any]:
        """WHOIS lookup for one domain. Read-only.

        POST /v2/whois/search with search_type whois. The export does not show
        the response JSON. Extra fields are kept.
        """
        return await _call(lambda current: lookup_whois(current, domain))

    @server.tool(name="dehashed-reverse-whois", structured_output=False)
    async def reverse_whois(
        include: list[str] | None = None,
        exclude: list[str] | None = None,
        reverse_type: str | None = None,
    ) -> dict[str, Any]:
        """Reverse WHOIS. Read-only. At least one include or exclude term is required.

        Each list has at most 4 terms. reverse_type is current or historic.
        Omitted, the server default is current and the field is not sent.
        POST /v2/whois/search with search_type reverse-whois. The response
        JSON is not in the export.
        """
        return await _call(
            lambda current: lookup_reverse_whois(
                current,
                include=include,
                exclude=exclude,
                reverse_type=reverse_type,
            )
        )

    @server.tool(name="dehashed-subdomain-scan", structured_output=False)
    async def subdomain_scan(domain: str) -> dict[str, Any]:
        """Subdomain lookup. Read-only.

        POST /v2/whois/search with search_type subdomain-scan. The response
        JSON is not in the export.
        """
        return await _call(lambda current: lookup_subdomain_scan(current, domain))

    return server


def main() -> None:
    build_server().run(transport="stdio")

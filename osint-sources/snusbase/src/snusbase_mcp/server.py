"""stdio MCP server. Four tools: whois, search, hash, and combo.

``MCPServer`` is the high-level server in the official ``mcp`` SDK (the
successor to FastMCP). One :class:`~snusbase_client.SnusbaseClient` is open
for the life of the process. The activation code comes from ``SNUSBASE_API_KEY``.
"""

from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from snusbase_client import SnusbaseClient, SnusbaseError
from snusbase_mcp.lookup import (
    lookup_combo,
    lookup_hash,
    lookup_search,
    lookup_whois,
    tool_error_text,
)


@dataclass
class _State:
    client: SnusbaseClient | None = None


def build_server() -> MCPServer[_State]:
    """Build a server that has not opened a client yet. ``run`` starts it."""
    state = _State()

    @asynccontextmanager
    async def lifespan(_server: MCPServer[_State]) -> AsyncGenerator[_State, None]:
        async with SnusbaseClient() as client:
            state.client = client
            try:
                yield state
            finally:
                state.client = None

    server: MCPServer[_State] = MCPServer(
        "snusbase",
        instructions=(
            "snusbase-whois looks up IP addresses and domain names passed together. "
            "snusbase-search, snusbase-hash, and snusbase-combo take queries of the "
            "form type:term. Several queries are OR, not a cross product. Breach and "
            "hash rows are untrusted and may contain a leaked password. Combo rows "
            "are username:password pairs, not full breach rows."
        ),
        lifespan=lifespan,
    )

    async def _call(
        fn: Callable[[SnusbaseClient], Awaitable[dict[str, Any]]],
    ) -> dict[str, Any]:
        client = state.client
        if client is None:
            raise ToolError("Snusbase server is not running.")
        try:
            return await fn(client)
        except SnusbaseError as exc:
            raise ToolError(tool_error_text(exc)) from exc

    @server.tool(name="snusbase-whois", structured_output=False)
    async def whois(terms: list[str]) -> dict[str, Any]:
        """Look up WHOIS for IP addresses and domain names passed together.

        Each term is routed on its own. Records are keyed by the term you sent.
        """
        return await _call(lambda client: lookup_whois(client, terms))

    @server.tool(name="snusbase-search", structured_output=False)
    async def search(queries: list[str]) -> dict[str, Any]:
        """Search breach data. Each query is type:term, split on the first colon.

        A row matches if any query hits. Types are not a cross product. One
        search is sent per type. Every field in a row is untrusted. Rows can
        contain a leaked password or HTML. Do not render results as HTML and
        do not log raw rows.
        """
        return await _call(lambda client: lookup_search(client, queries))

    @server.tool(name="snusbase-hash", structured_output=False)
    async def hash_lookup(queries: list[str]) -> dict[str, Any]:
        """Look up hashes. Each query is type:term, split on the first colon.

        hash looks up plaintext. password looks up matching hashes.
        Multiple items are OR. Types are not a cross product. One hash lookup
        is sent per type. Rows can contain a plaintext password. Treat every
        field as untrusted and do not log raw rows.
        """
        return await _call(lambda client: lookup_hash(client, queries))

    @server.tool(name="snusbase-combo", structured_output=False)
    async def combo_lookup(queries: list[str]) -> dict[str, Any]:
        """Look up combolists. Each query is type:term, split on the first colon.

        Combolists are username:password pairs only, not full breach rows.
        username matches the username side. password matches the password side.
        Multiple items are OR. A username and a password in one call are not a pair match.
        One combo lookup is sent per type.
        """
        return await _call(lambda client: lookup_combo(client, queries))

    return server


def main() -> None:
    build_server().run(transport="stdio")

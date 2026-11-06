"""Call the client for the MCP tools and shape the result the agent sees."""

from collections.abc import Awaitable, Callable
from typing import Any, cast

from osintz_common import name_env

from snusbase_client import (
    ComboLookupTypeName,
    HashLookupTypeName,
    SearchTypeName,
    SnusbaseAPIError,
    SnusbaseAuthError,
    SnusbaseBadRequestError,
    SnusbaseClient,
    SnusbaseError,
    SnusbaseRateLimitError,
    SnusbaseResponse,
)
from snusbase_client.client import ENV_API_KEY
from snusbase_mcp.routing import split_whois_terms

SEARCH_QUERY_TYPES = frozenset(
    {"email", "username", "lastip", "password", "hash", "name", "_domain"}
)
HASH_QUERY_TYPES = frozenset({"hash", "password"})
COMBO_QUERY_TYPES = frozenset({"username", "password"})


def tool_error_text(exc: SnusbaseError) -> str:
    """Text for a tool error. Names the env var on auth failure, never the key.

    A rate-limit error includes ``reset_seconds`` when the header was an integer.
    """
    if isinstance(exc, SnusbaseAuthError):
        return name_env(exc.message, ENV_API_KEY)
    if isinstance(exc, SnusbaseRateLimitError) and exc.reset_seconds is not None:
        return f"{exc.message} reset_seconds={exc.reset_seconds}"
    return exc.message


def parse_typed_queries(queries: list[str], allowed: frozenset[str]) -> list[tuple[str, list[str]]]:
    """Split ``type:term`` queries and group terms by type.

    The split is the first colon only. The prefix is the type. Everything after
    it is the term, including further colons. Whitespace is kept. Types are
    returned in the order they first appear. Rejects an empty list, a missing
    colon, an empty type, an empty term, or a type outside ``allowed`` before
    any request is sent.
    """
    if not queries:
        raise SnusbaseBadRequestError("At least one query is required.")
    grouped: dict[str, list[str]] = {}
    order: list[str] = []
    for raw in queries:
        if ":" not in raw:
            raise SnusbaseBadRequestError("Each query must be type:term.")
        type_name, term = raw.split(":", 1)
        if type_name == "":
            raise SnusbaseBadRequestError("Query type is empty.")
        if term == "":
            raise SnusbaseBadRequestError("Query term is empty.")
        if type_name not in allowed:
            raise SnusbaseBadRequestError(f"Query type is not documented: {type_name}.")
        if type_name not in grouped:
            order.append(type_name)
            grouped[type_name] = []
        grouped[type_name].append(term)
    return [(type_name, grouped[type_name]) for type_name in order]


def _view(response: SnusbaseResponse[Any]) -> dict[str, Any]:
    return {
        "took": response.data.took,
        "size": response.data.size,
        "results": response.data.results,
        "rate_limit": response.rate_limit.model_dump(),
    }


def _merge_grouped(parts: list[dict[str, Any]]) -> dict[str, Any]:
    """Sum sizes and ``took``, concatenate rows per table, keep the last rate limit.

    Each part's ``results`` must be an object of table name to a list of rows.
    That is the shape when ``group_by`` is omitted and the server default is ``"db"``.
    """
    results: dict[str, list[Any]] = {}
    size = 0
    took = 0.0
    for part in parts:
        size += part["size"]
        took += part["took"]
        rows = part["results"]
        if not isinstance(rows, dict):
            raise SnusbaseAPIError("Results were not grouped by table.")
        for table, table_rows in rows.items():
            if not isinstance(table_rows, list):
                raise SnusbaseAPIError("Results were not grouped by table.")
            results.setdefault(table, []).extend(table_rows)
    return {
        "took": took,
        "size": size,
        "results": results,
        "rate_limit": parts[-1]["rate_limit"],
    }


async def _lookup_by_type(
    client: SnusbaseClient,
    queries: list[str],
    allowed: frozenset[str],
    call: Callable[[SnusbaseClient, list[str], str], Awaitable[SnusbaseResponse[Any]]],
) -> dict[str, Any]:
    groups = parse_typed_queries(queries, allowed)
    parts: list[dict[str, Any]] = []
    for type_name, terms in groups:
        parts.append(_view(await call(client, terms, type_name)))
    return _merge_grouped(parts)


async def lookup_whois(client: SnusbaseClient, terms: list[str]) -> dict[str, Any]:
    """WHOIS for a mixed list. Only the kinds that were sent are present."""
    ips, domains = split_whois_terms(terms)
    out: dict[str, Any] = {}
    if ips:
        out["ip"] = _view(await client.ip_whois(ips))
    if domains:
        found = await client.domain_whois(domains)
        view = _view(found)
        if found.data.errors is not None:
            view["errors"] = found.data.errors
        out["domain"] = view
    return out


async def lookup_search(client: SnusbaseClient, queries: list[str]) -> dict[str, Any]:
    """One ``POST /data/search`` per type. Queries are OR, not a cross product."""
    return await _lookup_by_type(
        client,
        queries,
        SEARCH_QUERY_TYPES,
        lambda current, terms, type_name: current.search(terms, [cast(SearchTypeName, type_name)]),
    )


async def lookup_hash(client: SnusbaseClient, queries: list[str]) -> dict[str, Any]:
    """One ``POST /tools/hash-lookup`` per type."""
    return await _lookup_by_type(
        client,
        queries,
        HASH_QUERY_TYPES,
        lambda current, terms, type_name: current.hash_lookup(
            terms, [cast(HashLookupTypeName, type_name)]
        ),
    )


async def lookup_combo(client: SnusbaseClient, queries: list[str]) -> dict[str, Any]:
    """One ``POST /tools/combo-lookup`` per type."""
    return await _lookup_by_type(
        client,
        queries,
        COMBO_QUERY_TYPES,
        lambda current, terms, type_name: current.combo_lookup(
            terms, [cast(ComboLookupTypeName, type_name)]
        ),
    )

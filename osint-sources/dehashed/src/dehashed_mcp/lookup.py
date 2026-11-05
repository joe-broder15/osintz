"""Call the client for the MCP tools and shape the result the agent sees."""

from typing import Any

from pydantic import BaseModel

from dehashed_client import (
    ENV_API_KEY,
    DehashedAuthError,
    DehashedBadRequestError,
    DehashedClient,
    DehashedError,
    DehashedSubscriptionError,
)
from dehashed_client.client import DehashedResponse


def tool_error_text(exc: DehashedError) -> str:
    """Text for a tool error. Names the env var on a missing key, never the key.

    HTTP 401 stays a subscription message. A 400 whose text mentions
    authentication names ``DEHASHED_API_KEY`` without appending the key.
    """
    if isinstance(exc, DehashedAuthError):
        if ENV_API_KEY not in exc.message:
            return f"{exc.message} Set {ENV_API_KEY}."
        return exc.message
    if isinstance(exc, DehashedBadRequestError) and "authentication" in exc.message.lower():
        if ENV_API_KEY not in exc.message:
            return f"{exc.message} Check {ENV_API_KEY}."
    if isinstance(exc, DehashedSubscriptionError):
        return exc.message
    return exc.message


def dump_model(model: BaseModel) -> dict[str, Any]:
    """JSON-ready dict. Omitted response attributes stay omitted."""
    return model.model_dump(mode="json", exclude_none=True)


def _dump(response: DehashedResponse[Any]) -> dict[str, Any]:
    return dump_model(response.data)


async def lookup_search(
    client: DehashedClient,
    query: str,
    *,
    page: int | None = None,
    size: int | None = None,
    wildcard: bool | None = None,
    regex: bool | None = None,
    de_dupe: bool | None = None,
) -> dict[str, Any]:
    """One ``POST /v2/search``. The caller asks for one page."""
    return _dump(
        await client.search(
            query,
            page=page,
            size=size,
            wildcard=wildcard,
            regex=regex,
            de_dupe=de_dupe,
        )
    )


async def lookup_search_password(client: DehashedClient, password: str) -> dict[str, Any]:
    return _dump(await client.search_password(password))


async def lookup_data_wells(
    client: DehashedClient,
    *,
    count: int | None = None,
    page: int | None = None,
    sort: str | None = None,
) -> dict[str, Any]:
    return _dump(await client.data_wells(count=count, page=page, sort=sort))


async def lookup_whois(client: DehashedClient, domain: str) -> dict[str, Any]:
    return _dump(await client.whois(domain))


async def lookup_reverse_whois(
    client: DehashedClient,
    *,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    reverse_type: str | None = None,
) -> dict[str, Any]:
    return _dump(
        await client.reverse_whois(include=include, exclude=exclude, reverse_type=reverse_type)
    )


async def lookup_subdomain_scan(client: DehashedClient, domain: str) -> dict[str, Any]:
    return _dump(await client.subdomain_scan(domain))

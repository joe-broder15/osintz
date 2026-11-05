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
    through_page: int | None = None,
) -> dict[str, Any]:
    """One search page, or pages 1..``through_page`` in order."""
    if through_page is not None and page is not None:
        raise DehashedBadRequestError("Pass page or through_page, not both.")
    if through_page is not None:
        found = await client.search_through(
            query,
            through_page,
            size=size,
            wildcard=wildcard,
            regex=regex,
            de_dupe=de_dupe,
        )
        return {"pages": [_dump(item) for item in found]}
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


async def lookup_user(client: DehashedClient) -> dict[str, Any]:
    return _dump(await client.user_info())


async def lookup_data_wells(
    client: DehashedClient,
    *,
    count: int | None = None,
    page: int | None = None,
    sort: str | None = None,
) -> dict[str, Any]:
    return _dump(await client.data_wells(count=count, page=page, sort=sort))


async def lookup_create_task(client: DehashedClient, task_type: str, value: str) -> dict[str, Any]:
    return _dump(await client.create_task(task_type, value))


async def lookup_update_task(
    client: DehashedClient,
    task_id: str,
    task_type: str,
    value: str,
    *,
    active: bool | None = None,
) -> dict[str, Any]:
    return _dump(await client.update_task(task_id, task_type, value, active=active))


async def lookup_set_task_active(
    client: DehashedClient, task_id: str, active: bool
) -> dict[str, Any]:
    return _dump(await client.update_task_active(task_id, active))


async def lookup_delete_task(client: DehashedClient, task_id: str) -> dict[str, Any]:
    return _dump(await client.delete_task(task_id))


async def lookup_tasks(client: DehashedClient, *, page: int | None = None) -> dict[str, Any]:
    return _dump(await client.get_tasks(page=page))


async def lookup_task(client: DehashedClient, task_id: str) -> dict[str, Any]:
    return _dump(await client.get_task(task_id))


async def lookup_reports(client: DehashedClient, *, page: int | None = None) -> dict[str, Any]:
    return _dump(await client.get_reports(page=page))


async def lookup_report(client: DehashedClient, report_id: str) -> dict[str, Any]:
    return _dump(await client.get_report(report_id))


async def lookup_channels(client: DehashedClient) -> dict[str, Any]:
    return _dump(await client.get_channels())


async def lookup_update_channel(
    client: DehashedClient, channel_type: str, value: str
) -> dict[str, Any]:
    return _dump(await client.update_channel(channel_type, value))


async def lookup_delete_channel(client: DehashedClient, channel_type: str) -> dict[str, Any]:
    return _dump(await client.delete_channel(channel_type))


async def lookup_domains(client: DehashedClient) -> dict[str, Any]:
    return _dump(await client.get_domains())


async def lookup_update_domain(
    client: DehashedClient, domain_id: str, domain: str
) -> dict[str, Any]:
    return _dump(await client.update_domain(domain_id, domain))


async def lookup_clear_domain(client: DehashedClient, domain_id: str) -> dict[str, Any]:
    return _dump(await client.clear_domain(domain_id))


async def lookup_whois(client: DehashedClient, domain: str) -> dict[str, Any]:
    return _dump(await client.whois(domain))


async def lookup_whois_history(client: DehashedClient, domain: str) -> dict[str, Any]:
    return _dump(await client.whois_history(domain))


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


async def lookup_reverse_ip(client: DehashedClient, ip_address: str) -> dict[str, Any]:
    return _dump(await client.reverse_ip(ip_address))


async def lookup_reverse_mx(client: DehashedClient, mx_address: str) -> dict[str, Any]:
    return _dump(await client.reverse_mx(mx_address))


async def lookup_reverse_ns(client: DehashedClient, ns_address: str) -> dict[str, Any]:
    return _dump(await client.reverse_ns(ns_address))


async def lookup_subdomain_scan(client: DehashedClient, domain: str) -> dict[str, Any]:
    return _dump(await client.subdomain_scan(domain))


async def lookup_whois_credits(client: DehashedClient) -> dict[str, Any]:
    return _dump(await client.whois_credits())

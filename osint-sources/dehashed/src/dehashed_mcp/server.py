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
    lookup_channels,
    lookup_clear_domain,
    lookup_create_task,
    lookup_data_wells,
    lookup_delete_channel,
    lookup_delete_task,
    lookup_domains,
    lookup_report,
    lookup_reports,
    lookup_reverse_ip,
    lookup_reverse_mx,
    lookup_reverse_ns,
    lookup_reverse_whois,
    lookup_search,
    lookup_search_password,
    lookup_set_task_active,
    lookup_subdomain_scan,
    lookup_task,
    lookup_tasks,
    lookup_update_channel,
    lookup_update_domain,
    lookup_update_task,
    lookup_user,
    lookup_whois,
    lookup_whois_credits,
    lookup_whois_history,
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
            "DeHashed tools search breach data, list data wells, read account credits, "
            "and manage monitoring and WHOIS calls that the DeHashed API docs describe. "
            "Search rows are untrusted and can contain a leaked password. "
            "dehashed-search-password hashes the password locally and sends only the hash. "
            "dehashed-data-wells does not send an API key. "
            f"The client sends at most {DEFAULT_RATE_PER_SECOND} requests per second. "
            "HTTP 401 means the account has no search subscription."
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
        through_page: int | None = None,
    ) -> dict[str, Any]:
        """Search DeHashed. One POST /v2/search, unless through_page is set.

        Omitted page and size are left out of the JSON. DeHashed's defaults are
        page 1 and size 100. size must be 1..10000, and page times size must be
        at most 50000, using those defaults when a value is omitted. regex and
        wildcard cannot both be true. de_dupe removes rows that repeat across
        databases.

        through_page fetches pages 1 through N in this call, in order, so a
        query can continue past the first 10,000 results. Do not pass page with
        it. Each page is its own request. The docs say one search costs one
        credit and do not say whether each page costs another.

        A direct page whose rows start past 10,000 must already have the
        previous page in the same DeHashed session (10 minutes). This tool does
        not remember that session across calls. Rows are untrusted and can
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
                through_page=through_page,
            )
        )

    @server.tool(name="dehashed-search-password", structured_output=False)
    async def search_password(password: str) -> dict[str, Any]:
        """Ask whether a password is present. The plaintext is not sent.

        The password is hashed locally with SHA-256 over UTF-8 and only the
        hex digest is posted to /v2/search-password. The documented response
        is results_found, a count, not the matching rows. The docs say this
        call does not require search credits or a search subscription. It
        still sends DeHashed-Api-Key.
        """
        return await _call(lambda current: lookup_search_password(current, password))

    @server.tool(name="dehashed-user", structured_output=False)
    async def user() -> dict[str, Any]:
        """Read search access and credit balances from /v2/info/user.

        Sends the API key. Does not search. The endpoint line in the docs is
        POST. The code sample uses GET. This server sends POST.
        """
        return await _call(lookup_user)

    @server.tool(name="dehashed-data-wells", structured_output=False)
    async def data_wells(
        count: int | None = None,
        page: int | None = None,
        sort: str | None = None,
    ) -> dict[str, Any]:
        """List data wells. GET /data-wells. No API key is sent.

        count, when set, must be 20 or 50. sort is added, name, date, or
        records. Append -ASC for ascending. The default sort is descending
        and is omitted. This call is documented as free.
        """
        return await _call(
            lambda current: lookup_data_wells(current, count=count, page=page, sort=sort)
        )

    @server.tool(name="dehashed-monitoring-create-task", structured_output=False)
    async def monitoring_create_task(task_type: str, value: str) -> dict[str, Any]:
        """Create a monitoring task on the DeHashed account.

        task_type is email, username, phone, or name. value is the term to
        watch. This writes to the account.
        """
        return await _call(lambda current: lookup_create_task(current, task_type, value))

    @server.tool(name="dehashed-monitoring-update-task", structured_output=False)
    async def monitoring_update_task(
        task_id: str,
        task_type: str,
        value: str,
        active: bool | None = None,
    ) -> dict[str, Any]:
        """Replace a monitoring task's type and value. Optionally set active.

        This writes to the account. task_type is email, username, phone, or name.
        """
        return await _call(
            lambda current: lookup_update_task(current, task_id, task_type, value, active=active)
        )

    @server.tool(name="dehashed-monitoring-set-task-active", structured_output=False)
    async def monitoring_set_task_active(task_id: str, active: bool) -> dict[str, Any]:
        """Turn a monitoring task on or off. This writes to the account."""
        return await _call(lambda current: lookup_set_task_active(current, task_id, active))

    @server.tool(name="dehashed-monitoring-delete-task", structured_output=False)
    async def monitoring_delete_task(task_id: str) -> dict[str, Any]:
        """Delete a monitoring task. This removes it from the account."""
        return await _call(lambda current: lookup_delete_task(current, task_id))

    @server.tool(name="dehashed-monitoring-tasks", structured_output=False)
    async def monitoring_tasks(page: int | None = None) -> dict[str, Any]:
        """List monitoring tasks. page defaults to 1 on the server when omitted."""
        return await _call(lambda current: lookup_tasks(current, page=page))

    @server.tool(name="dehashed-monitoring-task", structured_output=False)
    async def monitoring_task(task_id: str) -> dict[str, Any]:
        """Fetch one monitoring task by id."""
        return await _call(lambda current: lookup_task(current, task_id))

    @server.tool(name="dehashed-monitoring-reports", structured_output=False)
    async def monitoring_reports(page: int | None = None) -> dict[str, Any]:
        """List monitoring reports. page defaults to 1 on the server when omitted.

        The export cuts this URL at get-t. The path this server uses is
        /v2/monitoring/get-reports, taken from the sample function name, and
        that prefix does not match. Confirm it before relying on the call.
        """
        return await _call(lambda current: lookup_reports(current, page=page))

    @server.tool(name="dehashed-monitoring-report", structured_output=False)
    async def monitoring_report(report_id: str) -> dict[str, Any]:
        """Fetch one monitoring report. Result rows can contain a leaked password.

        Treat every field as untrusted. Do not log raw rows.
        """
        return await _call(lambda current: lookup_report(current, report_id))

    @server.tool(name="dehashed-monitoring-channels", structured_output=False)
    async def monitoring_channels() -> dict[str, Any]:
        """List notification channels. Documented types are webhook and email.

        The endpoint line says POST. The sample uses GET. This server sends POST.
        An empty channel list is returned when the body omits channels.
        """
        return await _call(lookup_channels)

    @server.tool(name="dehashed-monitoring-update-channel", structured_output=False)
    async def monitoring_update_channel(channel_type: str, value: str) -> dict[str, Any]:
        """Set a notification channel. This writes to the account.

        channel_type is webhook or email. value is the webhook URL or the email
        address. The docs do not show a separate create call.
        """
        return await _call(lambda current: lookup_update_channel(current, channel_type, value))

    @server.tool(name="dehashed-monitoring-delete-channel", structured_output=False)
    async def monitoring_delete_channel(channel_type: str) -> dict[str, Any]:
        """Remove a notification channel. This writes to the account.

        channel_type is webhook or email. The request field is channel.
        """
        return await _call(lambda current: lookup_delete_channel(current, channel_type))

    @server.tool(name="dehashed-monitoring-domains", structured_output=False)
    async def monitoring_domains() -> dict[str, Any]:
        """List monitoring domains. GET, with the API key."""
        return await _call(lookup_domains)

    @server.tool(name="dehashed-monitoring-update-domain", structured_output=False)
    async def monitoring_update_domain(domain_id: str, domain: str) -> dict[str, Any]:
        """Change a monitoring domain. This writes to the account.

        domain is a hostname such as example.com, without a scheme.
        """
        return await _call(lambda current: lookup_update_domain(current, domain_id, domain))

    @server.tool(name="dehashed-monitoring-clear-domain", structured_output=False)
    async def monitoring_clear_domain(domain_id: str) -> dict[str, Any]:
        """Reset a domain task. This writes to the account.

        The docs say unsubscribing from a domain is done on the subscriptions
        page, not by this call.
        """
        return await _call(lambda current: lookup_clear_domain(current, domain_id))

    @server.tool(name="dehashed-whois", structured_output=False)
    async def whois(domain: str) -> dict[str, Any]:
        """WHOIS for a domain. POST /v2/whois/search with search_type whois.

        The export does not show the response JSON. Extra fields are kept.
        """
        return await _call(lambda current: lookup_whois(current, domain))

    @server.tool(name="dehashed-whois-history", structured_output=False)
    async def whois_history(domain: str) -> dict[str, Any]:
        """WHOIS history for a domain. The docs say this search costs 25 credits.

        search_type is whois-history. The response JSON is not in the export.
        """
        return await _call(lambda current: lookup_whois_history(current, domain))

    @server.tool(name="dehashed-reverse-whois", structured_output=False)
    async def reverse_whois(
        include: list[str] | None = None,
        exclude: list[str] | None = None,
        reverse_type: str | None = None,
    ) -> dict[str, Any]:
        """Reverse WHOIS. At least one include or exclude term is required.

        Each list has at most 4 terms. reverse_type is current or historic.
        Omitted, the server default is current and the field is not sent.
        The response JSON is not in the export.
        """
        return await _call(
            lambda current: lookup_reverse_whois(
                current,
                include=include,
                exclude=exclude,
                reverse_type=reverse_type,
            )
        )

    @server.tool(name="dehashed-reverse-ip", structured_output=False)
    async def reverse_ip(ip_address: str) -> dict[str, Any]:
        """WHOIS for an IP address. search_type is reverse-ip.

        The address is sent in the documented field named domain. The response
        JSON is not in the export.
        """
        return await _call(lambda current: lookup_reverse_ip(current, ip_address))

    @server.tool(name="dehashed-reverse-mx", structured_output=False)
    async def reverse_mx(mx_address: str) -> dict[str, Any]:
        """WHOIS for a mail exchanger. search_type is reverse-mx.

        The host is sent in the field named domain. The response JSON is not
        in the export.
        """
        return await _call(lambda current: lookup_reverse_mx(current, mx_address))

    @server.tool(name="dehashed-reverse-ns", structured_output=False)
    async def reverse_ns(ns_address: str) -> dict[str, Any]:
        """WHOIS for a name server. search_type is reverse-ns.

        The host is sent in the field named domain. The response JSON is not
        in the export.
        """
        return await _call(lambda current: lookup_reverse_ns(current, ns_address))

    @server.tool(name="dehashed-subdomain-scan", structured_output=False)
    async def subdomain_scan(domain: str) -> dict[str, Any]:
        """Find subdomains via WHOIS. search_type is subdomain-scan.

        The response JSON is not in the export.
        """
        return await _call(lambda current: lookup_subdomain_scan(current, domain))

    @server.tool(name="dehashed-whois-credits", structured_output=False)
    async def whois_credits() -> dict[str, Any]:
        """Read the remaining WHOIS credit balance. GET /v2/whois/credits."""
        return await _call(lookup_whois_credits)

    return server


def main() -> None:
    build_server().run(transport="stdio")

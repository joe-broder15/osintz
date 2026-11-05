"""HTTP behavior, mocked. No test in this file opens a socket."""

import ast
import asyncio
import hashlib
import inspect
import json
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from dehashed_client import (
    DEFAULT_RATE_PER_SECOND,
    DehashedAPIError,
    DehashedAuthError,
    DehashedBadRequestError,
    DehashedClient,
    DehashedError,
    DehashedForbiddenError,
    DehashedRateLimitError,
    DehashedSubscriptionError,
    __version__,
    hash_password,
)
from dehashed_client.client import (
    AUTH_HEADER,
    DEFAULT_BASE_URL,
    DEFAULT_TIMEOUT_SECONDS,
    ENV_API_KEY,
    OPERATIONS,
    PATH_GET_REPORTS,
)

API_KEY = "test-key-not-a-secret"
LEAK_KEY = "leak-key-0123456789"
PASSWORD = "HorseBattery!"

SEARCH_BODY = {
    "balance": 60,
    "entries": [
        {
            "id": "1",
            "email": ["ada@example.com"],
            "password": ["secret"],
            "database_name": "Example",
        }
    ],
    "took": "179µs",
    "total": 1,
}
WELLS_BODY = {
    "next_page": False,
    "total": 1,
    "data_wells": [
        {
            "data": "email",
            "date": "2025-03-01",
            "description": "A well",
            "name": "Example",
            "records": 5,
            "is_sensitive": False,
        }
    ],
}
SUCCESS = {"success": True}
USER_BODY = {"search_access": False, "search_credits": 0, "whois_credits": 1}
TASKS_BODY = {
    "tasks": [
        {
            "id": "t",
            "type": "email",
            "value": "ada@example.com",
            "active": True,
            "created": "2023-01-01T12:00:00.000000Z",
            "updated": "2023-01-01T12:00:00.000000Z",
        }
    ],
    "total": 1,
    "active": 1,
    "inactive": 0,
    "max": 10,
    "next_page": False,
}
TASK_BODY = {
    "type": "email",
    "value": "ada@example.com",
    "active": True,
    "created": "2023-01-01T12:00:00.000000Z",
    "updated": "2023-01-01T12:00:00.000000Z",
}
REPORTS_BODY = {
    "reports": [{"id": "r", "timestamp": "2023-01-01T12:00:00.000000Z"}],
    "next_page": False,
}
REPORT_BODY = {
    "tasks": [
        {
            "id": "ref",
            "key": "email",
            "value": "ada@example.com",
            "results_count": 1,
            "timestamp": "2023-01-01T12:00:00.000000Z",
            "results": [{"id": "1", "email": ["ada@example.com"]}],
        }
    ]
}
CHANNELS_BODY = {
    "channels": [
        {
            "id": "c",
            "type": "webhook",
            "value": "https://example.com/hook",
            "updated_at": "2023-01-01T12:00:00.000000Z",
        }
    ]
}
DOMAINS_BODY = {
    "domains": [{"id": "d", "domain": "example.com", "updated": "2023-01-01T12:00:00.000000Z"}]
}
WHOIS_BODY = {"unspecified": True}
CREDITS_BODY = {"whois_credits": 4}


def _bodies() -> dict[str, dict[str, Any]]:
    return {
        "search": SEARCH_BODY,
        "search_password": {"results_found": 1},
        "user_info": USER_BODY,
        "data_wells": WELLS_BODY,
        "create_task": SUCCESS,
        "update_task": SUCCESS,
        "update_task_active": SUCCESS,
        "delete_task": SUCCESS,
        "get_tasks": TASKS_BODY,
        "get_task": TASK_BODY,
        "get_reports": REPORTS_BODY,
        "get_report": REPORT_BODY,
        "get_channels": CHANNELS_BODY,
        "update_channel": SUCCESS,
        "delete_channel": SUCCESS,
        "get_domains": DOMAINS_BODY,
        "update_domain": SUCCESS,
        "clear_domain": SUCCESS,
        "whois": WHOIS_BODY,
        "whois_history": WHOIS_BODY,
        "reverse_whois": WHOIS_BODY,
        "reverse_ip": WHOIS_BODY,
        "reverse_mx": WHOIS_BODY,
        "reverse_ns": WHOIS_BODY,
        "subdomain_scan": WHOIS_BODY,
        "whois_credits": CREDITS_BODY,
    }


async def _invoke(client: DehashedClient, name: str) -> Any:
    if name == "search":
        return await client.search("ada@example.com")
    if name == "search_password":
        return await client.search_password(PASSWORD)
    if name == "user_info":
        return await client.user_info()
    if name == "data_wells":
        return await client.data_wells()
    if name == "create_task":
        return await client.create_task("email", "ada@example.com")
    if name == "update_task":
        return await client.update_task("t", "email", "ada@example.com")
    if name == "update_task_active":
        return await client.update_task_active("t", False)
    if name == "delete_task":
        return await client.delete_task("t")
    if name == "get_tasks":
        return await client.get_tasks()
    if name == "get_task":
        return await client.get_task("t")
    if name == "get_reports":
        return await client.get_reports()
    if name == "get_report":
        return await client.get_report("r")
    if name == "get_channels":
        return await client.get_channels()
    if name == "update_channel":
        return await client.update_channel("webhook", "https://example.com/hook")
    if name == "delete_channel":
        return await client.delete_channel("email")
    if name == "get_domains":
        return await client.get_domains()
    if name == "update_domain":
        return await client.update_domain("d", "example.com")
    if name == "clear_domain":
        return await client.clear_domain("d")
    if name == "whois":
        return await client.whois("example.com")
    if name == "whois_history":
        return await client.whois_history("example.com")
    if name == "reverse_whois":
        return await client.reverse_whois(include=["ada"])
    if name == "reverse_ip":
        return await client.reverse_ip("8.8.8.8")
    if name == "reverse_mx":
        return await client.reverse_mx("mx.example.com")
    if name == "reverse_ns":
        return await client.reverse_ns("ns.example.com")
    if name == "subdomain_scan":
        return await client.subdomain_scan("example.com")
    if name == "whois_credits":
        return await client.whois_credits()
    raise AssertionError(name)


def _wire(name: str) -> dict[str, Any] | None:
    digest = hashlib.sha256(PASSWORD.encode("utf-8")).hexdigest()
    bodies: dict[str, dict[str, Any] | None] = {
        "search": {"query": "ada@example.com"},
        "search_password": {"sha256_hashed_password": digest},
        "user_info": {},
        "data_wells": None,
        "create_task": {"type": "email", "value": "ada@example.com"},
        "update_task": {"id": "t", "type": "email", "value": "ada@example.com"},
        "update_task_active": {"id": "t", "active": False},
        "delete_task": {"id": "t"},
        "get_tasks": {},
        "get_task": {"id": "t"},
        "get_reports": {},
        "get_report": {"id": "r"},
        "get_channels": {},
        "update_channel": {"type": "webhook", "value": "https://example.com/hook"},
        "delete_channel": {"channel": "email"},
        "get_domains": None,
        "update_domain": {"id": "d", "domain": "example.com"},
        "clear_domain": {"id": "d"},
        "whois": {"search_type": "whois", "domain": "example.com"},
        "whois_history": {"search_type": "whois-history", "domain": "example.com"},
        "reverse_whois": {"search_type": "reverse-whois", "include": ["ada"]},
        "reverse_ip": {"search_type": "reverse-ip", "domain": "8.8.8.8"},
        "reverse_mx": {"search_type": "reverse-mx", "domain": "mx.example.com"},
        "reverse_ns": {"search_type": "reverse-ns", "domain": "ns.example.com"},
        "subdomain_scan": {"search_type": "subdomain-scan", "domain": "example.com"},
        "whois_credits": None,
    }
    return bodies[name]


def run[T](callback: Callable[[DehashedClient], Awaitable[T]], /, *args: Any, **kwargs: Any) -> T:
    async def _go() -> T:
        async with DehashedClient(*args, **kwargs) as client:
            return await callback(client)

    return asyncio.run(_go())


def _mock(router: Any, name: str, *, status: int, payload: dict[str, Any] | None) -> None:
    method, path, _auth = OPERATIONS[name]
    kwargs: dict[str, Any] = {"status_code": status}
    if payload is not None:
        kwargs["json"] = payload
    getattr(router, method.lower())(DEFAULT_BASE_URL + path).mock(
        return_value=httpx.Response(**kwargs)
    )


def test_client_sources_do_not_import_mcp_or_snusbase() -> None:
    root = Path(__file__).resolve().parents[1] / "src" / "dehashed_client"
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
            for module in modules:
                top = module.split(".", 1)[0]
                assert top not in {"mcp", "snusbase_client", "snusbase_mcp", "dehashed_mcp"}


def test_public_methods_match_operations() -> None:
    methods = {
        name
        for name, value in vars(DehashedClient).items()
        if not name.startswith("_") and inspect.isfunction(value)
    }
    assert methods - {"aclose"} == set(OPERATIONS) | {"search_through"}
    assert __version__ == "0.1.0"
    assert PATH_GET_REPORTS == "/v2/monitoring/get-reports"
    assert OPERATIONS["get_reports"][1] == PATH_GET_REPORTS
    assert OPERATIONS["user_info"][0] == "POST"
    assert OPERATIONS["get_channels"][0] == "POST"
    assert OPERATIONS["data_wells"] == ("GET", "/data-wells", False)


@pytest.mark.parametrize("name", list(OPERATIONS))
def test_each_operation_matches_the_documented_call(router: Any, name: str) -> None:
    _mock(router, name, status=200, payload=_bodies()[name])
    result = run(lambda client: _invoke(client, name), api_key=API_KEY)
    assert result.status_code == 200
    method, path, authenticated = OPERATIONS[name]
    request = router.calls[0].request
    assert request.method == method
    assert request.url.path == path
    header = request.headers.get(AUTH_HEADER)
    if authenticated:
        assert header == API_KEY
        assert API_KEY not in repr(result)
    else:
        assert header is None
    if method == "POST":
        assert request.headers["content-type"].startswith("application/json")
        assert json.loads(request.content) == _wire(name)
    else:
        assert "content-type" not in request.headers
        assert request.content == b""
    raw = request.content.decode()
    assert PASSWORD not in raw
    assert API_KEY not in raw
    if name == "search_password":
        assert hash_password(PASSWORD) in raw
        assert PASSWORD not in str(request.url)


def test_password_hash_is_utf8_sha256_hex() -> None:
    digest = hash_password("pá")
    assert digest == hashlib.sha256("pá".encode()).hexdigest()
    assert "pá" not in digest
    with pytest.raises(DehashedBadRequestError, match="empty"):
        hash_password("")


def test_data_wells_omits_the_key_even_when_one_is_configured(router: Any) -> None:
    _mock(router, "data_wells", status=200, payload=WELLS_BODY)
    run(
        lambda client: client.data_wells(count=50, page=2, sort="records"),
        api_key=LEAK_KEY,
    )
    request = router.calls[0].request
    assert request.headers.get(AUTH_HEADER) is None
    assert LEAK_KEY not in str(request.url)
    assert request.url.params["count"] == "50"
    assert request.url.params["page"] == "2"
    assert request.url.params["sort"] == "records"


def test_missing_key_blocks_search_and_still_allows_data_wells(router: Any) -> None:
    _mock(router, "data_wells", status=200, payload=WELLS_BODY)

    async def call(client: DehashedClient) -> None:
        with pytest.raises(DehashedAuthError, match=ENV_API_KEY):
            await client.search("ada@example.com")
        await client.data_wells()

    run(call)
    assert len(router.calls) == 1
    assert router.calls[0].request.url.path == "/data-wells"


def test_empty_key_is_rejected_before_any_request() -> None:
    with pytest.raises(DehashedAuthError, match="empty"):
        DehashedClient(api_key="")
    with pytest.raises(DehashedAuthError, match="empty"):
        DehashedClient(api_key="   ")


def test_search_limits_do_not_send(router: Any) -> None:
    async def call(client: DehashedClient) -> None:
        with pytest.raises(DehashedBadRequestError, match="size must be between 1 and 10000"):
            await client.search("ada@example.com", size=0)
        with pytest.raises(DehashedBadRequestError, match="pagination limit exceeded"):
            await client.search("ada@example.com", page=6, size=10_000)
        with pytest.raises(DehashedBadRequestError, match="regex and wildcard cannot both be true"):
            await client.search("ada@example.com", regex=True, wildcard=True)
        with pytest.raises(DehashedBadRequestError, match="pagination limit exceeded"):
            await client.search_through("ada@example.com", 6, size=10_000)

    run(call, api_key=API_KEY)
    assert len(router.calls) == 0


def test_sequential_pages_are_sent_in_order(router: Any) -> None:
    router.post(DEFAULT_BASE_URL + "/v2/search").mock(
        side_effect=[
            httpx.Response(200, json=SEARCH_BODY),
            httpx.Response(200, json=SEARCH_BODY),
        ]
    )

    async def call(client: DehashedClient) -> list[int]:
        found = await client.search_through(
            "ada@example.com",
            2,
            size=10_000,
            de_dupe=True,
        )
        return [item.data.total for item in found]

    assert run(call, api_key=API_KEY) == [1, 1]
    assert json.loads(router.calls[0].request.content)["page"] == 1
    assert json.loads(router.calls[1].request.content)["page"] == 2
    assert json.loads(router.calls[0].request.content)["size"] == 10_000
    assert json.loads(router.calls[0].request.content)["de_dupe"] is True


def test_a_later_sequential_page_does_not_return_earlier_bodies(router: Any) -> None:
    router.post(DEFAULT_BASE_URL + "/v2/search").mock(
        side_effect=[
            httpx.Response(200, json=SEARCH_BODY),
            httpx.Response(
                400,
                json={
                    "error": (
                        "deep pagination error: pages must be fetched sequentially - "
                        "please restart from page 1"
                    )
                },
            ),
        ]
    )

    async def call(client: DehashedClient) -> None:
        with pytest.raises(DehashedBadRequestError, match="restart from page 1"):
            await client.search_through("ada@example.com", 2, size=10_000)

    run(call, api_key=API_KEY)
    assert len(router.calls) == 2


@pytest.mark.parametrize(
    ("status", "payload", "exc_type", "match"),
    [
        (400, {"error": "issue with authentication"}, DehashedBadRequestError, "authentication"),
        (
            401,
            {
                "error": (
                    "You need a search subscription and API credits to use the API, "
                    "please purchase a search subscription."
                )
            },
            DehashedSubscriptionError,
            "search subscription",
        ),
        (403, {"error": "Insufficient Credits"}, DehashedForbiddenError, "Insufficient Credits"),
        (429, {"error": "too many requests"}, DehashedRateLimitError, "20 requests per second"),
    ],
)
def test_documented_error_statuses(
    router: Any,
    status: int,
    payload: dict[str, str],
    exc_type: type[Exception],
    match: str,
) -> None:
    _mock(router, "search", status=status, payload=payload)
    with pytest.raises(exc_type, match=match) as caught:
        run(lambda client: client.search("ada@example.com"), api_key=API_KEY)
    err = caught.value
    assert isinstance(err, DehashedError)
    assert err.status_code == status
    assert API_KEY not in str(err)


def test_password_search_still_calls_when_search_would_be_unauthorized(router: Any) -> None:
    _mock(
        router,
        "search_password",
        status=200,
        payload={"results_found": 0},
    )
    result = run(lambda client: client.search_password(PASSWORD), api_key=API_KEY)
    assert result.data.results_found == 0
    assert PASSWORD not in router.calls[0].request.content.decode()


def test_error_body_redacts_the_key_and_a_long_password(router: Any) -> None:
    router.post(DEFAULT_BASE_URL + "/v2/search").mock(
        return_value=httpx.Response(400, json={"error": f"rejected {LEAK_KEY}"})
    )
    router.post(DEFAULT_BASE_URL + "/v2/search-password").mock(
        return_value=httpx.Response(400, json={"error": f"echo {PASSWORD}"})
    )

    async def call(client: DehashedClient) -> tuple[str, str]:
        with pytest.raises(DehashedBadRequestError) as key_error:
            await client.search("ada@example.com")
        with pytest.raises(DehashedBadRequestError) as password_error:
            await client.search_password(PASSWORD)
        return str(key_error.value), str(password_error.value)

    key_message, password_message = run(call, api_key=LEAK_KEY)
    assert LEAK_KEY not in key_message
    assert "<redacted>" in key_message
    assert PASSWORD not in password_message
    assert "<redacted>" in password_message


def test_redirect_transport_and_schema_errors(router: Any) -> None:
    router.post(DEFAULT_BASE_URL + "/v2/search").mock(
        side_effect=[
            httpx.Response(
                302,
                headers={"Location": "https://evil.example/collect?key=" + LEAK_KEY},
            ),
            httpx.Response(500, json={"error": "issue with pagination state"}),
            httpx.Response(200, text="ok"),
            httpx.Response(200, json=["nope"]),
            httpx.Response(200, json={"balance": 1}),
        ]
    )

    async def call(client: DehashedClient) -> None:
        with pytest.raises(DehashedAPIError, match="redirect") as redirected:
            await client.search("ada@example.com")
        assert "evil.example" not in str(redirected.value)
        assert LEAK_KEY not in str(redirected.value)
        with pytest.raises(DehashedAPIError, match="pagination state") as transient:
            await client.search("ada@example.com")
        assert transient.value.status_code == 500
        with pytest.raises(DehashedAPIError, match="JSON object"):
            await client.search("ada@example.com")
        with pytest.raises(DehashedAPIError, match="JSON object"):
            await client.search("ada@example.com")
        with pytest.raises(DehashedAPIError, match="documented schema"):
            await client.search("ada@example.com")

    run(call, api_key=LEAK_KEY)

    router.get(DEFAULT_BASE_URL + "/v2/whois/credits").mock(
        side_effect=httpx.ConnectError(f"down {LEAK_KEY}")
    )

    async def offline(client: DehashedClient) -> str:
        with pytest.raises(DehashedAPIError, match="ConnectError") as caught:
            await client.whois_credits()
        return str(caught.value)

    message = run(offline, api_key=LEAK_KEY)
    assert LEAK_KEY not in message
    assert "down" not in message


def test_explicit_false_is_sent_and_the_key_is_redacted(router: Any) -> None:
    _mock(router, "search", status=200, payload=SEARCH_BODY)

    async def call(client: DehashedClient) -> None:
        assert LEAK_KEY not in repr(client)
        assert LEAK_KEY not in str(client)
        secret = client._api_key
        assert secret is not None
        assert format(secret) == "<redacted>"
        await client.search("ada@example.com", wildcard=False, regex=False, de_dupe=False, page=1)

    run(call, api_key=LEAK_KEY)
    sent = json.loads(router.calls[0].request.content)
    assert sent["wildcard"] is False
    assert sent["regex"] is False
    assert sent["de_dupe"] is False
    assert "de_dupe" in sent


def test_rate_limit_waits_before_the_next_call(router: Any) -> None:
    _mock(router, "data_wells", status=200, payload=WELLS_BODY)
    clock = {"t": 0.0}
    sleeps: list[float] = []

    async def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock["t"] += seconds

    async def call(client: DehashedClient) -> None:
        assert client._limiter.limit == 2
        await client.data_wells()
        await client.data_wells()
        await client.data_wells()

    run(call, rate_per_second=2, clock=lambda: clock["t"], sleep=sleep)
    assert sleeps == [1.0]
    assert len(router.calls) == 3
    assert DEFAULT_RATE_PER_SECOND == 20


def test_client_defaults_and_closed(router: Any) -> None:
    async def call() -> None:
        bare = DehashedClient()
        assert bare.base_url == DEFAULT_BASE_URL
        await bare.aclose()
        client = DehashedClient(api_key=API_KEY, timeout=12.5)
        assert client.timeout == 12.5
        assert client._http.follow_redirects is False
        assert client._limiter.limit == DEFAULT_RATE_PER_SECOND
        await client.aclose()
        with pytest.raises(DehashedAPIError, match="closed"):
            await client.user_info()

    asyncio.run(call())
    assert len(router.calls) == 0
    assert DEFAULT_TIMEOUT_SECONDS == 60.0

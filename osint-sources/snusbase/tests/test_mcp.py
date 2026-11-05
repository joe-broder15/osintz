"""MCP tool behavior, mocked. No test in this file opens a socket."""

import ast
import asyncio
import importlib.metadata
import inspect
import json
import logging
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp.server.mcpserver.exceptions import ToolError

from snusbase_client import SnusbaseClient
from snusbase_client.client import DEFAULT_BASE_URL, ENV_API_KEY
from snusbase_client.exceptions import SnusbaseBadRequestError
from snusbase_mcp.lookup import (
    COMBO_QUERY_TYPES,
    HASH_QUERY_TYPES,
    SEARCH_QUERY_TYPES,
    lookup_combo,
    lookup_hash,
    lookup_search,
    lookup_whois,
    parse_typed_queries,
)
from snusbase_mcp.routing import split_whois_terms
from snusbase_mcp.server import build_server, main

API_KEY = "sb" + "0" * 28
LEAK_KEY = "sbLEAK0123456789abcdef01234567"

RATE_HEADERS = {
    "X-Rate-Limit": "256",
    "X-Rate-Limit-Remaining": "255",
    "X-Rate-Limit-Reset": "120",
}


def run[T](body: Callable[[Any], Awaitable[T]]) -> T:
    async def _go() -> T:
        server = build_server()
        lifespan = server.settings.lifespan
        assert lifespan is not None
        async with lifespan(server):
            return await body(server)

    return asyncio.run(_go())


def _mock(
    router: Any,
    path: str,
    *,
    status: int,
    payload: dict[str, Any],
    headers: dict[str, str] | None = None,
) -> None:
    router.post(DEFAULT_BASE_URL + path).mock(
        return_value=httpx.Response(status, json=payload, headers=headers or {})
    )


def _json(result: Any) -> Any:
    assert result.is_error is False
    block = result.content[0]
    assert block.type == "text"
    return json.loads(block.text)


def test_client_sources_do_not_import_mcp() -> None:
    root = Path(__file__).resolve().parents[1] / "src" / "snusbase_client"
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
                assert top not in {"mcp", "snusbase_mcp"}, path


def test_distribution_ships_the_stdio_entry_point() -> None:
    dist = importlib.metadata.metadata("osintz-snusbase-mcp")
    assert dist["Name"] == "osintz-snusbase-mcp"
    assert dist["Version"] == "0.1.0"
    with pytest.raises(importlib.metadata.PackageNotFoundError):
        importlib.metadata.metadata("snusbase-client")
    scripts = {ep.name: ep.value for ep in importlib.metadata.entry_points(group="console_scripts")}
    assert scripts["snusbase-mcp"] == "snusbase_mcp.server:main"
    assert 'transport="stdio"' in inspect.getsource(main)


def test_split_whois_terms_classifies_ip_and_domain() -> None:
    ips, domains = split_whois_terms([" 1.2.3.4 ", "Example.ORG", "2001:db8::1"])
    assert ips == ["1.2.3.4", "2001:db8::1"]
    assert domains == ["Example.ORG"]


def test_split_whois_terms_rejects_blank() -> None:
    with pytest.raises(SnusbaseBadRequestError):
        split_whois_terms([])
    with pytest.raises(SnusbaseBadRequestError):
        split_whois_terms(["example.org", "  "])


def test_split_whois_terms_rejects_over_100_domains() -> None:
    domains = [f"d{i}.example" for i in range(101)]
    with pytest.raises(SnusbaseBadRequestError):
        split_whois_terms(domains)
    with pytest.raises(SnusbaseBadRequestError):
        split_whois_terms([*domains, "1.2.3.4"])


def test_server_exposes_the_four_snusbase_tools() -> None:
    async def body(server: Any) -> None:
        tools = {tool.name: tool for tool in await server.list_tools()}
        assert set(tools) == {
            "snusbase-whois",
            "snusbase-search",
            "snusbase-hash",
            "snusbase-combo",
        }
        search = tools["snusbase-search"].description.lower()
        assert "any query hits" in search
        assert "not a cross product" in search
        assert "untrusted" in search
        assert "password" in search
        assert set(tools["snusbase-search"].input_schema["properties"]) == {"queries"}
        assert set(tools["snusbase-whois"].input_schema["properties"]) == {"terms"}
        hash_text = tools["snusbase-hash"].description.lower()
        assert "plaintext" in hash_text
        assert "matching hashes" in hash_text
        assert "multiple items are or" in hash_text
        combo = tools["snusbase-combo"].description.lower()
        assert "username:password pairs" in combo
        assert "not full breach rows" in combo
        assert "not a pair match" in combo
        assert set(tools["snusbase-hash"].input_schema["properties"]) == {"queries"}
        assert set(tools["snusbase-combo"].input_schema["properties"]) == {"queries"}

    run(body)


def test_retired_tool_names_are_not_registered(router: Any) -> None:
    async def body(server: Any) -> None:
        with pytest.raises(ToolError):
            await server.call_tool("whois", {"terms": ["example.org"]})
        with pytest.raises(ToolError):
            await server.call_tool("search", {"queries": ["email:ada@example.com"]})

    run(body)
    assert len(router.calls) == 0


@pytest.mark.parametrize(
    "queries",
    [
        [],
        ["ada@example.com"],
        [":ada@example.com"],
        ["email:"],
        ["phone:ada@example.com"],
    ],
)
def test_bad_search_queries_do_not_send(router: Any, queries: list[str]) -> None:
    async def body(server: Any) -> None:
        with pytest.raises(ToolError):
            await server.call_tool("snusbase-search", {"queries": queries})

    run(body)
    assert len(router.calls) == 0


def test_lookup_runs_without_starting_the_server(
    router: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ENV_API_KEY, API_KEY)
    _mock(
        router,
        "/data/search",
        status=200,
        payload={
            "took": 1.5,
            "size": 1,
            "results": {"T": [{"email": "ada@example.com"}]},
        },
        headers=RATE_HEADERS,
    )
    _mock(
        router,
        "/tools/domain-whois",
        status=200,
        payload={"took": 1, "size": 1, "results": {"example.org": {"tld": "org"}}},
        headers=RATE_HEADERS,
    )

    async def go() -> tuple[dict[str, Any], dict[str, Any]]:
        async with SnusbaseClient() as client:
            found = await lookup_search(client, ["email:ada@example.com"])
            who = await lookup_whois(client, ["example.org"])
        return found, who

    found, who = asyncio.run(go())
    assert found["results"]["T"][0]["email"] == "ada@example.com"
    assert set(who) == {"domain"}
    assert json.loads(router.calls[0].request.content) == {
        "terms": ["ada@example.com"],
        "types": ["email"],
    }
    assert json.loads(router.calls[1].request.content) == {"terms": ["example.org"]}


def test_mixed_whois_routes_and_omits_group_by(
    router: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ENV_API_KEY, API_KEY)
    _mock(
        router,
        "/tools/ip-whois",
        status=200,
        payload={
            "took": 1,
            "size": 1,
            "results": {"1.2.3.4": {"query": "1.2.3.4", "country": "US"}},
        },
        headers=RATE_HEADERS,
    )
    _mock(
        router,
        "/tools/domain-whois",
        status=200,
        payload={
            "took": 2,
            "size": 1,
            "results": {"example.org": {"domain": "example.org"}},
            "errors": ["missing.test: Likely not registered"],
        },
        headers={
            "X-Rate-Limit": "256",
            "X-Rate-Limit-Remaining": "254",
            "X-Rate-Limit-Reset": "90",
        },
    )

    async def body(server: Any) -> Any:
        return await server.call_tool("snusbase-whois", {"terms": [" 1.2.3.4 ", "example.org"]})

    payload = _json(run(body))
    assert [call.request.url.path for call in router.calls] == [
        "/tools/ip-whois",
        "/tools/domain-whois",
    ]
    assert json.loads(router.calls[0].request.content) == {"terms": ["1.2.3.4"]}
    assert json.loads(router.calls[1].request.content) == {"terms": ["example.org"]}
    assert payload["ip"]["results"]["1.2.3.4"]["country"] == "US"
    assert payload["ip"]["rate_limit"]["remaining"] == 255
    assert "errors" not in payload["ip"]
    assert payload["domain"]["errors"] == ["missing.test: Likely not registered"]
    assert payload["domain"]["rate_limit"]["reset_seconds"] == 90
    assert set(payload) == {"ip", "domain"}


def test_domain_only_whois_makes_one_call(router: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_API_KEY, API_KEY)
    _mock(
        router,
        "/tools/domain-whois",
        status=200,
        payload={"took": 1, "size": 1, "results": {"example.org": {"tld": "org"}}},
        headers=RATE_HEADERS,
    )

    async def body(server: Any) -> Any:
        return await server.call_tool("snusbase-whois", {"terms": ["example.org"]})

    payload = _json(run(body))
    assert len(router.calls) == 1
    assert router.calls[0].request.url.path == "/tools/domain-whois"
    assert set(payload) == {"domain"}
    assert "errors" not in payload["domain"]


def test_whois_over_limit_does_not_send(router: Any) -> None:
    terms = [f"d{i}.example" for i in range(101)]

    async def body(server: Any) -> None:
        with pytest.raises(ToolError):
            await server.call_tool("snusbase-whois", {"terms": [*terms, "8.8.8.8"]})

    run(body)
    assert len(router.calls) == 0


def test_parse_typed_queries_splits_on_the_first_colon() -> None:
    assert parse_typed_queries(["email:a:b@example.com"], SEARCH_QUERY_TYPES) == [
        ("email", ["a:b@example.com"])
    ]
    assert parse_typed_queries(
        ["username:ada", "email:a@example.com", "username:bob"],
        SEARCH_QUERY_TYPES,
    ) == [("username", ["ada", "bob"]), ("email", ["a@example.com"])]
    assert HASH_QUERY_TYPES == frozenset({"hash", "password"})
    assert COMBO_QUERY_TYPES == frozenset({"username", "password"})


def test_search_groups_by_type_and_merges(
    router: Any, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    monkeypatch.setenv(ENV_API_KEY, API_KEY)
    password = "hunter2-leak"
    _method, url = _url_path("/data/search")
    router.post(url).mock(
        side_effect=[
            httpx.Response(
                200,
                json={
                    "took": 1.5,
                    "size": 1,
                    "results": {"T": [{"email": "ada@example.com", "password": password}]},
                },
                headers={
                    "X-Rate-Limit": "2048",
                    "X-Rate-Limit-Remaining": "2047",
                    "X-Rate-Limit-Reset": "100",
                },
            ),
            httpx.Response(
                200,
                json={
                    "took": 0.5,
                    "size": 2,
                    "results": {
                        "T": [{"username": "ada"}],
                        "U": [{"username": "other"}],
                    },
                },
                headers={
                    "X-Rate-Limit": "2048",
                    "X-Rate-Limit-Remaining": "2046",
                    "X-Rate-Limit-Reset": "90",
                },
            ),
        ]
    )

    async def body(server: Any) -> Any:
        return await server.call_tool(
            "snusbase-search",
            {"queries": ["email:a:b@example.com", "username:ada", "email:zoe@example.com"]},
        )

    payload = _json(run(body))
    assert [json.loads(call.request.content) for call in router.calls] == [
        {"terms": ["a:b@example.com", "zoe@example.com"], "types": ["email"]},
        {"terms": ["ada"], "types": ["username"]},
    ]
    assert payload["took"] == 2.0
    assert payload["size"] == 3
    assert payload["results"]["T"] == [
        {"email": "ada@example.com", "password": password},
        {"username": "ada"},
    ]
    assert payload["results"]["U"] == [{"username": "other"}]
    assert payload["rate_limit"]["remaining"] == 2046
    assert "group_by" not in json.loads(router.calls[0].request.content)
    assert "wildcard" not in json.loads(router.calls[0].request.content)
    assert "tables" not in json.loads(router.calls[0].request.content)
    assert password not in caplog.text


def _url_path(path: str) -> tuple[str, str]:
    return "POST", DEFAULT_BASE_URL + path


def test_rate_limit_surfaces_reset_seconds(router: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_API_KEY, API_KEY)
    _mock(
        router,
        "/data/search",
        status=429,
        payload={"errors": ["slow down"]},
        headers={
            "X-Rate-Limit": "2048",
            "X-Rate-Limit-Remaining": "0",
            "X-Rate-Limit-Reset": "3600",
        },
    )

    async def body(server: Any) -> None:
        with pytest.raises(ToolError, match=r"reset_seconds=3600") as caught:
            await server.call_tool(
                "snusbase-search",
                {"queries": ["email:ada@example.com"]},
            )
        assert "slow down" in str(caught.value)
        assert API_KEY not in str(caught.value)

    run(body)


def test_missing_key_does_not_send(router: Any, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)

    async def body(server: Any) -> None:
        with pytest.raises(ToolError, match="SNUSBASE_API_KEY") as caught:
            await server.call_tool(
                "snusbase-search",
                {"queries": ["email:ada@example.com"]},
            )
        assert LEAK_KEY not in str(caught.value)

    run(body)
    assert len(router.calls) == 0


def test_auth_failure_names_env_and_hides_key(
    router: Any, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    monkeypatch.setenv(ENV_API_KEY, LEAK_KEY)
    _mock(
        router,
        "/data/search",
        status=401,
        payload={"errors": ["invalid api key"]},
        headers=RATE_HEADERS,
    )

    async def body(server: Any) -> None:
        with pytest.raises(ToolError, match="SNUSBASE_API_KEY") as caught:
            await server.call_tool(
                "snusbase-search",
                {"queries": ["email:ada@example.com"]},
            )
        assert LEAK_KEY not in str(caught.value)

    run(body)
    assert LEAK_KEY not in caplog.text


def test_later_search_group_failure_drops_earlier_results(
    router: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ENV_API_KEY, API_KEY)
    _method, url = _url_path("/data/search")
    router.post(url).mock(
        side_effect=[
            httpx.Response(
                200,
                json={"took": 1, "size": 1, "results": {"T": [{"email": "ada@example.com"}]}},
                headers=RATE_HEADERS,
            ),
            httpx.Response(
                429,
                json={"errors": ["slow down"]},
                headers={"X-Rate-Limit-Reset": "10"},
            ),
        ]
    )

    async def body(server: Any) -> None:
        with pytest.raises(ToolError, match="slow down") as caught:
            await server.call_tool(
                "snusbase-search",
                {"queries": ["email:ada@example.com", "username:ada"]},
            )
        assert "ada@example.com" not in str(caught.value)

    run(body)
    assert len(router.calls) == 2


@pytest.mark.parametrize(
    ("tool", "path", "queries", "body"),
    [
        (
            "snusbase-hash",
            "/tools/hash-lookup",
            ["hash:abc", "password:secret", "hash:def"],
            [
                {"terms": ["abc", "def"], "types": ["hash"]},
                {"terms": ["secret"], "types": ["password"]},
            ],
        ),
        (
            "snusbase-combo",
            "/tools/combo-lookup",
            ["password:secret", "username:ada"],
            [
                {"terms": ["secret"], "types": ["password"]},
                {"terms": ["ada"], "types": ["username"]},
            ],
        ),
    ],
)
def test_hash_and_combo_group_by_type(
    router: Any,
    monkeypatch: pytest.MonkeyPatch,
    tool: str,
    path: str,
    queries: list[str],
    body: list[dict[str, Any]],
) -> None:
    monkeypatch.setenv(ENV_API_KEY, API_KEY)
    _method, url = _url_path(path)
    router.post(url).mock(
        side_effect=[
            httpx.Response(
                200,
                json={"took": 1, "size": 1, "results": {"A": [{"password": "one"}]}},
                headers={"X-Rate-Limit-Remaining": "9", "X-Rate-Limit-Reset": "1"},
            ),
            httpx.Response(
                200,
                json={"took": 2, "size": 1, "results": {"A": [{"password": "two"}]}},
                headers={"X-Rate-Limit-Remaining": "8", "X-Rate-Limit-Reset": "1"},
            ),
        ]
    )

    async def call(server: Any) -> Any:
        return await server.call_tool(tool, {"queries": queries})

    payload = _json(run(call))
    assert [json.loads(call_item.request.content) for call_item in router.calls] == body
    assert payload["size"] == 2
    assert payload["took"] == 3
    assert payload["results"]["A"] == [{"password": "one"}, {"password": "two"}]
    assert payload["rate_limit"]["remaining"] == 8
    assert "wildcard" not in json.loads(router.calls[0].request.content)
    assert "group_by" not in json.loads(router.calls[0].request.content)


def test_hash_and_combo_reject_the_other_types(router: Any) -> None:
    async def body(server: Any) -> None:
        with pytest.raises(ToolError):
            await server.call_tool("snusbase-hash", {"queries": ["email:ada@example.com"]})
        with pytest.raises(ToolError):
            await server.call_tool("snusbase-combo", {"queries": ["hash:abc"]})

    run(body)
    assert len(router.calls) == 0


def test_hash_and_combo_run_without_the_server(
    router: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ENV_API_KEY, API_KEY)
    _mock(
        router,
        "/tools/hash-lookup",
        status=200,
        payload={"took": 1, "size": 1, "results": {"H": [{"hash": "abc"}]}},
        headers=RATE_HEADERS,
    )
    _mock(
        router,
        "/tools/combo-lookup",
        status=200,
        payload={"took": 1, "size": 1, "results": {"C": [{"username": "ada"}]}},
        headers=RATE_HEADERS,
    )

    async def go() -> tuple[dict[str, Any], dict[str, Any]]:
        async with SnusbaseClient() as client:
            hashed = await lookup_hash(client, ["hash:abc"])
            combo = await lookup_combo(client, ["username:ada"])
        return hashed, combo

    hashed, combo = asyncio.run(go())
    assert hashed["results"]["H"][0]["hash"] == "abc"
    assert combo["results"]["C"][0]["username"] == "ada"

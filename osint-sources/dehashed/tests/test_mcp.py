"""MCP tool behavior, mocked. No test in this file opens a socket."""

import ast
import asyncio
import hashlib
import importlib.metadata
import inspect
import json
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp.server.mcpserver.exceptions import ToolError

from dehashed_client import DehashedClient
from dehashed_client.client import AUTH_HEADER, DEFAULT_BASE_URL, ENV_API_KEY
from dehashed_mcp.lookup import lookup_search
from dehashed_mcp.server import build_server, main

API_KEY = "test-key-not-a-secret"
PASSWORD = "HorseBattery!"

TOOL_NAMES = {
    "dehashed-search",
    "dehashed-search-password",
    "dehashed-data-wells",
    "dehashed-whois",
    "dehashed-reverse-whois",
    "dehashed-subdomain-scan",
}

SEARCH_BODY = {
    "balance": 60,
    "entries": [{"id": "1", "email": ["ada@example.com"], "password": ["secret"]}],
    "took": "179µs",
    "total": 1,
}


def run[T](body: Callable[[Any], Awaitable[T]]) -> T:
    async def _go() -> T:
        server = build_server()
        lifespan = server.settings.lifespan
        assert lifespan is not None
        async with lifespan(server):
            return await body(server)

    return asyncio.run(_go())


def _json(result: Any) -> Any:
    assert result.is_error is False
    block = result.content[0]
    assert block.type == "text"
    return json.loads(block.text)


def test_mcp_sources_do_not_import_snusbase() -> None:
    root = Path(__file__).resolve().parents[1] / "src" / "dehashed_mcp"
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
            for module in modules:
                assert not module.startswith("snusbase")


def test_distribution_ships_the_stdio_entry_point() -> None:
    dist = importlib.metadata.metadata("osintz-dehashed-mcp")
    assert dist["Name"] == "osintz-dehashed-mcp"
    assert dist["Version"] == "0.1.0"
    scripts = {ep.name: ep.value for ep in importlib.metadata.entry_points(group="console_scripts")}
    assert scripts["dehashed-mcp"] == "dehashed_mcp.server:main"
    source = inspect.getsource(main)
    assert 'transport="stdio"' in source
    assert "streamable-http" not in source
    pyproject = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()
    assert "snusbase" not in pyproject
    server_source = (
        Path(__file__).resolve().parents[1] / "src" / "dehashed_mcp" / "server.py"
    ).read_text()
    assert "streamable-http" not in server_source
    assert "DEHASHED_MCP_HOST" not in server_source


def test_main_is_stdio_only(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_run(self: Any, transport: str = "stdio", **kwargs: Any) -> None:
        seen["transport"] = transport
        seen["kwargs"] = kwargs

    monkeypatch.setattr("dehashed_mcp.server.MCPServer.run", fake_run)
    main()
    assert seen == {"transport": "stdio", "kwargs": {}}


def test_server_exposes_the_dehashed_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_API_KEY, API_KEY)

    async def body(server: Any) -> None:
        tools = {tool.name: tool for tool in await server.list_tools()}
        assert set(tools) == TOOL_NAMES
        search = tools["dehashed-search"].description.lower()
        assert "untrusted" in search
        assert "password" in search
        assert "read-only" in search
        assert "through_page" not in search
        assert "10000" in search or "10,000" in search
        password = tools["dehashed-search-password"].description.lower()
        assert "sha-256" in password
        assert "plaintext" in password
        assert "sha256" in password
        props = tools["dehashed-search-password"].input_schema["properties"]
        assert set(props) == {"password", "input_kind"}
        assert props["input_kind"]["default"] == "password"
        wells = tools["dehashed-data-wells"].description.lower()
        assert "no api key" in wells
        assert set(tools["dehashed-search"].input_schema["properties"]) == {
            "query",
            "page",
            "size",
            "wildcard",
            "regex",
            "de_dupe",
        }
        assert "password" in tools["dehashed-search-password"].input_schema["properties"]
        assert "api_key" not in tools["dehashed-search"].input_schema["properties"]

    run(body)


def test_bare_tool_names_are_not_registered(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_API_KEY, API_KEY)

    async def body(server: Any) -> None:
        with pytest.raises(ToolError):
            await server.call_tool("search", {"query": "ada@example.com"})

    run(body)


def test_search_tool_returns_rows_and_maps_errors(
    router: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ENV_API_KEY, API_KEY)
    router.post(DEFAULT_BASE_URL + "/v2/search").mock(
        side_effect=[
            httpx.Response(200, json=SEARCH_BODY),
            httpx.Response(400, json={"error": "issue with authentication"}),
            httpx.Response(
                401,
                json={
                    "error": (
                        "You need a search subscription and API credits to use the API, "
                        "please purchase a search subscription."
                    )
                },
            ),
            httpx.Response(403, json={"error": "Insufficient Credits"}),
            httpx.Response(429, json={"error": "too many requests"}),
        ]
    )

    async def body(server: Any) -> None:
        found = _json(await server.call_tool("dehashed-search", {"query": "ada@example.com"}))
        assert found["total"] == 1
        assert found["entries"][0]["password"] == ["secret"]
        assert "ip_address" not in found["entries"][0]
        with pytest.raises(ToolError, match="DEHASHED_API_KEY"):
            await server.call_tool("dehashed-search", {"query": "ada@example.com"})
        with pytest.raises(ToolError, match="search subscription") as subscription:
            await server.call_tool("dehashed-search", {"query": "ada@example.com"})
        assert "Set DEHASHED_API_KEY" not in str(subscription.value)
        with pytest.raises(ToolError, match="Insufficient Credits"):
            await server.call_tool("dehashed-search", {"query": "ada@example.com"})
        with pytest.raises(ToolError, match="20 requests per second"):
            await server.call_tool("dehashed-search", {"query": "ada@example.com"})

    run(body)
    assert router.calls[0].request.headers[AUTH_HEADER] == API_KEY


def test_password_tool_hashes_plaintext_and_passes_a_digest(
    router: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ENV_API_KEY, API_KEY)
    supplied = "CD" * 32
    router.post(DEFAULT_BASE_URL + "/v2/search-password").mock(
        return_value=httpx.Response(200, json={"results_found": 2})
    )

    async def body(server: Any) -> None:
        found = _json(await server.call_tool("dehashed-search-password", {"password": PASSWORD}))
        assert found == {"results_found": 2}
        hashed = _json(
            await server.call_tool(
                "dehashed-search-password",
                {"password": supplied, "input_kind": "sha256"},
            )
        )
        assert hashed == {"results_found": 2}
        with pytest.raises(ToolError, match="64 hexadecimal"):
            await server.call_tool(
                "dehashed-search-password",
                {"password": "not-a-hash", "input_kind": "sha256"},
            )

    run(body)
    first = router.calls[0].request.content.decode()
    second = router.calls[1].request.content.decode()
    assert PASSWORD not in first
    assert hashlib.sha256(PASSWORD.encode()).hexdigest() in first
    assert json.loads(second) == {"sha256_hashed_password": supplied.lower()}
    assert supplied not in second
    assert len(router.calls) == 2


def test_data_wells_tool_works_without_a_key(router: Any) -> None:
    router.get(DEFAULT_BASE_URL + "/data-wells").mock(
        return_value=httpx.Response(
            200,
            json={
                "next_page": False,
                "total": 0,
                "data_wells": [],
            },
        )
    )

    async def body(server: Any) -> None:
        found = _json(await server.call_tool("dehashed-data-wells", {"sort": "name-ASC"}))
        assert found["total"] == 0

    run(body)
    request = router.calls[0].request
    assert request.headers.get(AUTH_HEADER) is None
    assert request.url.params["sort"] == "name-ASC"


def test_pagination_is_one_page(router: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_API_KEY, API_KEY)
    router.post(DEFAULT_BASE_URL + "/v2/search").mock(
        return_value=httpx.Response(200, json=SEARCH_BODY)
    )

    async def body(server: Any) -> None:
        with pytest.raises(ToolError, match="size must be between 1 and 10000"):
            await server.call_tool("dehashed-search", {"query": "ada@example.com", "size": 0})
        found = _json(
            await server.call_tool(
                "dehashed-search",
                {"query": "ada@example.com", "page": 2, "size": 10000},
            )
        )
        assert found["total"] == 1

    run(body)
    assert len(router.calls) == 1
    assert json.loads(router.calls[0].request.content)["page"] == 2


def test_lookup_runs_without_starting_the_server(
    router: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ENV_API_KEY, API_KEY)
    router.post(DEFAULT_BASE_URL + "/v2/search").mock(
        return_value=httpx.Response(200, json=SEARCH_BODY)
    )

    async def call() -> dict[str, Any]:
        async with DehashedClient() as client:
            return await lookup_search(client, "ada@example.com", page=2, size=100)

    found = asyncio.run(call())
    assert found["balance"] == 60
    assert json.loads(router.calls[0].request.content) == {
        "query": "ada@example.com",
        "page": 2,
        "size": 100,
    }


def test_missing_key_tool_error_names_the_env_var(router: Any) -> None:
    async def body(server: Any) -> None:
        with pytest.raises(ToolError, match="DEHASHED_API_KEY") as caught:
            await server.call_tool("dehashed-whois", {"domain": "example.com"})
        assert API_KEY not in str(caught.value)

    run(body)
    assert len(router.calls) == 0

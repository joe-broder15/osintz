"""Async client for the documented DeHashed API.

The key is taken from the ``api_key`` argument or, if that argument is omitted,
from ``DEHASHED_API_KEY``. It is sent as ``DeHashed-Api-Key``. It is never a
tool argument and never written to a log line by this package. ``repr`` and
``str`` redact it.

``GET /data-wells`` is the only call that does not send the key. The header is
omitted even when a key is configured, because the docs say that call needs
no key and no subscription.

Every path in ``OPERATIONS`` is written in full in the export. Monitoring URLs
are truncated there, so this client does not call them.
"""

import asyncio
import hashlib
import re
import time
from collections import deque
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from os import environ
from typing import Any

import httpx
from pydantic import BaseModel, ValidationError

from dehashed_client.exceptions import (
    DehashedAPIError,
    DehashedAuthError,
    DehashedBadRequestError,
    DehashedError,
    DehashedForbiddenError,
    DehashedRateLimitError,
    DehashedSubscriptionError,
)
from dehashed_client.models import (
    DataWellsQuery,
    DataWellsResponse,
    PasswordSearchRequest,
    PasswordSearchResponse,
    ReverseWhoisRequest,
    SearchRequest,
    SearchResponse,
    WhoisDomainRequest,
    WhoisSearchResponse,
)

DEFAULT_BASE_URL = "https://api.dehashed.com"
DEFAULT_TIMEOUT_SECONDS = 60.0
DEFAULT_RATE_PER_SECOND = 20
ENV_API_KEY = "DEHASHED_API_KEY"
AUTH_HEADER = "DeHashed-Api-Key"

PATH_SEARCH = "/v2/search"
PATH_SEARCH_PASSWORD = "/v2/search-password"
PATH_DATA_WELLS = "/data-wells"
PATH_WHOIS_SEARCH = "/v2/whois/search"

# Public client method name -> (HTTP method, path, send the API key).
# Each path is complete in the export. Truncated monitoring URLs are not here.
OPERATIONS: dict[str, tuple[str, str, bool]] = {
    "search": ("POST", PATH_SEARCH, True),
    "search_password": ("POST", PATH_SEARCH_PASSWORD, True),
    "data_wells": ("GET", PATH_DATA_WELLS, False),
    "whois": ("POST", PATH_WHOIS_SEARCH, True),
    "reverse_whois": ("POST", PATH_WHOIS_SEARCH, True),
    "subdomain_scan": ("POST", PATH_WHOIS_SEARCH, True),
}


class _Secret:
    """Holds the API key. ``str`` and ``repr`` never reveal it."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def __repr__(self) -> str:
        return "_Secret(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"

    def __format__(self, format_spec: str) -> str:
        return "<redacted>"

    def reveal(self) -> str:
        return self._value


@dataclass(frozen=True, slots=True)
class DehashedResponse[T: BaseModel]:
    """Parsed body from one response. Rate-limit headers are not documented."""

    data: T
    status_code: int


class _SlidingWindow:
    """At most ``limit`` acquisitions in any ``window_seconds`` interval.

    The docs allow 20 requests per second from one IP and one API credential.
    The 21st call waits. This does not retry an HTTP 429.
    """

    def __init__(
        self,
        *,
        limit: int,
        window_seconds: float = 1.0,
        clock: Callable[[], float] | None = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        if limit < 1:
            raise ValueError("rate limit must be at least 1 request per second")
        self.limit = limit
        self.window_seconds = window_seconds
        self._clock = clock or time.monotonic
        self._sleep = sleep or asyncio.sleep
        self._hits: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                now = self._clock()
                cutoff = now - self.window_seconds
                while self._hits and self._hits[0] <= cutoff:
                    self._hits.popleft()
                if len(self._hits) < self.limit:
                    self._hits.append(now)
                    return
                wait = self.window_seconds - (now - self._hits[0])
            await self._sleep(wait if wait > 0 else 0.0)


_SHA256_HEX = re.compile(r"^[0-9a-fA-F]{64}$")


def hash_password(password: str) -> str:
    """Lowercase SHA-256 hex digest of the UTF-8 password.

    The sample function returns ``str`` and is cut off at ``encode('u``. UTF-8
    and hex are the assumption that produces a string digest. The plaintext is
    not returned.
    """
    if password == "":
        raise DehashedBadRequestError("Password is empty.")
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def password_search_digest(value: str, input_kind: str = "password") -> str:
    """Digest for ``POST /v2/search-password``.

    ``password`` hashes locally. ``sha256`` must already be 64 hex characters
    and is lowercased, not hashed again. The published samples use a string
    digest, so the wire value is lowercase hex.
    """
    if input_kind == "password":
        return hash_password(value)
    if input_kind == "sha256":
        if _SHA256_HEX.fullmatch(value) is None:
            raise DehashedBadRequestError("sha256 input must be 64 hexadecimal characters.")
        return value.lower()
    raise DehashedBadRequestError("input_kind must be password or sha256.")


def _resolve_api_key(api_key: str | None) -> str | None:
    if api_key is not None:
        if not api_key.strip():
            raise DehashedAuthError("API key is empty.")
        return api_key
    env = environ.get(ENV_API_KEY)
    if env is None or not env.strip():
        return None
    return env


def _validation_messages(exc: ValidationError) -> list[str]:
    messages: list[str] = []
    for err in exc.errors():
        loc = ".".join(str(part) for part in err.get("loc", ()))
        msg = str(err.get("msg", "invalid value"))
        text = msg.removeprefix("Value error, ")
        messages.append(f"{loc}: {text}" if loc else text)
    return messages


def validated_body(model: type[BaseModel], /, **data: Any) -> dict[str, Any]:
    """Validate a request and drop fields that are ``None``."""
    try:
        parsed = model.model_validate(data)
    except ValidationError as exc:
        messages = _validation_messages(exc)
        message = (
            "; ".join(messages) if messages else "Request does not match the documented parameters."
        )
        raise DehashedBadRequestError(message) from None
    return parsed.model_dump(mode="json", exclude_none=True)


def _error_text(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return f"HTTP {response.status_code}"
    if isinstance(payload, dict):
        raw = payload.get("error")
        if isinstance(raw, str) and raw:
            return raw
        if raw is not None:
            return str(raw)
    return f"HTTP {response.status_code}"


def _error_from_response(response: httpx.Response) -> DehashedError:
    message = _error_text(response)
    status = response.status_code
    if status == 400:
        return DehashedBadRequestError(message, status_code=status)
    if status == 401:
        if message == "HTTP 401":
            message = (
                "You need a search subscription and API credits to use the API, "
                "please purchase a search subscription."
            )
        return DehashedSubscriptionError(message, status_code=status)
    if status == 403:
        if message == "HTTP 403":
            message = "Insufficient Credits"
        return DehashedForbiddenError(message, status_code=status)
    if status == 429:
        if message == "HTTP 429":
            message = "too many requests"
        return DehashedRateLimitError(
            f"{message} The documented limit is 20 requests per second.",
            status_code=status,
        )
    return DehashedAPIError(message, status_code=status)


def _parse_response[T: BaseModel](response: httpx.Response, model: type[T]) -> DehashedResponse[T]:
    if not response.is_success:
        if 300 <= response.status_code < 400:
            raise DehashedAPIError(
                f"Unexpected redirect (HTTP {response.status_code}). Redirects are not followed.",
                status_code=response.status_code,
            )
        raise _error_from_response(response)
    try:
        payload = response.json()
    except ValueError:
        raise DehashedAPIError(
            f"Expected a JSON object (HTTP {response.status_code}).",
            status_code=response.status_code,
        ) from None
    if not isinstance(payload, dict):
        raise DehashedAPIError(
            f"Expected a JSON object (HTTP {response.status_code}).",
            status_code=response.status_code,
        )
    try:
        data = model.model_validate(payload)
    except ValidationError as exc:
        messages = _validation_messages(exc)
        detail = "; ".join(messages) if messages else "response did not match"
        raise DehashedAPIError(
            f"Response did not match the documented schema (HTTP {response.status_code}): {detail}",
            status_code=response.status_code,
        ) from None
    return DehashedResponse(data=data, status_code=response.status_code)


def _check_base_url(base_url: str) -> str:
    if not isinstance(base_url, str) or not base_url.strip():
        raise ValueError("base_url must be a non-empty string")
    return base_url.rstrip("/")


def _redact(message: str, secret: str) -> str:
    if len(secret) < 4 or secret not in message:
        return message
    return message.replace(secret, "<redacted>")


class DehashedClient:
    """Asynchronous client. Use ``async with`` so the connection pool closes.

    ``timeout`` is forwarded to httpx. Redirects are not followed. Calls share
    one 20-request-per-second window. ``clock`` and ``sleep`` exist so tests
    can move that window without waiting.
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float | httpx.Timeout = DEFAULT_TIMEOUT_SECONDS,
        rate_per_second: int = DEFAULT_RATE_PER_SECOND,
        clock: Callable[[], float] | None = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        self.base_url = _check_base_url(base_url)
        self.timeout = timeout
        resolved = _resolve_api_key(api_key)
        self._api_key = _Secret(resolved) if resolved is not None else None
        self._limiter = _SlidingWindow(limit=rate_per_second, clock=clock, sleep=sleep)
        self._http = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout,
            follow_redirects=False,
        )

    def __repr__(self) -> str:
        key_set = self._api_key is not None
        return (
            f"{type(self).__name__}(base_url={self.base_url!r}, "
            f"timeout={self.timeout!r}, api_key_set={key_set})"
        )

    def __str__(self) -> str:
        return repr(self)

    async def __aenter__(self) -> "DehashedClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._http.aclose()

    async def search(
        self,
        query: str,
        *,
        page: int | None = None,
        size: int | None = None,
        wildcard: bool | None = None,
        regex: bool | None = None,
        de_dupe: bool | None = None,
    ) -> DehashedResponse[SearchResponse]:
        """``POST /v2/search``. One page. Deep pages are sent as the caller asked."""
        return await self._json(
            "search",
            SearchResponse,
            SearchRequest,
            query=query,
            page=page,
            size=size,
            wildcard=wildcard,
            regex=regex,
            de_dupe=de_dupe,
        )

    async def search_password(
        self,
        password: str,
        *,
        input_kind: str = "password",
    ) -> DehashedResponse[PasswordSearchResponse]:
        """``POST /v2/search-password``. Sends a SHA-256 hex digest, never plaintext.

        ``input_kind="password"`` hashes locally. ``input_kind="sha256"`` sends
        that digest after lowercasing it.
        """
        digest = password_search_digest(password, input_kind)
        try:
            return await self._json(
                "search_password",
                PasswordSearchResponse,
                PasswordSearchRequest,
                sha256_hashed_password=digest,
            )
        except DehashedError as exc:
            if input_kind != "password":
                raise
            redacted = _redact(exc.message, password)
            if redacted == exc.message:
                raise
            raise type(exc)(redacted, status_code=exc.status_code) from None

    async def data_wells(
        self,
        *,
        count: int | None = None,
        page: int | None = None,
        sort: str | None = None,
    ) -> DehashedResponse[DataWellsResponse]:
        """``GET /data-wells``. No API key is sent."""
        query = validated_body(DataWellsQuery, count=count, page=page, sort=sort)
        return await self._invoke("data_wells", DataWellsResponse, query=query or None)

    async def whois(self, domain: str) -> DehashedResponse[WhoisSearchResponse]:
        """WHOIS search. ``search_type`` is ``whois``."""
        return await self._whois("whois", "whois", domain)

    async def reverse_whois(
        self,
        *,
        include: list[str] | None = None,
        exclude: list[str] | None = None,
        reverse_type: str | None = None,
    ) -> DehashedResponse[WhoisSearchResponse]:
        """Reverse WHOIS. ``search_type`` is ``reverse-whois``."""
        return await self._json(
            "reverse_whois",
            WhoisSearchResponse,
            ReverseWhoisRequest,
            search_type="reverse-whois",
            include=include,
            exclude=exclude,
            reverse_type=reverse_type,
        )

    async def subdomain_scan(self, domain: str) -> DehashedResponse[WhoisSearchResponse]:
        """Subdomain scan. ``search_type`` is ``subdomain-scan``."""
        return await self._whois("subdomain_scan", "subdomain-scan", domain)

    async def _whois(
        self,
        operation: str,
        search_type: str,
        domain: str,
    ) -> DehashedResponse[WhoisSearchResponse]:
        return await self._json(
            operation,
            WhoisSearchResponse,
            WhoisDomainRequest,
            search_type=search_type,
            domain=domain,
        )

    async def _json[T: BaseModel](
        self,
        operation: str,
        model: type[T],
        body_model: type[BaseModel] | None = None,
        *,
        body: Mapping[str, Any] | None = None,
        **data: Any,
    ) -> DehashedResponse[T]:
        if body_model is None:
            json_body: dict[str, Any] = {} if body is None else dict(body)
        else:
            json_body = validated_body(body_model, **data)
        return await self._invoke(operation, model, json_body=json_body)

    async def _invoke[T: BaseModel](
        self,
        operation: str,
        model: type[T],
        *,
        json_body: dict[str, Any] | None = None,
        query: dict[str, Any] | None = None,
    ) -> DehashedResponse[T]:
        method, path, authenticated = OPERATIONS[operation]
        if self._http.is_closed:
            raise DehashedAPIError("Client is closed.")
        headers: dict[str, str] = {}
        if authenticated:
            if self._api_key is None:
                raise DehashedAuthError(
                    "An API key is required for this endpoint. "
                    f"Pass api_key or set the {ENV_API_KEY} environment variable."
                )
            headers[AUTH_HEADER] = self._api_key.reveal()
        kwargs: dict[str, Any] = {}
        if json_body is not None:
            headers["Content-Type"] = "application/json"
            kwargs["json"] = json_body
        if query:
            kwargs["params"] = query
        if headers:
            kwargs["headers"] = headers
        await self._limiter.acquire()
        try:
            response = await self._http.request(method, path, **kwargs)
        except httpx.RequestError as exc:
            raise DehashedAPIError(f"Request to {path} failed ({type(exc).__name__}).") from None
        try:
            return _parse_response(response, model)
        except DehashedError as exc:
            secret = self._api_key.reveal() if self._api_key is not None else None
            if secret is None:
                raise
            redacted = _redact(exc.message, secret)
            if redacted == exc.message:
                raise
            raise type(exc)(redacted, status_code=exc.status_code) from None

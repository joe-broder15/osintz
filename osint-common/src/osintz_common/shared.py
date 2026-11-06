"""The duplicated helpers, and nothing else."""


class Secret:
    """Holds an API key. ``str``, ``repr``, and ``format`` never reveal it."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def __repr__(self) -> str:
        return "Secret(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"

    def __format__(self, format_spec: str) -> str:
        return "<redacted>"

    def reveal(self) -> str:
        return self._value


class ClientError(Exception):
    """Message plus optional HTTP status. Sources add their own subclasses."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code

    def __repr__(self) -> str:
        return f"{type(self).__name__}(status_code={self.status_code!r})"


def check_base_url(base_url: str) -> str:
    """Reject a blank base URL and drop a trailing slash."""
    if not isinstance(base_url, str) or not base_url.strip():
        raise ValueError("base_url must be a non-empty string")
    return base_url.rstrip("/")


def redirect_not_followed(status_code: int) -> str:
    """Text for a 3xx that was not followed. Does not include ``Location``."""
    return f"Unexpected redirect (HTTP {status_code}). Redirects are not followed."


def client_repr(kind: str, base_url: str, timeout: object, *, api_key_set: bool) -> str:
    """``repr`` shared by the source clients. The key itself is not included."""
    return f"{kind}(base_url={base_url!r}, timeout={timeout!r}, api_key_set={api_key_set})"


def name_env(message: str, env_name: str, *, verb: str = "Set") -> str:
    """Name the env var on a tool error when the message does not already.

    The key is never added. ``verb`` is ``Set`` or ``Check`` so the existing
    sentences stay the same.
    """
    if env_name in message:
        return message
    return f"{message} {verb} {env_name}."

"""HTTP client for the documented Snusbase API.

Used by ``snusbase_mcp``. This package does not import the MCP stack, so these
calls can run without starting a server. It ships inside the
``osintz-snusbase-mcp`` distribution; it is not its own distribution.
"""

from snusbase_client.client import (
    DEFAULT_BASE_URL,
    DEFAULT_TIMEOUT_SECONDS,
    ENV_API_KEY,
    SnusbaseClient,
    SnusbaseResponse,
    parse_rate_limit,
)
from snusbase_client.exceptions import (
    SnusbaseAPIError,
    SnusbaseAuthError,
    SnusbaseBadRequestError,
    SnusbaseError,
    SnusbaseRateLimitError,
)
from snusbase_client.models import (
    ComboLookupResponse,
    ComboLookupType,
    ComboLookupTypeName,
    CountResponse,
    DomainWhoisResponse,
    HashLookupResponse,
    HashLookupType,
    HashLookupTypeName,
    IpWhoisResponse,
    RateLimit,
    SearchResponse,
    SearchType,
    SearchTypeName,
    StatsResponse,
)

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_BASE_URL",
    "DEFAULT_TIMEOUT_SECONDS",
    "ENV_API_KEY",
    "ComboLookupResponse",
    "ComboLookupType",
    "ComboLookupTypeName",
    "CountResponse",
    "DomainWhoisResponse",
    "HashLookupResponse",
    "HashLookupType",
    "HashLookupTypeName",
    "IpWhoisResponse",
    "RateLimit",
    "SearchResponse",
    "SearchType",
    "SearchTypeName",
    "SnusbaseAPIError",
    "SnusbaseAuthError",
    "SnusbaseBadRequestError",
    "SnusbaseClient",
    "SnusbaseError",
    "SnusbaseRateLimitError",
    "SnusbaseResponse",
    "StatsResponse",
    "__version__",
    "parse_rate_limit",
]

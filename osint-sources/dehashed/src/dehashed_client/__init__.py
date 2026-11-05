"""HTTP client for the documented DeHashed API.

Used by ``dehashed_mcp``. This package does not import the MCP stack, so these
calls can run without starting a server. It ships inside the
``osintz-dehashed-mcp`` distribution; it is not its own distribution.
"""

from dehashed_client.client import (
    AUTH_HEADER,
    DEFAULT_BASE_URL,
    DEFAULT_RATE_PER_SECOND,
    DEFAULT_TIMEOUT_SECONDS,
    ENV_API_KEY,
    OPERATIONS,
    DehashedClient,
    DehashedResponse,
)
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
    SEARCH_DEFAULT_PAGE,
    SEARCH_DEFAULT_SIZE,
    SEARCH_MAX_RESULTS,
    SEARCH_MAX_SIZE,
)

__version__ = "0.1.0"

__all__ = [
    "AUTH_HEADER",
    "DEFAULT_BASE_URL",
    "DEFAULT_RATE_PER_SECOND",
    "DEFAULT_TIMEOUT_SECONDS",
    "ENV_API_KEY",
    "OPERATIONS",
    "SEARCH_DEFAULT_PAGE",
    "SEARCH_DEFAULT_SIZE",
    "SEARCH_MAX_RESULTS",
    "SEARCH_MAX_SIZE",
    "DehashedAPIError",
    "DehashedAuthError",
    "DehashedBadRequestError",
    "DehashedClient",
    "DehashedError",
    "DehashedForbiddenError",
    "DehashedRateLimitError",
    "DehashedResponse",
    "DehashedSubscriptionError",
    "__version__",
]

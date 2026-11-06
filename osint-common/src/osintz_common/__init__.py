"""Pieces Snusbase and DeHashed both already had.

This is not a client framework. Source-specific errors, rate limits, pacing,
and tool text stay in each source.
"""

from osintz_common.shared import (
    ClientError,
    Secret,
    check_base_url,
    client_repr,
    name_env,
    redirect_not_followed,
)

__version__ = "0.1.0"

__all__ = [
    "ClientError",
    "Secret",
    "__version__",
    "check_base_url",
    "client_repr",
    "name_env",
    "redirect_not_followed",
]

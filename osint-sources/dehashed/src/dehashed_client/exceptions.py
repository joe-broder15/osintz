"""Errors raised by the DeHashed client.

HTTP 400, 401, 403, and 429 map to the specific subclasses. The published 401
body is a missing search subscription, not a missing key. A missing or blank
key is :class:`DehashedAuthError` and is raised before a request is sent.
Any other HTTP failure, transport failure, or successful body that does not
match the documented shape is :class:`DehashedAPIError`.

:class:`DehashedError` is :class:`osintz_common.ClientError`. The subclasses
are DeHashed's status mapping, not a second copy of the base.
"""

from osintz_common import ClientError


class DehashedError(ClientError):
    """Base class for errors from this client."""


class DehashedBadRequestError(DehashedError):
    """HTTP 400, or a request that fails local checks against the docs."""


class DehashedAuthError(DehashedError):
    """No API key was configured for an endpoint that sends ``DeHashed-Api-Key``."""


class DehashedSubscriptionError(DehashedError):
    """HTTP 401.

    The published body says a search subscription and API credits are required.
    Free endpoints are still called. This client does not turn a 401 into a
    local refusal before the request.
    """


class DehashedForbiddenError(DehashedError):
    """HTTP 403. The published body is ``Insufficient Credits``."""


class DehashedRateLimitError(DehashedError):
    """HTTP 429. The docs describe a temporary restriction after 20 requests/second."""


class DehashedAPIError(DehashedError):
    """Any other failed response, including transport errors and unexpected redirects."""

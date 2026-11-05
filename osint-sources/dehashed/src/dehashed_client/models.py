"""Pydantic models for documented DeHashed request and response bodies.

Request models reject unknown fields. Response models keep extra keys. Optional
request fields left as ``None`` are omitted from the JSON so the server can
apply its own defaults.

Search entry attributes are optional: the docs say they are omitted when empty,
and the report section says result fields are omitted when null. WHOIS search
bodies are not in the export, so that response model has no required fields.
"""

from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

# Documented server defaults for POST /v2/search. Used only to evaluate
# page * size locally. Omitted tool arguments are not sent.
SEARCH_DEFAULT_PAGE = 1
SEARCH_DEFAULT_SIZE = 100
SEARCH_MAX_SIZE = 10_000
SEARCH_MAX_RESULTS = 50_000

TaskTypeName = Literal["email", "username", "phone", "name"]
ChannelTypeName = Literal["webhook", "email"]
ReverseWhoisTypeName = Literal["current", "historic"]
WhoisSearchTypeName = Literal[
    "whois",
    "whois-history",
    "reverse-ip",
    "reverse-mx",
    "reverse-ns",
    "subdomain-scan",
]
DataWellCount = Literal[20, 50]
DataWellSort = Literal[
    "added",
    "name",
    "date",
    "records",
    "added-ASC",
    "name-ASC",
    "date-ASC",
    "records-ASC",
]


class SearchRequest(BaseModel):
    """Body of ``POST /v2/search``."""

    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1)
    page: int | None = None
    size: int | None = None
    regex: bool | None = None
    wildcard: bool | None = None
    de_dupe: bool | None = None

    @model_validator(mode="after")
    def enforce_documented_limits(self) -> Self:
        if self.regex is True and self.wildcard is True:
            raise ValueError("regex and wildcard cannot both be true")
        if self.size is not None and not 1 <= self.size <= SEARCH_MAX_SIZE:
            raise ValueError("size must be between 1 and 10000")
        if self.page is not None and self.page < 1:
            raise ValueError("page must be 1 or greater")
        page = SEARCH_DEFAULT_PAGE if self.page is None else self.page
        size = SEARCH_DEFAULT_SIZE if self.size is None else self.size
        if page * size > SEARCH_MAX_RESULTS:
            raise ValueError("pagination limit exceeded")
        return self


class PasswordSearchRequest(BaseModel):
    """Body of ``POST /v2/search-password``. The value is a SHA-256 hex digest."""

    model_config = ConfigDict(extra="forbid")

    sha256_hashed_password: str = Field(min_length=1)


class DataWellsQuery(BaseModel):
    """Query string of ``GET /data-wells``. ``count`` is 20 or 50 when set."""

    model_config = ConfigDict(extra="forbid")

    count: DataWellCount | None = None
    page: int | None = None
    sort: DataWellSort | None = None


class CreateTaskRequest(BaseModel):
    """Body of the create-task call."""

    model_config = ConfigDict(extra="forbid")

    type: TaskTypeName
    value: str = Field(min_length=1)


class UpdateTaskRequest(BaseModel):
    """Body of the update-task call. ``active`` is optional in the docs."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    type: TaskTypeName
    value: str = Field(min_length=1)
    active: bool | None = None


class UpdateTaskActiveRequest(BaseModel):
    """Body of the update-task-active call."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    active: bool


class TaskIdRequest(BaseModel):
    """Body of get-task and delete-task. Both take ``id``."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)


class PageRequest(BaseModel):
    """Optional ``page`` on get-tasks and get-reports. The documented default is 1."""

    model_config = ConfigDict(extra="forbid")

    page: int | None = None


class UpdateChannelRequest(BaseModel):
    """Body of the update-channel call."""

    model_config = ConfigDict(extra="forbid")

    type: ChannelTypeName
    value: str = Field(min_length=1)


class DeleteChannelRequest(BaseModel):
    """Body of the delete-channel call. The field name is ``channel``, not ``type``."""

    model_config = ConfigDict(extra="forbid")

    channel: ChannelTypeName


class UpdateDomainRequest(BaseModel):
    """Body of the update-domain call."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    domain: str = Field(min_length=1)


class DomainIdRequest(BaseModel):
    """Body of the clear-domain call."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)


class WhoisDomainRequest(BaseModel):
    """Body of ``POST /v2/whois/search`` for the domain-shaped search types.

    Reverse IP, MX, and NS also send the address in ``domain``. That is the
    field name in the export, not a client rename.
    """

    model_config = ConfigDict(extra="forbid")

    search_type: WhoisSearchTypeName
    domain: str = Field(min_length=1)


class ReverseWhoisRequest(BaseModel):
    """Body of reverse WHOIS. At least one include or exclude term is required."""

    model_config = ConfigDict(extra="forbid")

    search_type: Literal["reverse-whois"]
    include: list[str] | None = Field(default=None, max_length=4)
    exclude: list[str] | None = Field(default=None, max_length=4)
    reverse_type: ReverseWhoisTypeName | None = None

    @model_validator(mode="after")
    def at_least_one_term(self) -> Self:
        if not (self.include or self.exclude):
            raise ValueError("include and exclude cannot both be empty")
        return self


class RawRecord(BaseModel):
    """``raw_record`` object on a search or report row."""

    model_config = ConfigDict(extra="allow")

    le_only: bool | None = None
    unstructured: bool | None = None


class SearchEntry(BaseModel):
    """One search or monitoring-report row. Missing attributes stay unset."""

    model_config = ConfigDict(extra="allow")

    id: str | None = None
    email: list[str] | None = None
    ip_address: list[str] | None = None
    username: list[str] | None = None
    password: list[str] | None = None
    hashed_password: list[str] | None = None
    name: list[str] | None = None
    dob: list[str] | None = None
    license_plate: list[str] | None = None
    address: list[str] | None = None
    phone: list[str] | None = None
    company: list[str] | None = None
    url: list[str] | None = None
    social: list[str] | None = None
    cryptocurrency_address: list[str] | None = None
    database_name: str | None = None
    raw_record: RawRecord | None = None


class SearchResponse(BaseModel):
    """Body of ``POST /v2/search``.

    The only published envelope has ``balance``, ``entries``, ``took``, and
    ``total``. ``took`` is the string ``179µs`` in that example.
    """

    model_config = ConfigDict(extra="allow")

    balance: int
    entries: list[SearchEntry]
    took: str
    total: int


class PasswordSearchResponse(BaseModel):
    """Body of ``POST /v2/search-password``."""

    model_config = ConfigDict(extra="allow")

    results_found: int


class UserInfoResponse(BaseModel):
    """Body of ``/v2/info/user``."""

    model_config = ConfigDict(extra="allow")

    search_access: bool
    search_credits: int
    whois_credits: int


class DataWell(BaseModel):
    """One object in ``data_wells``. The sample JSON is missing a comma; these are its fields."""

    model_config = ConfigDict(extra="allow")

    data: str
    date: str
    description: str
    name: str
    records: int
    is_sensitive: bool


class DataWellsResponse(BaseModel):
    """Body of ``GET /data-wells``."""

    model_config = ConfigDict(extra="allow")

    next_page: bool
    total: int
    data_wells: list[DataWell]


class SuccessResponse(BaseModel):
    """``{"success": true}`` on monitoring writes."""

    model_config = ConfigDict(extra="allow")

    success: bool


class MonitoringTask(BaseModel):
    """One object in the get-tasks ``tasks`` array."""

    model_config = ConfigDict(extra="allow")

    id: str
    type: str
    value: str
    active: bool
    created: str
    updated: str


class TaskListResponse(BaseModel):
    """Body of get-tasks."""

    model_config = ConfigDict(extra="allow")

    tasks: list[MonitoringTask]
    total: int
    active: int
    inactive: int
    max: int
    next_page: bool


class TaskDetailResponse(BaseModel):
    """Body of get-task. The sample has no ``id``."""

    model_config = ConfigDict(extra="allow")

    type: str
    value: str
    active: bool
    created: str
    updated: str


class ReportSummary(BaseModel):
    """One object in the get-reports ``reports`` array."""

    model_config = ConfigDict(extra="allow")

    id: str
    timestamp: str


class ReportListResponse(BaseModel):
    """Body of get-reports."""

    model_config = ConfigDict(extra="allow")

    reports: list[ReportSummary]
    next_page: bool


class ReportTask(BaseModel):
    """One task inside a monitoring report."""

    model_config = ConfigDict(extra="allow")

    id: str
    key: str
    value: str
    results_count: int
    timestamp: str
    results: list[SearchEntry]


class ReportDetailResponse(BaseModel):
    """Body of get-report."""

    model_config = ConfigDict(extra="allow")

    tasks: list[ReportTask]


class NotificationChannel(BaseModel):
    """One notification channel. The timestamp field is ``updated_at``."""

    model_config = ConfigDict(extra="allow")

    id: str
    type: str
    value: str
    updated_at: str


class ChannelListResponse(BaseModel):
    """Body of get-channels.

    The docs say the response is empty when there are no channels. No empty
    payload is shown. An object with ``channels`` omitted is accepted.
    """

    model_config = ConfigDict(extra="allow")

    channels: list[NotificationChannel] = Field(default_factory=list)


class MonitoringDomain(BaseModel):
    """One monitoring domain. The timestamp field is ``updated``."""

    model_config = ConfigDict(extra="allow")

    id: str
    domain: str
    updated: str


class DomainListResponse(BaseModel):
    """Body of get-domains."""

    model_config = ConfigDict(extra="allow")

    domains: list[MonitoringDomain]


class WhoisSearchResponse(BaseModel):
    """Body of ``POST /v2/whois/search``.

    The export does not publish this JSON. Any object is kept. A non-object
    body still fails in the client before this model runs.
    """

    model_config = ConfigDict(extra="allow")


class WhoisCreditsResponse(BaseModel):
    """Body of ``GET /v2/whois/credits``."""

    model_config = ConfigDict(extra="allow")

    whois_credits: int

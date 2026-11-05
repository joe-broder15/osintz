"""Pydantic models for the DeHashed calls this server makes.

Request models reject unknown fields. Response models keep extra keys. Optional
request fields left as ``None`` are omitted from the JSON so the server can
apply its own defaults.

Search entry attributes are optional: the docs say they are omitted when empty.
WHOIS search bodies are not in the export, so that response model has no
required fields.
"""

from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

# Documented server defaults for POST /v2/search. Used only to evaluate
# page * size locally. Omitted tool arguments are not sent.
SEARCH_DEFAULT_PAGE = 1
SEARCH_DEFAULT_SIZE = 100
SEARCH_MAX_SIZE = 10_000
SEARCH_MAX_RESULTS = 50_000

ReverseWhoisTypeName = Literal["current", "historic"]
WhoisSearchTypeName = Literal["whois", "subdomain-scan"]
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


class DataWellsQuery(BaseModel):
    """Query string of ``GET /data-wells``. ``count`` is 20 or 50 when set."""

    model_config = ConfigDict(extra="forbid")

    count: DataWellCount | None = None
    page: int | None = None
    sort: DataWellSort | None = None


class WhoisDomainRequest(BaseModel):
    """Body of ``POST /v2/whois/search`` for whois and subdomain-scan."""

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
    """``raw_record`` object on a search row."""

    model_config = ConfigDict(extra="allow")

    le_only: bool | None = None
    unstructured: bool | None = None


class SearchEntry(BaseModel):
    """One search row. Missing attributes stay unset."""

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


class WhoisSearchResponse(BaseModel):
    """Body of ``POST /v2/whois/search``.

    The export does not publish this JSON. Any object is kept. A non-object
    body still fails in the client before this model runs.
    """

    model_config = ConfigDict(extra="allow")

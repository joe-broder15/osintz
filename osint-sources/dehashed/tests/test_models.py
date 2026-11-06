"""Request limits and response shapes from the DeHashed export."""

import pytest
from pydantic import ValidationError

from dehashed_client.models import (
    SEARCH_DEFAULT_PAGE,
    SEARCH_DEFAULT_SIZE,
    DataWellsQuery,
    ReverseWhoisRequest,
    SearchEntry,
    SearchRequest,
    SearchResponse,
    WhoisSearchResponse,
)


def test_search_omits_defaults_and_rejects_both_matchers() -> None:
    body = SearchRequest.model_validate({"query": "ada@example.com"}).model_dump(exclude_none=True)
    assert body == {"query": "ada@example.com"}
    assert SEARCH_DEFAULT_PAGE == 1
    assert SEARCH_DEFAULT_SIZE == 100
    with pytest.raises(ValidationError, match="regex and wildcard cannot both be true"):
        SearchRequest.model_validate({"query": "ada@example.com", "regex": True, "wildcard": True})


@pytest.mark.parametrize(
    ("payload", "match"),
    [
        ({"query": "ada@example.com", "size": 0}, "size must be between 1 and 10000"),
        ({"query": "ada@example.com", "size": 10001}, "size must be between 1 and 10000"),
        ({"query": "ada@example.com", "page": 0}, "page must be 1 or greater"),
        ({"query": "ada@example.com", "page": 6, "size": 10000}, "pagination limit exceeded"),
        ({"query": "ada@example.com", "page": 501}, "pagination limit exceeded"),
    ],
)
def test_search_limits(payload: dict[str, object], match: str) -> None:
    with pytest.raises(ValidationError, match=match):
        SearchRequest.model_validate(payload)


def test_deep_page_within_the_50000_window_is_valid() -> None:
    # The earlier note calls page 3 size 5000 invalid. The pagination section
    # allows any request with page * size <= 50000. This client follows that.
    parsed = SearchRequest.model_validate(
        {"query": "ada@example.com", "page": 5, "size": 10000, "de_dupe": False}
    )
    assert parsed.model_dump(exclude_none=True)["de_dupe"] is False
    SearchRequest.model_validate({"query": "ada@example.com", "page": 3, "size": 5000})


def test_search_entry_keeps_unknown_fields_and_drops_nothing_required() -> None:
    entry = SearchEntry.model_validate({"id": "1", "email": ["a@example.com"], "future": ["x"]})
    assert entry.password is None
    assert entry.model_dump()["future"] == ["x"]
    response = SearchResponse.model_validate(
        {
            "balance": 3,
            "entries": [entry.model_dump()],
            "took": "179µs",
            "total": 1,
            "extra": True,
        }
    )
    assert response.model_dump()["extra"] is True
    assert response.entries[0].email == ["a@example.com"]


def test_whois_response_has_no_required_fields() -> None:
    assert WhoisSearchResponse.model_validate({}).model_dump() == {}
    kept = WhoisSearchResponse.model_validate({"domain": "example.com", "raw": [1]})
    assert kept.model_dump()["raw"] == [1]


def test_data_well_sort_and_count() -> None:
    assert DataWellsQuery.model_validate({"sort": "name-ASC", "count": 20}).count == 20
    with pytest.raises(ValidationError):
        DataWellsQuery.model_validate({"count": 10})
    with pytest.raises(ValidationError):
        DataWellsQuery.model_validate({"sort": "name-DESC"})


def test_reverse_whois_needs_a_term_and_caps_lists() -> None:
    with pytest.raises(ValidationError, match="cannot both be empty"):
        ReverseWhoisRequest.model_validate({"search_type": "reverse-whois"})
    with pytest.raises(ValidationError):
        ReverseWhoisRequest.model_validate(
            {"search_type": "reverse-whois", "include": ["a", "b", "c", "d", "e"]}
        )
    parsed = ReverseWhoisRequest.model_validate(
        {"search_type": "reverse-whois", "exclude": ["x"], "reverse_type": "historic"}
    )
    assert parsed.exclude == ["x"]

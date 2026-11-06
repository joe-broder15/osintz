from osintz_common import (
    ClientError,
    Secret,
    check_base_url,
    client_repr,
    name_env,
    redirect_not_followed,
)


def test_secret_hides_the_value() -> None:
    secret = Secret("sb" + "k" * 28)
    assert secret.reveal().endswith("k" * 28)
    assert "k" * 28 not in repr(secret)
    assert str(secret) == "<redacted>"
    assert format(secret) == "<redacted>"
    assert format(secret, "s") == "<redacted>"


def test_client_error_keeps_status_and_message() -> None:
    err = ClientError("nope", status_code=400)
    assert str(err) == "nope"
    assert err.message == "nope"
    assert err.status_code == 400
    assert repr(err) == "ClientError(status_code=400)"


def test_check_base_url_strips_a_slash() -> None:
    assert check_base_url("https://api.example/") == "https://api.example"
    try:
        check_base_url("  ")
    except ValueError as exc:
        assert "non-empty" in str(exc)
    else:
        raise AssertionError("blank base url was accepted")


def test_redirect_text_has_no_location() -> None:
    text = redirect_not_followed(302)
    assert text == "Unexpected redirect (HTTP 302). Redirects are not followed."
    assert "Location" not in text


def test_client_repr_says_whether_a_key_is_set() -> None:
    text = client_repr("SnusbaseClient", "https://api.example", 60.0, api_key_set=True)
    assert text == "SnusbaseClient(base_url='https://api.example', timeout=60.0, api_key_set=True)"


def test_name_env_does_not_repeat_the_variable() -> None:
    assert name_env("missing", "SNUSBASE_API_KEY") == "missing Set SNUSBASE_API_KEY."
    assert name_env("see SNUSBASE_API_KEY", "SNUSBASE_API_KEY") == "see SNUSBASE_API_KEY"
    assert name_env("bad", "DEHASHED_API_KEY", verb="Check") == "bad Check DEHASHED_API_KEY."

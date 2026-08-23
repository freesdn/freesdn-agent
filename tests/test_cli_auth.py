"""
Every authenticated CLI command returned 403 against a current controller.

``daemon/cli.py`` is 397 statements at 0% coverage, and it is the FIRST thing an
operator runs -- the .deb postinst prints ``freesdn-agent register`` and every
doc opens with it. Two separate faults had shipped there, and the second was
introduced by the fix for the first.

FAULT 1 (v1.0.0): ``register`` POSTed to /auth/login and read ``access_token``
off a response that deliberately omits it, raising an uncaught KeyError.

FAULT 2 (the "fix"): moving to /auth/token returned the token correctly, and the
NEXT call then failed with 403. /auth/token returns bearer tokens in the body AND
sets the browser session cookies. httpx stores them on the client, so the
follow-up request carried both a bearer header and a session cookie -- and the
server's CSRF middleware enforces CSRF for exactly that combination, on purpose,
because an attacker who could send "Authorization: Bearer garbage" alongside a
victim's cookie would otherwise bypass it.

Proven against the running backend before fixing:

    shared client  -> 403 {"message": "CSRF token missing"}
    cookie-free    -> 200 ['agent_id', 'agent_key', 'websocket_url']

The agent is not a browser and has no use for those cookies, so ``_login`` drops
them. After that, register completed end to end for the first time:

    Registration successful!
      Agent ID:  b2d421bc-6545-432a-8488-3ba771b892aa

FAULT 3, found while testing the other two: registration could not be automated
at all. ``getpass`` reads /dev/tty rather than stdin, so piping a password did
not merely fail -- it HUNG, with no output and no timeout, which is the worst
way for a headless install to behave. Credentials now come from the environment
first, and a non-TTY run with nothing set exits with a message instead of
blocking for ever.
"""

from __future__ import annotations

import httpx
import pytest

from freesdn_agent.daemon import cli

# ── credentials ─────────────────────────────────────────────────


def test_credentials_come_from_the_environment(monkeypatch):
    """So a .deb postinst, an Ansible play or a container can register."""
    monkeypatch.setenv("FREESDN_EMAIL", "ops@example.com")
    monkeypatch.setenv("FREESDN_PASSWORD", "hunter2")

    assert cli._read_credentials() == ("ops@example.com", "hunter2")


def test_a_headless_run_with_no_credentials_gives_up_instead_of_hanging(monkeypatch, capsys):
    """
    The behaviour that matters. Before this, the same situation blocked for ever
    inside getpass with nothing on stdout -- an install script that appeared to
    have frozen.
    """
    monkeypatch.delenv("FREESDN_EMAIL", raising=False)
    monkeypatch.delenv("FREESDN_PASSWORD", raising=False)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)

    assert cli._read_credentials() is None
    assert "FREESDN_EMAIL" in capsys.readouterr().err


def test_the_environment_wins_over_prompting(monkeypatch):
    """
    A prompt reached while the environment is set would still hang a headless
    run, which is the bug wearing a different hat.
    """
    monkeypatch.setenv("FREESDN_EMAIL", "ops@example.com")
    monkeypatch.setenv("FREESDN_PASSWORD", "hunter2")

    def _boom(*a, **k):  # pragma: no cover - only runs if the guard is wrong
        raise AssertionError("prompted despite credentials being in the environment")

    monkeypatch.setattr("builtins.input", _boom)
    assert cli._read_credentials() is not None


# ── login ───────────────────────────────────────────────────────


def _mock_server(monkeypatch, *, token_body: dict, set_cookies: bool = True, status: int = 200):
    """An httpx client wired to a server that behaves like the real one.

    Real ``httpx.Client`` over ``MockTransport``, not a stub: the cookie jar has
    to behave for the assertion below to mean anything.
    """
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path.endswith("/auth/token"):
            headers = {}
            if set_cookies:
                # Exactly what the controller sends back.
                headers = [
                    ("set-cookie", "freesdn_access=abc; Path=/"),
                    ("set-cookie", "freesdn_csrf=def; Path=/"),
                    ("set-cookie", "freesdn_refresh=ghi; Path=/"),
                ]
            return httpx.Response(status, json=token_body, headers=headers)
        return httpx.Response(200, json={})

    real_client = httpx.Client
    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **kw: real_client(**{**kw, "transport": httpx.MockTransport(handler)}),
    )
    return seen


def test_login_drops_the_session_cookies(monkeypatch):
    """
    THE regression. Keeping them makes every following request carry bearer +
    cookie, which the server refuses with 403 by design.
    """
    monkeypatch.setenv("FREESDN_EMAIL", "ops@example.com")
    monkeypatch.setenv("FREESDN_PASSWORD", "hunter2")
    _mock_server(monkeypatch, token_body={"access_token": "tok"})

    result = cli._login("http://server")
    assert result is not None
    client, headers = result
    try:
        assert dict(client.cookies) == {}, (
            "session cookies survived login; every authenticated call will 403"
        )
        assert headers == {"Authorization": "Bearer tok"}
    finally:
        client.close()


def test_login_uses_the_oauth_token_endpoint_not_the_browser_one(monkeypatch):
    """
    /auth/login is the BROWSER endpoint and omits the tokens from its body.
    Reading access_token off it is fault 1, and it must not come back.
    """
    monkeypatch.setenv("FREESDN_EMAIL", "ops@example.com")
    monkeypatch.setenv("FREESDN_PASSWORD", "hunter2")
    seen = _mock_server(monkeypatch, token_body={"access_token": "tok"})

    result = cli._login("http://server")
    assert result is not None
    result[0].close()
    assert any(r.url.path.endswith("/auth/token") for r in seen)
    assert not any(r.url.path.endswith("/auth/login") for r in seen)


def test_a_response_without_a_token_is_reported_not_raised(monkeypatch, capsys):
    """
    Fault 1's actual shape was an uncaught KeyError on a dict subscript. A
    missing token has to read as a diagnosable message, not a traceback.
    """
    monkeypatch.setenv("FREESDN_EMAIL", "ops@example.com")
    monkeypatch.setenv("FREESDN_PASSWORD", "hunter2")
    _mock_server(monkeypatch, token_body={"token_type": "bearer"})  # no access_token

    assert cli._login("http://server") is None
    assert "no access token" in capsys.readouterr().err.lower()


def test_a_failed_login_returns_none(monkeypatch, capsys):
    monkeypatch.setenv("FREESDN_EMAIL", "ops@example.com")
    monkeypatch.setenv("FREESDN_PASSWORD", "bad")
    _mock_server(monkeypatch, token_body={"detail": "nope"}, status=401)

    assert cli._login("http://server") is None
    assert "login failed" in capsys.readouterr().err.lower()


def test_no_credentials_means_no_request_is_attempted(monkeypatch):
    monkeypatch.delenv("FREESDN_EMAIL", raising=False)
    monkeypatch.delenv("FREESDN_PASSWORD", raising=False)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    seen = _mock_server(monkeypatch, token_body={"access_token": "tok"})

    assert cli._login("http://server") is None
    assert seen == [], "the CLI dialled the server before it had anything to send"


# ── one login path, not several ─────────────────────────────────


def test_register_uses_the_shared_login(monkeypatch):
    """
    ``register`` used to carry its own copy, and the copies had ALREADY drifted
    once: the /auth/login to /auth/token migration was applied to one and not
    the other. Two copies would also have needed the cookie fix twice.
    """
    import inspect

    src = inspect.getsource(cli._cmd_register)
    # Strip comments: the explanation in that function NAMES /auth/token while
    # describing the drift, and an assertion that matched the prose would fail
    # on correct code and pass on the bug if the comment were ever removed.
    code = "\n".join(ln for ln in src.splitlines() if not ln.strip().startswith("#"))
    assert "_login(" in code
    assert "/auth/token" not in code, "register is talking to the auth endpoint directly again"


def test_register_does_not_re_enter_the_client(monkeypatch):
    """
    ``_login`` has already made a request on the client it returns, and httpx
    refuses to re-enter one: "Cannot open a client instance more than once".
    Every other command uses try/finally, and so must this one.
    """
    import inspect

    src = inspect.getsource(cli._cmd_register)
    assert "with client:" not in src
    assert "client.close()" in src


@pytest.mark.parametrize("command", ["_cmd_list_discovered", "_cmd_adopt", "_cmd_schedule"])
def test_every_authenticated_command_goes_through_it(command: str):
    """
    All of these were broken by the same cookie carry-over, because all of them
    take their client from the shared helper. That is what made one fix enough.
    """
    import inspect

    src = inspect.getsource(getattr(cli, command))
    assert "_login" in src

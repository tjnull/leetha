"""Regression — mutation endpoints capture the authenticated token id in audit rows.

The auth middleware publishes the token id via ``request.scope["auth_token_id"]``
(see ``leetha.auth.middleware.auth_middleware``). Our endpoints used to read
``request.state.token_id`` — a different container — so every write landed
with actor=``anonymous``. This test pins the read path.
"""

from types import SimpleNamespace

from leetha.ui.web.routers.devices import _actor_from_request
from leetha.ui.web.routers.authorization_bulk import _actor


def _req(scope_extra: dict | None = None, state_extra: dict | None = None):
    """Build a minimal Request-like object exposing .scope and .state."""
    scope = {"type": "http"}
    if scope_extra:
        scope.update(scope_extra)
    state = SimpleNamespace()
    for k, v in (state_extra or {}).items():
        setattr(state, k, v)
    return SimpleNamespace(scope=scope, state=state)


def test_per_device_actor_reads_scope_token_id():
    r = _req(scope_extra={"auth_token_id": 42})
    assert _actor_from_request(r) == "42"


def test_per_device_actor_falls_back_to_state():
    """If a caller set request.state.token_id directly (unusual but supported),
    use it when scope is empty."""
    r = _req(state_extra={"token_id": 7})
    assert _actor_from_request(r) == "7"


def test_per_device_actor_is_anonymous_when_unauthenticated():
    r = _req()
    assert _actor_from_request(r) == "anonymous"


def test_bulk_actor_reads_scope_token_id():
    r = _req(scope_extra={"auth_token_id": 99})
    assert _actor(r) == "99"


def test_bulk_actor_is_bulk_anonymous_when_unauthenticated():
    r = _req()
    assert _actor(r) == "bulk-anonymous"


def test_bulk_actor_falls_back_to_state():
    r = _req(state_extra={"token_id": 3})
    assert _actor(r) == "3"


def test_scope_token_id_preferred_over_state():
    """If both are present, scope wins — it came from the real middleware."""
    r = _req(scope_extra={"auth_token_id": 10}, state_extra={"token_id": 20})
    assert _actor_from_request(r) == "10"
    assert _actor(r) == "10"

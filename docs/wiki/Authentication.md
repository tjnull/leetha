# Authentication & API Security

Leetha includes token-based authentication for securing the web dashboard and REST API when exposed beyond localhost.

## When Auth Is Enabled

Authentication is **automatically enabled** when the web server binds to a non-localhost address (e.g., `0.0.0.0`). It is **disabled** when bound to `127.0.0.1` or `::1`.

You can override this with:
- `--auth` -- force authentication on
- `--no-auth` -- force authentication off

## Admin Token

On first startup, Leetha generates an admin token and saves it to `~/.leetha/admin-token`. View it with:

```bash
leetha auth show-token
```

## Token Management

```bash
# List all tokens
leetha auth list-tokens

# Create a new token with a specific role
leetha auth create-token --role analyst --label "readonly-user"

# Revoke a token
leetha auth revoke-token <token-id>
```

## Roles

| Role | Permissions |
|------|-------------|
| `admin` | Full access: settings, capture control, token management, delete alerts |
| `analyst` | Read access: devices, alerts, stats. Can acknowledge alerts. |

## API Authentication

Include the token in the `Authorization` header:

```bash
curl -k -H "Authorization: Bearer ltk_..." https://host/api/devices
```

## WebSocket Authentication

WebSocket connections use the `leetha-v1` subprotocol. The auth token is passed as a query parameter or cookie -- the subprotocol name is fixed and no longer echoes the token value:

```javascript
new WebSocket("wss://host/ws", ["leetha-v1"]);
```

## Cookie Security

When TLS is enabled (the default), the authentication cookie is set with `secure=True`, ensuring it is only transmitted over HTTPS connections.

## Exempt Paths

These paths do not require authentication:
- `/login` -- login page
- `/api/health` -- health check
- Static assets (`/assets/*`)

The `/metrics` endpoint **requires authentication** (it is not exempt).

## Disabled Endpoints

OpenAPI documentation endpoints are disabled for security hardening:
- `/api/docs` -- not available
- `/api/redoc` -- not available

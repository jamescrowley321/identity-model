# FastAPI example (fastapi-identity-model)

A runnable FastAPI app demonstrating the **`fastapi-identity-model`** package
(which lives in `py/packages/fastapi-identity-model/`). It wires up both patterns:

- **Relying-party browser login** — `GET /auth/login` → provider → `/auth/callback`
  → identity in the session; read it at `GET /me`.
- **Resource-server API protection** — `/api/*` routes require a validated
  `Authorization: Bearer <token>` via `TokenValidationMiddleware`.

See `app.py` for the wiring and the package README for the full API.

## Run

```bash
# from the repo root
cd py && uv sync --all-packages

# configure your provider (Descope shown; any OIDC provider works)
export DISCOVERY_URL="https://api.descope.com/v1/apps/<project_id>/.well-known/openid-configuration"
export CLIENT_ID="<client_id>"
export REDIRECT_URI="http://localhost:8000/auth/callback"
export AUDIENCE="<client_id>"
export SESSION_SECRET="$(openssl rand -hex 32)"

cd examples/fastapi     # i.e. py/examples/fastapi
uv run python app.py     # http://localhost:8000
```

### Try it

```bash
# Browser login (relying party): open in a browser
open http://localhost:8000/auth/login      # → redirects to your provider, then /me

# API protection (resource server): needs a Bearer token
TOKEN="<access-token>"
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/me
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/claims
curl http://localhost:8000/api/me        # 401 — no token
```

Interactive docs: <http://localhost:8000/docs>.

## Endpoints

| Path | Auth | Description |
|------|------|-------------|
| `/`, `/health` | none | Public |
| `GET /auth/login`, `GET /auth/callback`, `POST /auth/logout` | session | RP login flow |
| `/me` | session | Logged-in identity from the session cookie |
| `/api/me`, `/api/claims`, `/api/profile`, `/api/token-info` | Bearer | Validated-token info |
| `/api/data` (GET/POST) | Bearer + scope | Scope-based authorization |
| `/api/admin/*` | Bearer + `role=admin` | Claim-based authorization |

## Environment variables

| Var | Default | Notes |
|-----|---------|-------|
| `DISCOVERY_URL` | `https://localhost:5001/.well-known/openid-configuration` | Provider discovery |
| `CLIENT_ID` | `py-identity-model-client` | OAuth client id |
| `REDIRECT_URI` | `http://localhost:8000/auth/callback` | Must match the router's callback |
| `CLIENT_SECRET` | _(unset)_ | Omit for public/PKCE clients |
| `AUDIENCE` | `py-identity-model` | Expected token audience |
| `SCOPE` | `openid profile email` | Scopes requested by `/auth/login` |
| `SESSION_SECRET` | _(random per run)_ | Set a stable secret so sessions survive restarts; never a shared/committed value |
| `SESSION_HTTPS_ONLY` | `false` | Set `true` behind TLS to add the cookie `Secure` flag |

## Tests

Integration tests (`test_integration.py`) exercise the Bearer-protected `/api/*`
routes against a real identity server. See the Docker Compose setup at
`py/examples/docker-compose.test.yml` and `py/examples/run-tests.sh` (`make test-examples`).

## License

Apache-2.0 — see the repository `LICENSE`.

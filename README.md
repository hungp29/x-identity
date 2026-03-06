# x-identity

Authentication and authorization gRPC service for the x-projects platform.

## Overview

x-identity is a Go gRPC service that provides:

- **Authentication** — registration, login, logout, refresh-token rotation, and stateless JWT access-token validation.
- **Authorization** — role-based access control (RBAC): permission checks, role assignment, and role revocation.

It is backed by a PostgreSQL database (schema `xdata`) whose tables are created and seeded by the `x-migration` service.

---

## Repository layout

```
x-identity/
├── cmd/xidentity/main.go           # entry point
├── internal/
│   ├── config/config.go            # fail-fast env config; builds DB URL from parts
│   ├── db/db.go                    # pgxpool connection helper
│   ├── model/                      # domain types (no framework deps)
│   │   ├── user.go                 # User, IsLocked(), IsEmailVerified()
│   │   ├── session.go              # Session, IsActive()
│   │   └── rbac.go                 # Role, Permission, UserRole, IsActive()
│   ├── repository/                 # SQL via pgx — one file per aggregate
│   │   ├── user_repo.go            # UserRepo: Create, FindByEmail, FindByID, login counters
│   │   ├── session_repo.go         # SessionRepo: Create, FindByTokenHash, Revoke, RevokeByUserID
│   │   └── rbac_repo.go            # RBACRepo: role lookup, permissions, assign/revoke
│   ├── service/                    # business logic; depends on repository interfaces
│   │   ├── auth_service.go         # AuthService: Register, Login, Logout, RefreshToken, ValidateToken
│   │   └── authz_service.go        # AuthzService: CheckPermission, GetUserPermissions, AssignRole, RevokeRole
│   ├── grpcserver/                 # gRPC handlers — map service errors to status codes
│   │   ├── auth_server.go          # AuthServer implements identityv1.AuthServiceServer
│   │   └── authz_server.go         # AuthzServer implements identityv1.AuthzServiceServer
│   └── server/server.go            # wires deps, creates grpc.Server, runs with graceful shutdown
├── charts/x-identity/              # Helm chart
├── .github/workflows/              # CI/CD
│   ├── release.yaml                # manual: cuts a timestamped tag
│   └── build-and-push.yaml         # on tag: builds image, pushes to GHCR, packages chart, PRs x-deployk8s
├── Makefile
├── Dockerfile                      # multi-stage, scratch final image
└── .env.example
```

---

## gRPC API

Proto source: `x-proto/identity/v1/identity.proto`  
Go package: `github.com/hungp29/x-proto/gen/go/identity/v1` (alias `identityv1`)

### AuthService

| RPC | Request fields | Response | Notes |
|-----|---------------|----------|-------|
| `Register` | `email`, `name`, `password` | `User` | bcrypt-hashes password; `AlreadyExists` if email taken |
| `Login` | `email`, `password`, `ip_address`, `user_agent` | `User`, `TokenPair` | locks account after `MAX_FAILED_LOGINS`; resets counter on success |
| `Logout` | `refresh_token` | — | revokes the session row; `NotFound` if already revoked |
| `RefreshToken` | `refresh_token`, `ip_address`, `user_agent` | `TokenPair` | rotates token: revokes old session, creates new one |
| `ValidateToken` | `access_token` | `user_id`, `email`, `roles[]` | stateless JWT parse; no DB call |

### AuthzService

| RPC | Request fields | Response | Notes |
|-----|---------------|----------|-------|
| `CheckPermission` | `user_id`, `resource`, `action` | `allowed bool` | wildcard `*:*` grants everything (super_admin) |
| `GetUserPermissions` | `user_id` | `Permission[]` | all effective permissions via active roles |
| `AssignRole` | `user_id`, `role_name`, `expires_at` (unix sec, 0=permanent), `granted_by` | — | upserts `user_roles`; `NotFound` if user or role missing |
| `RevokeRole` | `user_id`, `role_name` | — | silent if assignment doesn't exist |

### Shared message types

```protobuf
message User        { id, email, name, email_verified, locked }
message TokenPair   { access_token, refresh_token, access_token_expires_in (seconds) }
message Permission  { id, resource, action, description }
```

---

## Token strategy

### Access token (JWT, HS256)
- Signed with `JWT_SECRET` using `github.com/golang-jwt/jwt/v5`.
- Claims: `sub` (user_id), `email`, `roles[]`, `iat`, `exp`.
- Default TTL: 15 min (`ACCESS_TOKEN_TTL`). Stateless — no DB lookup on validation.

### Refresh token (opaque, server-side session)
- 32 cryptographically random bytes encoded as hex (64-char string) sent to the client.
- Only the SHA-256 hex digest (`hashToken()`) is stored in the `sessions` table.
- Default TTL: 7 days (`REFRESH_TOKEN_TTL`).
- On refresh: old session is revoked **before** the new one is created (rotation).

---

## Database schema

Managed by `x-migration` (Flyway). All tables live in the `xdata` schema.

| Table | Purpose |
|-------|---------|
| `users` | Accounts. Stores `password_hash` (bcrypt), `failed_login_count`, `locked_at`, `email_verified_at`. |
| `sessions` | Server-side refresh-token records. Stores `token_hash` (SHA-256), `expires_at`, `revoked_at`. |
| `roles` | Named roles (e.g. `super_admin`, `admin`, `editor`, `viewer`). `is_system=true` rows are seeded. |
| `permissions` | `(resource, action)` pairs, e.g. `("users","read")`, `("*","*")`. |
| `role_permissions` | Many-to-many: role → permission. |
| `user_roles` | Role assignments per user with optional `expires_at`. |

### Built-in roles (seeded by x-migration V5)

| Role | Permissions |
|------|-------------|
| `super_admin` | `*:*` wildcard |
| `admin` | All non-wildcard permissions |
| `editor` | `read`+`write` on domain resources |
| `viewer` | `read` on domain resources |

### Permission check logic (`AuthzService.CheckPermission`)

A user is allowed if any of their effective permissions (via active, non-expired roles) satisfies:
1. `resource == "*" && action == "*"` (super_admin wildcard)
2. `resource == req.resource && action == req.action` (exact match)
3. `resource == req.resource && action == "*"` (resource wildcard)

---

## Configuration

All configuration is read from environment variables at startup. Missing required variables cause an immediate fatal error.

### Database — individual vars (no embedded URL)

DB credentials are split into separate env vars so Kubernetes Secrets can inject them without a full connection string.

| Var | Required | Default | Description |
|-----|----------|---------|-------------|
| `DB_HOST` | yes | — | PostgreSQL host |
| `DB_PORT` | no | `5432` | PostgreSQL port |
| `DB_NAME` | yes | — | Database name |
| `DB_USER` | yes | — | Database user (inject from Secret) |
| `DB_PASSWORD` | yes | — | Database password (inject from Secret) |
| `DB_SSLMODE` | no | `disable` | SSL mode |
| `DB_SCHEMA` | no | `xdata` | PostgreSQL search_path |

### Application

| Var | Required | Default | Description |
|-----|----------|---------|-------------|
| `GRPC_PORT` | no | `50051` | gRPC listen port |
| `JWT_SECRET` | yes | — | HS256 signing key (min 32 chars; inject from Secret) |
| `ACCESS_TOKEN_TTL` | no | `15m` | JWT access token lifetime |
| `REFRESH_TOKEN_TTL` | no | `168h` | Refresh token / session lifetime (7 days) |
| `MAX_FAILED_LOGINS` | no | `5` | Consecutive failures before account lock |

---

## Service error → gRPC status code mapping

| Sentinel error | gRPC code | Scenario |
|----------------|-----------|---------|
| `ErrEmailTaken` | `AlreadyExists` | Register with duplicate email |
| `ErrInvalidCredentials` | `Unauthenticated` | Wrong email or password |
| `ErrAccountLocked` | `PermissionDenied` | Login/refresh on locked account |
| `ErrSessionNotFound` | `NotFound` / `Unauthenticated` | Logout / refresh with unknown token |
| `ErrSessionExpired` | `Unauthenticated` | Refresh with expired session |
| `ErrInvalidToken` | `Unauthenticated` | ValidateToken with bad JWT |
| `ErrUserNotFound` | `NotFound` | AssignRole with unknown user |
| `ErrRoleNotFound` | `NotFound` | AssignRole / RevokeRole with unknown role |
| `repository.ErrNotFound` | — | Internal; re-wrapped into domain errors above |
| `repository.ErrDuplicate` | — | Internal; re-wrapped into `ErrEmailTaken` |

---

## Running locally

```bash
cp .env.example .env
# fill in DB_USER, DB_PASSWORD, JWT_SECRET, and DB_HOST

make run          # builds and runs the binary
make build        # build only
make test         # go test ./...
make lint         # golangci-lint or go vet
```

The database must be reachable and migrations must have been applied by `x-migration`.

### Regenerate proto stubs

Proto source lives in `../x-proto/identity/v1/identity.proto`.

```bash
make generate     # requires protoc, protoc-gen-go, protoc-gen-go-grpc
```

Generated files are committed to the repo and should not be edited by hand.

---

## Helm chart

```bash
helm install x-identity ./charts/x-identity \
  --set env.DB_HOST=postgres-svc \
  --set secret.dbUser=xidentity \
  --set secret.dbPassword=s3cr3t \
  --set secret.jwtSecret=my-long-jwt-signing-key
```

Secrets are always sourced from a Kubernetes `Secret` via `secretKeyRef`. Non-sensitive config (DB_HOST, DB_PORT, etc.) is in `values.yaml`.

Set `secret.create=false` and `secret.name=<name>` to bring your own Secret.

---

## CI/CD

### Cut a release (manual)
Trigger `release.yaml` from GitHub Actions UI. It creates a tag in the format `YYYYMMDD-HHMMSS-<sha7>-<run_number>` and fires `build-and-push.yaml`.

### Build and push (on tag)
`build-and-push.yaml` runs on every tag push:
1. Builds and pushes Docker image to `ghcr.io/<owner>/x-identity:<tag>`.
2. Patches `charts/x-identity/values.yaml` with the new image tag.
3. Packages and pushes the Helm chart to `oci://ghcr.io/<owner>/charts`.
4. Opens a PR in `x-deployk8s` to bump the ArgoCD `targetRevision` for `applications/x-identity.yaml` (skipped if `DEPLOYK8S_REPO_TOKEN` is not set).

### Required secrets
| Secret | Purpose |
|--------|---------|
| `GITHUB_TOKEN` | Auto-provided; used for GHCR login |
| `DEPLOYK8S_REPO_TOKEN` | PAT with write access to x-deployk8s repo (optional) |

---

## Key design decisions

- **No shared mutable request/session state.** All state is passed explicitly through function arguments or retrieved from the DB per request.
- **Fail-fast config.** `config.Load()` validates all required vars at startup and exits with a clear error before accepting any traffic.
- **Credentials never in the connection string.** DB credentials are assembled from separate env vars inside `buildDatabaseURL()` so Kubernetes Secrets are injected cleanly.
- **Refresh token rotation.** On every refresh, the old session is revoked before the new one is created. A stolen refresh token used after rotation will be rejected.
- **Token hash storage.** The raw refresh token is never stored. Only its SHA-256 hex digest lives in the DB, limiting exposure from a DB dump.
- **Structured JSON logging.** `log/slog` with `NewJSONHandler`. Every RPC is logged with `method`, `ok`, `duration_ms` via a unary interceptor.
- **Deep modules.** Repository types expose narrow interfaces consumed by service types, not the other way around. Services depend on interface subsets, not concrete repo types.

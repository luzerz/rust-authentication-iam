# Tasks for Authentication Service

## Completed
- [x] Domain models: User, Role, Permission, Token (with business logic and unit tests)
- [x] Application layer: Commands, handlers, services for login, token issuance, validation, refresh
- [x] Infrastructure: PostgresUserRepository, PostgresRefreshTokenRepository
- [x] Interface: Axum HTTP endpoints for /iam/login, /iam/validate-token, /iam/refresh-token, /iam/logout, /iam/roles, /iam/permissions, /iam/abac/policies, etc.
- [x] Environment-based config (dotenvy for secrets, DB URL, API mode, host, and port)
- [x] Docker Compose for Postgres
- [x] Database migrations for users, roles, user_roles, refresh_tokens
- [x] Manual E2E testing via curl/Postman
- [x] DDD/hexagonal structure (domain, application, infrastructure, interface)
- [x] Secure JWT/refresh token logic (with jti, DB storage, revocation, and tests for revoked tokens)
- [x] OpenTelemetry tracing for all major flows (HTTP), with golden signal events (latency, traffic, errors, success) instrumented in all handlers
- [x] OpenAPI/Swagger spec for all endpoints (all endpoints documented, secured, and described in Swagger UI)
- [x] Modular handler/middleware structure: all HTTP handlers and AppState are shared and testable
- [x] Global JWT authentication middleware (all routes except /iam/login)
- [x] Per-route RBAC/ABAC checks via extractor and AuthZService
- [x] Full integration and E2E test coverage for all endpoints
- [x] Endpoint versioning (if required)

## In Progress / Remaining
- [ ] RBAC: Role hierarchies (role inheritance)
- [ ] RBAC: Permission groups and metadata
- [ ] RBAC: User-role assignment/listing endpoints
- [ ] RBAC: Role-permission assignment/listing endpoints
- [ ] RBAC: List effective permissions for a user
- [ ] ABAC: Policy CRUD (create, update, delete, list)
- [ ] ABAC: Policy assignment to users/roles/resources
- [ ] ABAC: Support more condition operators (in, gt, lt, etc.)
- [ ] ABAC: Policy evaluation endpoint
- [ ] ABAC: Policy priorities/conflict resolution
- [ ] Harden refresh token rotation, add audit logging
- [ ] Add user registration, password change/reset endpoints

## Traceability
- All completed tasks are mapped to requirements in `.specs/requrements.md` and follow project rules. 
- API_MODE, HTTP_HOST, HTTP_PORT in `.env` control which APIs are enabled and their ports.
- Golden signals (latency, traffic, errors, success) are observable via OpenTelemetry tracing events and spans. 
- All endpoints are documented and secured in the OpenAPI/Swagger UI. 
- All endpoints (except /iam/login) are protected by JWT middleware and RBAC/ABAC checks. 
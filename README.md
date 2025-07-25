[![CI/CD](https://github.com/luzerz/rust-authentication-iam/actions/workflows/ci.yml/badge.svg)](https://github.com/luzerz/rust-authentication-iam/actions/workflows/ci.yml) [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=luzerz_rust-authentication-iam&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=luzerz_rust-authentication-iam) [![Coverage](https://sonarcloud.io/api/project_badges/measure?project=luzerz_rust-authentication-iam&metric=coverage)](https://sonarcloud.io/summary/new_code?id=luzerz_rust-authentication-iam) [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=luzerz_rust-authentication-iam&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=luzerz_rust-authentication-iam) [![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=luzerz_rust-authentication-iam&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=luzerz_rust-authentication-iam)
# Authentication Service (IAM)

A robust, production-grade Identity and Access Management (IAM) service written in Rust. Implements authentication, RBAC, and ABAC with JWT, OpenAPI docs, and high test coverage.

## Features
- User authentication with JWT (access & refresh tokens)
- Role-Based Access Control (RBAC)
- Attribute-Based Access Control (ABAC)
- CRUD for users, roles, permissions, ABAC policies
- Assign roles/permissions/policies to users and roles
- Token validation, refresh, and logout
- API versioning (`/v1/...`)
- OpenAPI/Swagger documentation
- Modular, testable, and extensible architecture

## Tech Stack
- **Rust** 1.88+
- **Axum** (HTTP API)
- **Postgres** (primary DB)
- **sqlx** (async DB toolkit)
- **bcrypt** (password hashing)
- **jsonwebtoken** (JWT)
- **utoipa** (OpenAPI/Swagger)
- **Docker** (local dev)

## Architecture
- Domain Driven Design (DDD)
- Hexagonal/Clean Architecture
- CQRS (Commands/Queries)
- Modular: `domain`, `application`, `infrastructure`, `interface`

## API Versioning
All endpoints are under `/v1/iam/...` (e.g., `/v1/iam/login`).

## Running Locally
1. **Clone the repo:**
   ```sh
   git clone <repo-url>
   cd authentication-service
   ```
2. **Set up environment:**
   - Copy `.env.example` to `.env` and fill in secrets (see below).
3. **Run Postgres (Docker):**
   ```sh
   docker-compose up -d
   # or use your own Postgres instance
   ```
4. **Run migrations:**
   ```sh
   # If using sqlx-cli
   sqlx migrate run
   ```
5. **Run the server:**
   ```sh
   cargo run
   ```
6. **View Swagger UI:**
   - Go to [http://localhost:8080/swagger](http://localhost:8080/swagger)

## Environment Variables
- `DATABASE_URL` - Postgres connection string
- `JWT_SECRET` - Secret for signing JWTs
- `HTTP_HOST`/`HTTP_PORT` - Server bind address
- `API_MODE` - Server Mode option: http, grpc (future implement), both

## API Documentation
- **Swagger UI:** `/swagger`
- **OpenAPI JSON:** `/openapi.json`
- All endpoints are tagged (`Auth`, `RBAC`, `ABAC`) and documented.

## Testing
- Run all tests:
  ```sh
  cargo test
  ```
- 90%+ coverage expected (unit, integration, E2E)

## Contribution
- Fork, branch, and PR as usual.
- Add/extend tests for all new features.

## RBAC/ABAC
- RBAC: Manage roles, permissions, assignments
- ABAC: Define policies with conditions, assign to users/roles
- All permission checks go through `AuthZService`

## CI/CD

This project is set up for CI/CD using GitHub Actions (or your preferred CI system).

Typical pipeline steps:
- **Build:** Ensure the project compiles on all supported platforms.
- **Test:** Run all unit, integration, and E2E tests (90%+ coverage required).
- **Lint/Format:** Enforce Rust formatting and linting (`cargo fmt`, `cargo clippy`).
- **Coverage:** Check code coverage and fail if below threshold.

A sample workflow is provided in `.github/workflows/ci.yml` (add or customize as needed).

## Project Tasks

### Completed
- Domain models: User, Role, Permission, Token (with business logic and unit tests)
- Application layer: Commands, handlers, services for login, token issuance, validation, refresh
- Infrastructure: PostgresUserRepository, PostgresRefreshTokenRepository
- Interface: Axum HTTP endpoints for /iam/login, /iam/validate-token, /iam/refresh-token, /iam/logout, /iam/roles, /iam/permissions, /iam/abac/policies, etc.
- Environment-based config (dotenvy for secrets, DB URL, API mode, host, and port)
- Docker Compose for Postgres
- Database migrations for users, roles, user_roles, refresh_tokens
- Manual E2E testing via curl/Postman
- DDD/hexagonal structure (domain, application, infrastructure, interface)
- Secure JWT/refresh token logic (with jti, DB storage, revocation, and tests for revoked tokens)
- OpenTelemetry tracing for all major flows (HTTP), with golden signal events (latency, traffic, errors, success) instrumented in all handlers
- OpenAPI/Swagger spec for all endpoints (all endpoints documented, secured, and described in Swagger UI)
- Modular handler/middleware structure: all HTTP handlers and AppState are shared and testable
- Global JWT authentication middleware (all routes except /iam/login)
- Per-route RBAC/ABAC checks via extractor and AuthZService
- Full integration and E2E test coverage for all endpoints

### In Progress / Remaining
- Endpoint versioning (if required)
- RBAC: Role hierarchies (role inheritance)
- RBAC: Permission groups and metadata
- RBAC: User-role assignment/listing endpoints
- RBAC: Role-permission assignment/listing endpoints
- RBAC: List effective permissions for a user
- ABAC: Policy CRUD (create, update, delete, list)
- ABAC: Policy assignment to users/roles/resources
- ABAC: Support more condition operators (in, gt, lt, etc.)
- ABAC: Policy evaluation endpoint
- ABAC: Policy priorities/conflict resolution
- Harden refresh token rotation, add audit logging
- Add user registration, password change/reset endpoints

## License
MIT  
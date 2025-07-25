[![CI/CD](https://github.com/luzerz/rust-authentication-iam/actions/workflows/ci.yml/badge.svg)](https://github.com/luzerz/rust-authentication-iam/actions/workflows/ci.yml) [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=luzerz_rust-authentication-iam&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=luzerz_rust-authentication-iam) [![Coverage](https://sonarcloud.io/api/project_badges/measure?project=luzerz_rust-authentication-iam&metric=coverage)](https://sonarcloud.io/summary/new_code?id=luzerz_rust-authentication-iam) [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=luzerz_rust-authentication-iam&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=luzerz_rust-authentication-iam) [![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=luzerz_rust-authentication-iam&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=luzerz_rust-authentication-iam)
# Authentication Service (IAM)

A comprehensive Identity and Access Management (IAM) service built with Rust, featuring authentication, authorization, and user management capabilities.

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

### Prerequisites

- Rust 1.88.0 or later
- PostgreSQL 15
- Docker (for development)

### Local Development

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd authentication-service
   ```

2. **Set up environment**
   ```bash
   cp .env.example .env
   # Edit .env with your database configuration
   ```

3. **Start the database**
   ```bash
   docker-compose up -d db
   ```

4. **Run migrations**
   ```bash
   cargo install sqlx-cli --no-default-features --features postgres
   sqlx migrate run
   ```

5. **Run the service**
   ```bash
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

### Run All Tests
```bash
cargo test
```

### Run Tests with Database
```bash
./scripts/run_tests_with_db.sh
```

### Run Specific Test Categories
```bash
# Unit tests only
cargo test --lib

# Integration tests
cargo test --test integration_tests

# Infrastructure tests with database
DATABASE_URL="postgres://test_user:test_pass@localhost:5433/test_auth_db" cargo test --test infrastructure_tests
```

## CI/CD Pipeline

The project includes a comprehensive CI/CD pipeline with:

- **Build**: Compilation and dependency management
- **Testing**: Unit and integration tests with database
- **Linting**: Code quality checks with Clippy
- **Formatting**: Code style validation with rustfmt
- **Coverage**: Test coverage analysis (60% minimum)
- **SonarCloud**: Code quality and security analysis

### Quality Gates

- **Coverage**: Minimum 60% test coverage
- **Code Quality**: SonarCloud quality gates
- **Security**: Automated security scanning
- **Performance**: Build and test performance monitoring

## Documentation

- [API Documentation](http://localhost:8080/swagger) - Interactive API docs
- [Test Database Setup](TEST_DATABASE_SETUP.md) - Database testing guide
- [CI/CD Setup](CI_CD_SETUP.md) - Complete pipeline documentation
- [SonarCloud Setup](SONARCLOUD_SETUP.md) - Quality analysis setup

## Architecture

### Domain Layer
- **User**: User entity with authentication and role management
- **Role**: Role-based access control implementation
- **Permission**: Fine-grained permission system
- **ABAC Policy**: Attribute-based access control policies

### Application Layer
- **AuthService**: Authentication logic
- **TokenService**: JWT token management
- **PasswordService**: Password hashing and verification
- **AuthZService**: Authorization logic

### Infrastructure Layer
- **PostgreSQL Repositories**: Database implementations
- **In-Memory Repositories**: Testing and development
- **Migration System**: Database schema management

### Interface Layer
- **HTTP Handlers**: REST API endpoints
- **gRPC Services**: High-performance RPC endpoints
- **Middleware**: Authentication and authorization middleware

## API Endpoints

### Authentication
- `POST /v1/iam/login` - User login
- `POST /v1/iam/validate-token` - Token validation
- `POST /v1/iam/refresh-token` - Token refresh
- `POST /v1/iam/logout` - User logout

### User Management
- `POST /v1/iam/roles` - Create role
- `GET /v1/iam/roles` - List roles
- `DELETE /v1/iam/roles/{id}` - Delete role
- `POST /v1/iam/roles/assign` - Assign role to user
- `POST /v1/iam/roles/remove` - Remove role from user

### Permission Management
- `POST /v1/iam/permissions` - Create permission
- `GET /v1/iam/permissions` - List permissions
- `DELETE /v1/iam/permissions/{id}` - Delete permission
- `POST /v1/iam/permissions/assign` - Assign permission to role
- `POST /v1/iam/permissions/remove` - Remove permission from role

### ABAC Policies
- `POST /v1/iam/abac/policies` - Create ABAC policy
- `GET /v1/iam/abac/policies` - List ABAC policies
- `DELETE /v1/iam/abac/policies/{id}` - Delete ABAC policy
- `POST /v1/iam/abac/assign` - Assign ABAC policy

## Development

### Code Quality

The project maintains high code quality standards:

- **Rustfmt**: Consistent code formatting
- **Clippy**: Linting and best practices
- **SonarCloud**: Code quality and security analysis
- **Test Coverage**: Comprehensive test suite

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

### Testing Strategy

- **Unit Tests**: Test individual components in isolation
- **Integration Tests**: Test component interactions
- **Database Tests**: Test with real PostgreSQL database
- **API Tests**: Test HTTP endpoints end-to-end

## Deployment

### Docker

```bash
# Build the image
docker build -t authentication-service .

# Run with environment variables
docker run -p 8080:8080 \
  -e DATABASE_URL=postgres://user:pass@host:5432/db \
  -e JWT_SECRET=your_secret \
  authentication-service
```

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

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For questions and support:
- Create an issue in the GitHub repository
- Check the documentation in the `/docs` directory
- Review the API documentation at `/swagger`  
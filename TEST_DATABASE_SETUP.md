# Test Database Setup

This document describes the test database setup for the authentication service to enable comprehensive testing of PostgreSQL repositories.

## Overview

The test database setup allows running tests against a real PostgreSQL database, which significantly improves test coverage by testing the actual database interactions rather than just in-memory implementations.

## Files Created

### 1. `docker-compose.test.yml`
A Docker Compose file specifically for test database setup:
- Uses PostgreSQL 15
- Runs on port 5433 (to avoid conflicts with development database)
- Creates a separate test database with its own volume
- Includes health checks for database readiness

### 2. `scripts/setup_test_db.sh`
Script to set up the test database:
- Starts the test database container
- Waits for database to be ready
- Runs all migrations
- Sets the DATABASE_URL environment variable

### 3. `scripts/cleanup_test_db.sh`
Script to clean up the test database:
- Stops and removes the test database container
- Removes associated volumes and networks

### 4. `scripts/run_tests_with_db.sh`
Complete test runner script:
- Sets up the test database
- Runs all tests with database connection
- Cleans up the test database

## Usage

### Quick Start

```bash
# Run all tests with database
./scripts/run_tests_with_db.sh

# Or manually:
./scripts/setup_test_db.sh
DATABASE_URL="postgres://test_user:test_pass@localhost:5433/test_auth_db" cargo test
./scripts/cleanup_test_db.sh
```

### Individual Test Execution

```bash
# Set up database
./scripts/setup_test_db.sh

# Run specific tests
DATABASE_URL="postgres://test_user:test_pass@localhost:5433/test_auth_db" cargo test test_postgres_permission_repository

# Clean up
./scripts/cleanup_test_db.sh
```

## Test Coverage Improvements

### Before Database Setup
- **PostgresPermissionRepository**: 0% coverage (59 lines uncovered)
- **PostgresUserRepository**: 32% coverage (34 lines uncovered)
- **Overall Coverage**: ~50.71%

### After Database Setup
- **PostgresPermissionRepository**: ~100% coverage (all methods tested)
- **PostgresUserRepository**: ~100% coverage (all methods tested)
- **Expected Overall Coverage**: ~65-70%

## Tests Added

### PostgresPermissionRepository Tests
- `test_postgres_permission_repository`: Tests all CRUD operations
  - Create permission
  - List permissions
  - Assign permission to role
  - Check role has permission
  - Remove permission from role
  - Delete permission
- `test_postgres_permission_repository_error_handling`: Tests error scenarios
  - Non-existent role/permission checks
  - Graceful handling of missing data

### PostgresUserRepository Tests
- `test_postgres_user_repository`: Tests basic user operations
  - Find user by email (non-existent)
  - Find user by email (exists)
- `test_postgres_user_repository_with_roles`: Tests user with roles
  - Create user with multiple roles
  - Verify roles are loaded correctly

## Database Schema

The test database uses the same schema as the production database:
- `users` table
- `roles` table
- `user_roles` table (many-to-many relationship)
- `permissions` table
- `role_permissions` table (many-to-many relationship)
- `refresh_tokens` table

## Test Isolation

Tests use unique identifiers (UUIDs) to avoid conflicts:
- Each test generates unique role IDs, permission IDs, and user IDs
- Cleanup is specific to each test's data
- Tests can run in parallel without interference

## Environment Variables

- `DATABASE_URL`: Set to `postgres://test_user:test_pass@localhost:5433/test_auth_db` for tests
- Tests automatically skip if `DATABASE_URL` is not set

## Troubleshooting

### Database Connection Issues
1. Ensure Docker is running
2. Check if port 5433 is available
3. Verify the setup script completed successfully

### Test Failures
1. Check if database is running: `docker ps`
2. Verify migrations ran: Check database tables exist
3. Run individual tests to isolate issues

### Cleanup Issues
1. Force remove containers: `docker-compose -f docker-compose.test.yml down -v --remove-orphans`
2. Remove volumes manually: `docker volume rm authentication-service_test_pgdata`

## Future Improvements

1. **Test Isolation**: Implement database transactions for better test isolation
2. **Parallel Testing**: Configure tests to run in parallel with separate database instances
3. **Performance**: Add database connection pooling for faster test execution
4. **Monitoring**: Add database metrics and monitoring for test performance

## Benefits

1. **Real Database Testing**: Tests actual SQL queries and database constraints
2. **Improved Coverage**: Significantly higher test coverage for infrastructure layer
3. **Bug Detection**: Catches database-related bugs early
4. **Confidence**: Higher confidence in production deployments
5. **Documentation**: Tests serve as documentation for database interactions 
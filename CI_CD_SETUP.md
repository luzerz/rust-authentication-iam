# CI/CD Setup with SonarCloud Integration

This document describes the complete CI/CD pipeline setup for the authentication service, including SonarCloud integration and test database configuration.

## Overview

The CI/CD pipeline includes:
- **Build**: Compilation and dependency management
- **Testing**: Unit tests with and without database
- **Linting**: Code quality checks with Clippy
- **Formatting**: Code style validation with rustfmt
- **Coverage**: Test coverage analysis with database
- **SonarCloud**: Code quality and security analysis

## CI/CD Pipeline Jobs

### 1. Build Job
- **Purpose**: Compile the project and cache dependencies
- **Triggers**: On push to main and pull requests
- **Dependencies**: None
- **Tools**: Rust toolchain, Cargo

### 2. Test Job
- **Purpose**: Run unit tests with database support
- **Triggers**: After successful build
- **Dependencies**: Build job
- **Services**: PostgreSQL 15 database
- **Tools**: sqlx CLI, Cargo test

### 3. Test-with-db Job
- **Purpose**: Run comprehensive tests with database integration
- **Triggers**: After successful build
- **Dependencies**: Build job
- **Services**: PostgreSQL 15 database
- **Tools**: sqlx CLI, Cargo test

### 4. Lint Job
- **Purpose**: Code quality checks with Clippy
- **Triggers**: After successful build
- **Dependencies**: Build job
- **Tools**: Clippy

### 5. Format Job
- **Purpose**: Code style validation
- **Triggers**: After successful build
- **Dependencies**: Build job
- **Tools**: rustfmt

### 6. Coverage Job
- **Purpose**: Generate test coverage reports
- **Triggers**: After successful tests
- **Dependencies**: Test and test-with-db jobs
- **Services**: PostgreSQL 15 database
- **Tools**: Tarpaulin, sqlx CLI
- **Output**: Coverage reports for Codecov and SonarCloud

### 7. SonarCloud Job
- **Purpose**: Code quality and security analysis
- **Triggers**: After successful tests and coverage
- **Dependencies**: Test, test-with-db, and coverage jobs
- **Services**: PostgreSQL 15 database
- **Tools**: SonarCloud Scanner, Tarpaulin
- **Output**: SonarCloud analysis results

## Database Integration

### PostgreSQL Service Configuration
```yaml
services:
  postgres:
    image: postgres:15
    env:
      POSTGRES_USER: test_user
      POSTGRES_PASSWORD: test_pass
      POSTGRES_DB: test_auth_db
    options: >-
      --health-cmd pg_isready
      --health-interval 10s
      --health-timeout 5s
      --health-retries 5
    ports:
      - 5433:5432
```

### Database Setup Steps
1. **Wait for Database**: Health check ensures database is ready
2. **Install sqlx CLI**: Required for migrations
3. **Run Migrations**: Apply database schema
4. **Run Tests**: Execute tests with database connection

## SonarCloud Integration

### Configuration
- **Organization**: luzerz
- **Project Key**: luzerz_rust-authentication-iam
- **Coverage Format**: Cobertura XML
- **Quality Gate**: Enabled with wait

### Coverage Settings
```properties
sonar.coverage.cobertura.reportPaths=target/sonar/cobertura.xml
sonar.coverage.exclusions=**/tests/**, **/examples/**, **/benches/**, **/migrations/**
sonar.test.inclusions=**/tests/**, **/*_test.rs, **/test_*.rs
```

### Quality Gates
- **Coverage**: Minimum 60% test coverage
- **Duplications**: Maximum 3% duplicated code
- **Maintainability**: A rating
- **Reliability**: A rating
- **Security**: A rating

## Environment Variables

### Required Secrets
- `SONAR_TOKEN`: SonarCloud authentication token
- `GITHUB_TOKEN`: GitHub authentication token (auto-provided)

### Environment Configuration
```yaml
env:
  CARGO_TERM_COLOR: always
  DATABASE_URL: postgres://test_user:test_pass@localhost:5433/test_auth_db
```

## Coverage Analysis

### Tools Used
- **Tarpaulin**: Rust-specific coverage tool
- **Output Format**: XML (Cobertura)
- **Coverage Threshold**: 60% minimum

### Coverage Reports
- **Codecov**: Public coverage dashboard
- **SonarCloud**: Integrated quality analysis
- **Local**: Available in CI artifacts

## Setup Instructions

### 1. SonarCloud Setup
1. Create SonarCloud account
2. Create new project for this repository
3. Get the project key and organization
4. Generate authentication token
5. Add `SONAR_TOKEN` to GitHub repository secrets

### 2. GitHub Secrets Configuration
```bash
# Add these secrets to your GitHub repository
SONAR_TOKEN=your_sonarcloud_token_here
```

### 3. Local Development
```bash
# Run tests with database locally
./scripts/run_tests_with_db.sh

# Run SonarCloud analysis locally
sonar-scanner
```

## Quality Metrics

### Code Quality
- **Maintainability**: Code complexity and structure
- **Reliability**: Bug detection and prevention
- **Security**: Security vulnerabilities detection
- **Coverage**: Test coverage percentage

### Coverage Targets
- **Overall**: 60% minimum
- **Critical Paths**: 80% minimum
- **Infrastructure**: 70% minimum

## Troubleshooting

### Common Issues

#### Database Connection Failures
```bash
# Check database health
docker ps
docker logs <postgres_container_id>

# Verify connection
pg_isready -h localhost -p 5433 -U test_user -d test_auth_db
```

#### SonarCloud Analysis Failures
1. Check `SONAR_TOKEN` secret
2. Verify project key in sonar-project.properties
3. Ensure coverage report exists
4. Check SonarCloud project settings

#### Coverage Report Issues
1. Verify Tarpaulin installation
2. Check database connection
3. Ensure tests run successfully
4. Verify XML output format

### Debug Commands
```bash
# Run specific job locally
cargo test --all --release

# Generate coverage locally
cargo tarpaulin --out Xml --all --release

# Check SonarCloud configuration
sonar-scanner -Dsonar.projectKey=test
```

## Performance Optimization

### Caching Strategy
- **Cargo Registry**: Cached between runs
- **Target Directory**: Cached for faster builds
- **Dependencies**: Cached based on Cargo.lock

### Parallel Execution
- **Independent Jobs**: Build, lint, format run in parallel
- **Dependent Jobs**: Tests and coverage run sequentially
- **Database Services**: Shared across dependent jobs

## Monitoring and Alerts

### Quality Gates
- **Automatic**: SonarCloud quality gates
- **Manual**: Coverage threshold checks
- **Notifications**: GitHub status checks

### Metrics Tracking
- **Coverage Trends**: Historical coverage data
- **Quality Trends**: Code quality metrics over time
- **Performance**: Build and test execution times

## Future Enhancements

### Planned Improvements
1. **Parallel Testing**: Multiple database instances
2. **Performance Testing**: Load testing integration
3. **Security Scanning**: Additional security tools
4. **Deployment Pipeline**: Automated deployment stages

### Advanced Features
1. **Differential Coverage**: Coverage for changed files only
2. **Custom Quality Gates**: Project-specific quality rules
3. **Performance Monitoring**: Build time optimization
4. **Security Scanning**: SAST/DAST integration 
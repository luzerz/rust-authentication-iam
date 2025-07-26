# Makefile for Authentication Service

.PHONY: help build build-dev run run-dev stop clean test test-db docker-build docker-run docker-stop docker-clean

# Default target
help:
	@echo "Available commands:"
	@echo "  build        - Build the application"
	@echo "  build-dev    - Build the application in development mode"
	@echo "  run          - Run the application locally"
	@echo "  run-dev      - Run the application with hot reloading"
	@echo "  stop         - Stop the application"
	@echo "  clean        - Clean build artifacts"
	@echo "  test         - Run unit tests"
	@echo "  test-db      - Run tests with database"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Run with Docker Compose"
	@echo "  docker-stop  - Stop Docker containers"
	@echo "  docker-clean - Clean Docker resources"

# Local development
build:
	cargo build --release

build-dev:
	cargo build

run:
	cargo run --release

run-dev:
	cargo watch -x run

stop:
	@echo "Stopping local application..."
	@pkill -f authentication_service || true

clean:
	cargo clean

# Testing
test:
	unset DATABASE_URL && cargo test --lib --bins --tests --workspace

test-db:
	./scripts/run_tests_with_db.sh

# Docker commands
docker-build:
	docker build -t authentication-service:latest .

docker-build-dev:
	docker build -f Dockerfile.dev -t authentication-service:dev .

docker-run:
	docker-compose -f docker-compose.prod.yml up -d

docker-run-dev:
	docker-compose -f docker-compose.dev.yml up -d

docker-run-full:
	docker-compose -f docker-compose.prod.yml --profile proxy up -d

docker-stop:
	docker-compose -f docker-compose.prod.yml down
	docker-compose -f docker-compose.dev.yml down

docker-clean:
	docker-compose -f docker-compose.prod.yml down -v
	docker-compose -f docker-compose.dev.yml down -v
	docker system prune -f

# Database commands
db-setup:
	./scripts/setup_test_db.sh

db-cleanup:
	./scripts/cleanup_test_db.sh

# Linting and formatting
lint:
	cargo clippy --all -- -D warnings

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

# Security
security-check:
	cargo audit

# Production deployment
deploy-prod:
	@echo "Deploying to production..."
	docker-compose -f docker-compose.prod.yml up -d --build

deploy-dev:
	@echo "Deploying to development..."
	docker-compose -f docker-compose.dev.yml up -d --build

# Monitoring
logs:
	docker-compose -f docker-compose.prod.yml logs -f

logs-dev:
	docker-compose -f docker-compose.dev.yml logs -f

# Health checks
health:
	curl -f http://localhost:8080/health || echo "Service is not healthy"

health-docker:
	docker-compose -f docker-compose.prod.yml exec auth_service curl -f http://localhost:8080/health || echo "Service is not healthy" 
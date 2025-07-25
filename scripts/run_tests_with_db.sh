#!/bin/bash

# Test runner script with database setup
set -e

echo "=== Running tests with database ==="

# Setup test database
echo "Setting up test database..."
./scripts/setup_test_db.sh

# Set test database URL for tests
export DATABASE_URL="postgres://test_user:test_pass@localhost:5433/test_auth_db"

# Run tests
echo "Running tests..."
cargo test

# Cleanup
echo "Cleaning up test database..."
./scripts/cleanup_test_db.sh

echo "=== Tests completed successfully ===" 
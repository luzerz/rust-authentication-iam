#!/bin/bash

# Test database setup script
set -e

echo "Setting up test database..."

# Start test database
echo "Starting test database..."
docker compose -f docker-compose.test.yml up -d test-db

# Wait for database to be ready
echo "Waiting for database to be ready..."
until docker compose -f docker-compose.test.yml exec -T test-db pg_isready -U test_user -d test_auth_db; do
  echo "Database is not ready yet. Waiting..."
  sleep 2
done

echo "Database is ready!"

# Set test database URL
export DATABASE_URL="postgres://test_user:test_pass@localhost:5433/test_auth_db"

# Run migrations
echo "Running migrations..."
sqlx migrate run --database-url "$DATABASE_URL"

echo "Test database setup complete!"
echo "Test database URL: $DATABASE_URL" 
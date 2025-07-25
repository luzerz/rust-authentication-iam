#!/bin/bash

# Test database cleanup script
set -e

echo "Cleaning up test database..."

# Stop and remove test database
echo "Stopping test database..."
docker compose -f docker-compose.test.yml down -v

echo "Test database cleanup complete!" 
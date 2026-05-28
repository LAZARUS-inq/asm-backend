#!/usr/bin/env bash
# Run once after first docker-compose up to create DB tables
set -e

echo "Running Alembic migrations..."
alembic upgrade head
echo "Done."

#!/bin/sh
set -e

echo "Waiting for Postgres..."
python -c "
import os
import time
from urllib.parse import urlparse
import psycopg2

database_url = os.getenv('DATABASE_URL')
if not database_url:
    raise SystemExit('DATABASE_URL is required')

parsed = urlparse(database_url.replace('+asyncpg', '').replace('+psycopg2', ''))
host = parsed.hostname
port = parsed.port
user = parsed.username
password = parsed.password
dbname = (parsed.path or '').lstrip('/')

if not all([host, port, user, password, dbname]):
    raise SystemExit('DATABASE_URL must include host, port, username, password, and database name')

deadline = time.time() + 60
last_error = None

while time.time() < deadline:
    try:
        conn = psycopg2.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            dbname=dbname,
        )
        conn.close()
        print('Postgres is ready')
        break
    except Exception as exc:
        last_error = exc
        print(f'Postgres not ready yet: {exc}')
        time.sleep(2)
else:
    raise SystemExit(f'Postgres did not become ready in time: {last_error}')
"

echo "Running migrations..."
alembic upgrade head
echo "Migrations complete"

echo "Starting application..."
if [ "$#" -eq 0 ]; then
  exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}" --proxy-headers --forwarded-allow-ips='*'
fi

exec "$@"

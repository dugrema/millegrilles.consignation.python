#!/usr/bin/env bash

EXIT_CODE=0

echo "[OK] Demarrage script de backup de redmine.postgres"

# Attente postgres
pg_dump redmine -U redmine | xz - > /tmp/backup.redmine.postgres.xz
EXIT_CODE=$?

echo "[OK] Fin du script de backup de redmine.postgres"

echo "{\"exit\": $EXIT_CODE}"
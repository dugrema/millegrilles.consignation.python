#!/usr/bin/env bash

EXIT_CODE=0

echo "[OK] Demarrage script d'installation de shared.postgres"
su -c "psql -f /tmp/apps/script.postgres.redmine.sql" postgres
echo "[OK] Fin du script d'installation de postgres"

echo "{\"exit\": $EXIT_CODE}"
#!/usr/bin/env bash

EXIT_CODE=0

echo "[OK] Demarrage script d'installation de shared.postgres"

# Attente postgres
sleep 5

echo "Script Redmine"
su -c "psql -f /tmp/apps/script.postgres.redmine.sql" postgres

echo "Script Blynk"
su -c "psql -f /tmp/apps/script.postgres.blynk.sql" postgres

echo "[OK] Fin du script d'installation de postgres"

echo "{\"exit\": $EXIT_CODE}"
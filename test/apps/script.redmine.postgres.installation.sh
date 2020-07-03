#!/usr/bin/env bash

EXIT_CODE=0

echo "[OK] Demarrage script d'installation de redmine.postgres"

# Attente postgres
sleep 5

# Injecter le mot de passe redmine dans le script pour creer le compte
SCRIPT_TMP=/tmp/script_redmine_postgres.sql
echo "\set psw '$PASSWORD'" > $SCRIPT_TMP
cat script.redmine.postgres.installation >> $SCRIPT_TMP
chmod 600 $SCRIPT_TMP
chown postgres $SCRIPT_TMP

# Executer le compte
su -c "psql -f $SCRIPT_TMP" postgres
EXIT_CODE=$?

# Cleanup
rm -f $SCRIPT_TMP

echo "[OK] Fin du script d'installation de redmine.postgres"

echo "{\"exit\": $EXIT_CODE}"

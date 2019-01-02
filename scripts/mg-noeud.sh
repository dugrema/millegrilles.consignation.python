#!/usr/bin/env bash

FICHIER_CONFIG=/usr/local/etc/mg-appareils.conf
SCRIPT_PYTHON=/usr/local/bin/mgraspberrypi.py
COMMAND=$1

if [ ! -f $FICHIER_CONFIG ]; then
  echo "Le fichier de configuration est introuvable: $FICHIER_CONFIG"
  exit 1
fi

source $FICHIER_CONFIG

PARAMS=""

# Ajouter parametre pour senseur APCUPSD au besoin
if [ ! -z $APCUPSD_NO ]; then
  PARAMS="$PARAMS --apcupsd $APCUPSD_NO"
fi

echo "Commande: $SCRIPT_PYTHON $COMMAND $PARAMS"
$SCRIPT_PYTHON $COMMAND $PARAMS

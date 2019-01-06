#!/usr/bin/env bash

FICHIERS_CERTS_ROOT=/usr/local/etc/millegrilles/certs/

if [ -d $FICHIERS_CERTS_ROOT ]; then
  echo "Copier plus recents certificats root MilleGrilles"
  mkdir -p certs
  cp -f $FICHIERS_CERTS_ROOT/*.pem certs/
fi

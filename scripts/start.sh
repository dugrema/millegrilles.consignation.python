#!/bin/bash

GITPATH=/home/mathieu/git
CONSIGNATION_PYTHON=$GITPATH/millegrilles.consignation.python
PYTHONPATH=$CONSIGNATION_PYTHON

WEBROOT=/home/mathieu/webroot/build

export PYTHONPATH

# export MG_CONSIGNATIONFICHIERS_HOST=mg-dev4.maple.maceroc.com
# export MG_CONSIGNATIONFICHIERS_PORT=3021
# export MG_MQ_HOST=mg-dev4
# export CERT_DUREE=30
# export CERT_DUREE_HEURES=0

python3 $CONSIGNATION_PYTHON/millegrilles/monitor/ServiceMonitor.py --dev --debug \
  --secrets /var/opt/millegrilles/secrets \
  --webroot $WEBROOT

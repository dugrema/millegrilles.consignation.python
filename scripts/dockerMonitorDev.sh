#!/bin/bash

demarrer_servicemonitor() {

  #  --env CERT_DUREE=0 --env CERT_DUREE_HEURES=1 \

  PARAMS_DUREE=""
  if [ -n $CERT_DUREE ]; then
    PARAMS_DUREE="$PARAMS_DUREE --env CERT_DUREE=$CERT_DUREE"
  fi
  if [ -n $CERT_DUREE_HEURES ]; then
    PARAMS_DUREE="$PARAMS_DUREE --env CERT_DUREE_HEURES=$CERT_DUREE_HEURES"
  fi

  sudo docker service create \
    --name monitor \
    --hostname monitor \
    --env MG_MONGO_HOST=mongo $PARAMS_DUREE \
    --network millegrille_net \
    --mount type=bind,source=/run/docker.sock,destination=/run/docker.sock \
    --mount type=bind,source=$MILLEGRILLES_VAR,destination=/var/opt/millegrilles \
    --mount type=bind,source=/home/mathieu/webroot/build,destination=/mnt/webroot \
    --mount type=volume,source=millegrille-secrets,destination=/var/opt/millegrilles_secrets \
    --user root:115 \
    ${SERVICEMONITOR_IMAGE} \
    -m millegrilles.monitor.ServiceMonitor --info \
    --webroot /mnt/webroot/
}

MILLEGRILLES_VAR=/var/opt/millegrilles
SERVICEMONITOR_IMAGE="docker.maceroc.com/millegrilles_consignation_python_main:armv7l_1.39.8"

demarrer_servicemonitor

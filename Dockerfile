# Image pour scripts python millegrilles.transactionet certains domaines.
# Note: les fichiers doivent avoir ete copies dans le repertoire courant sous src/

FROM docker.maceroc.com/millegrilles_consignation_python:1.16.2

ENV SRC_FOLDER=/opt/millegrilles/build/src

COPY scripts/ $BUILD_FOLDER/scripts
COPY ./ $SRC_FOLDER/MilleGrilles.consignation.python/

# Copier les fichiers templates et ressources html statiques
COPY html/ $BUNDLE_FOLDER/html

RUN $BUILD_FOLDER/scripts/setup.sh

USER mg_python

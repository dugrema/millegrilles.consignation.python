# Image pour scripts python millegrilles.
# Note: les fichiers doivent avoir ete copies dans le repertoire courant sous src/

FROM python:3.8

ENV BUILD_FOLDER=/opt/millegrilles/build \
    BUNDLE_FOLDER=/opt/millegrilles/dist \
    PYTHONPATH=/opt/millegrilles/dist \
    MG_DOMAINES_JSON=$BUNDLE_FOLDER/domaines.json

COPY certs/ $MG_CERTS_FOLDER
COPY scripts/ $BUILD_FOLDER/scripts
COPY requirements.txt $BUILD_FOLDER

RUN $BUILD_FOLDER/scripts/setup.sh

WORKDIR /opt/millegrilles/dist
ENTRYPOINT ["python3"]

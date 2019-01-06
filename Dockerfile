# Image pour scripts python millegrilles.transaction
# Note: les fichiers doivent avoir ete copies dans le repertoire courant sous src/

FROM python:3.7

ENV BUILD_FOLDER=/opt/millegrilles/build \
    BUNDLE_FOLDER=/opt/millegrilles/dist \
    SRC_FOLDER=/opt/millegrilles/build/src \
    PYTHONPATH=/opt/millegrilles/dist \
    MG_MQ_HOST=mq \
    MG_MONGO_HOST=mongo \
    MG_DOMAINES_JSON=$BUNDLE_FOLDER/domaines.json \
    MG_CERTS_FOLDER=/usr/local/etc/millegrilles/certs

COPY certs $MG_CERTS_FOLDER/
COPY scripts/ $BUILD_FOLDER/scripts
COPY ./ $SRC_FOLDER/MilleGrilles.consignation.python/

RUN $BUILD_FOLDER/scripts/setup.sh

WORKDIR /opt/millegrilles/dist
ENTRYPOINT ["python3"]
CMD ["demarrer_transaction.py"]

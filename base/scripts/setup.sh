#!/bin/bash

# Fichier de setup pour container Docker (doit etre execute dans le container via Dockerfile)

REQ_FILE=$BUILD_FOLDER/requirements.txt
if [ ! -f $REQ_FILE ]; then
    echo Fichier $REQ_FILE introuvable

    echo Repertoire git: $GIT_FOLDER
    echo Repertoire src: $SRC_FOLDER

    ls -la $SRC_FOLDER
    ls -la $GIT_FOLDER
    exit 1
fi

echo "Installer dependances Python avec pip: fichier $REQ_FILE"
# http_proxy=http://192.168.1.28:8000 pip3 install --no-cache-dir -r $REQ_FILE
pip3 install --no-cache-dir -r $REQ_FILE

# Fix pymongo, erreur cannot import abc (issue #305)
pip3 uninstall -y bson
pip3 uninstall -y pymongo
pip3 install pymongo

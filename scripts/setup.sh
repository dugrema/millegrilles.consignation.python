#!/bin/bash

# Fichier de setup pour container Docker (doit etre execute dans le container via Dockerfile)

GIT_NAME=MilleGrilles.consignation.python
GIT_FOLDER=$SRC_FOLDER/$GIT_NAME

echo "Installer dependances Python avec pip: fichier $GIT_FOLDER/requirements.txt"
http_proxy=http://192.168.1.28:8000 pip install --no-cache-dir -r $GIT_FOLDER/requirements.txt

echo Installer package MilleGrilles.consignation
cd $GIT_FOLDER
python3 setup.py install

echo "Copier script demarrer dans $BUNDLE_FOLDER"
mkdir -p $BUNDLE_FOLDER
cp $GIT_FOLDER/scripts/demarrer*.py $BUNDLE_FOLDER

cd $BUNDLE_FOLDER
rm -rf $BUILD_FOLDER

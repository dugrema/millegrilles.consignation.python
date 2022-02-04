#!/bin/bash

# Fichier de setup pour container Docker (doit etre execute dans le container via Dockerfile)

GIT_NAME=millegrilles.consignation.python
GIT_FOLDER=$SRC_FOLDER/$GIT_NAME

# Note: les requirements doivent etre installes dans l'image Python de base
#       (MilleGrilles.consignation/dockerfiles/millegrilles-python)
#REQ_FILE=$GIT_FOLDER/requirements.txt
#if [ ! -f $REQ_FILE ]; then
#    echo Fichier $REQ_FILE introuvable
#
#    echo Repertoire git: $GIT_FOLDER
#    echo Repertoire src: $SRC_FOLDER
#
#    ls -la $SRC_FOLDER
#    ls -la $GIT_FOLDER
#    exit 1
#fi
#
#echo "Installer dependances Python avec pip: fichier $REQ_FILE"
#pip3 install --no-cache-dir -r $REQ_FILE

echo Installer package MilleGrilles.consignation
cd $GIT_FOLDER
python3 setup.py install

echo "Copier script demarrer dans $BUNDLE_FOLDER"
mkdir -p $BUNDLE_FOLDER
cp $GIT_FOLDER/scripts/demarrer*.py $BUNDLE_FOLDER

# Copier fichier de reference pour la configuration de tous les domaines
cp $GIT_FOLDER/scripts/*.json $BUNDLE_FOLDER

groupadd -g 980 millegrilles

useradd -r -u 980 -g millegrilles mg_python
mkdir -p /opt/millegrilles/dist/secure/pki
chown mg_python:millegrilles /opt/millegrilles/dist/secure/pki
chmod 770 /opt/millegrilles/dist/secure/pki

useradd -r -u 981 -g millegrilles maitredescles
mkdir -p /opt/millegrilles/dist/secure/maitredescles
chown mg_python:root /opt/millegrilles/dist/secure/maitredescles
chmod 700 /opt/millegrilles/dist/secure/maitredescles

cd $BUNDLE_FOLDER
rm -rf $BUILD_FOLDER

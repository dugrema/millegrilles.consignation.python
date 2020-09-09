# Script de test pour transmettre message de transaction


# Script de test pour transmettre message de transaction

import datetime
import time
import json

from millegrilles.dao.ConfigurationDocument import ContexteRessourcesDocumentsMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles import Constantes
from millegrilles.Constantes import ConstantesDomaines, ConstantesBackup
from millegrilles.domaines.Principale import ConstantesPrincipale
from threading import Thread, Event


contexte = ContexteRessourcesDocumentsMilleGrilles()
contexte.initialiser()


class MessagesSample(BaseCallback):

    def __init__(self):
        super().__init__(contexte)

    def extraction_donnees_senseur(self):
        collection = self.contexte.document_dao.get_collection('millegrilles.domaines.SenseursPassifs')

        filter = {
            '.'.join([Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE, Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]): 'millegrilles.domaines.SenseursPassifs.lecture',
            '_evenements.9YsdG8FxZKaRykfSt2j3GKLpfP27UCTLeDevfK.transaction_traitee': {'$exists': True},
            'uuid_senseur': '5c7f7576ec2411e98c2d00155d011f09',
        }

        # Sonde 1 0fb0f962ec2511e98c2d00155d011f09
        # Sonde 2 5c7f7576ec2411e98c2d00155d011f09
        # Barometre b931082eec2511e98c2d00155d011f09

        uuid_trouves = set()

        project = {
            'senseurs': 1, 'timestamp': 1, 'uuid_senseur': 1
        }

        with open('/home/mathieu/tmp/output_climatdubrasseur.csv', 'w') as fichier:

            fichier.write('Date;TempSonde;TempPiece;HumPiece\n')

            curseur = collection.find(filter, project)
            for lecture in curseur:

                uuid_senseur = lecture['uuid_senseur']
                if not uuid_senseur in uuid_trouves:
                    print("UUID Senseur : %s" % uuid_senseur)
                    uuid_trouves.add(uuid_senseur)

                senseurs = dict()
                for senseur in lecture['senseurs']:
                    type_senseur = senseur.get('adresse') or senseur.get('type')
                    if not type_senseur:
                        continue
                    senseurs[type_senseur] = senseur

                sonde = senseurs.get('28eadb7997110375') or senseurs.get('28a6c97997110382')
                piece = senseurs.get('th')
                piece_temp = None
                piece_hum = None

                if sonde:
                    sonde = sonde.get('temperature')

                if piece:
                    piece_temp = piece.get('temperature')
                    piece_humidite = piece.get('humidite')

                timestamp_lecture = lecture['timestamp']
                date = datetime.datetime.fromtimestamp(timestamp_lecture)
                date_str = date.strftime('%Y/%m/%d %H:%M')
                if sonde or piece_temp or piece_hum:
                    fichier.write("%s;%s;%s;%s\n" % (date_str, sonde, piece_temp, piece_humidite))

    def executer(self):
        sample.extraction_donnees_senseur()


# --- MAIN ---
sample = MessagesSample()
sample.executer()
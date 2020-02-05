# Script de test pour transmettre message de transaction
import datetime, time

from millegrilles import Constantes
from millegrilles.Constantes import SenseursPassifsConstantes
from millegrilles.dao.ConfigurationDocument import ContexteRessourcesDocumentsMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from threading import Event

from millegrilles.util.JSONEncoders import MongoJSONEncoder

import json

contexte = ContexteRessourcesDocumentsMilleGrilles()
contexte.initialiser()


class RequeteMongo(BaseCallback):

    def __init__(self):
        super().__init__(contexte)
        self.contexte.message_dao.register_channel_listener(self)
        self.generateur = GenerateurTransaction(self.contexte)

        self.queue_name = None

        self.channel = None
        self.event_recu = Event()
        self.collection_transactions = self.contexte.document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM)

        self.temps_debut_rapport = datetime.datetime(year=2020, month=1, day=1)
        self.temps_fin_rapport = datetime.datetime(year=2020, month=2, day=1)

        self.filtre = {
            'en-tete.domaine': SenseursPassifsConstantes.TRANSACTION_DOMAINE_LECTURE,
            # 'uuid_senseur': {'$in': ['731bf65cf35811e9b135b827eb9064af']},
            SenseursPassifsConstantes.TRANSACTION_DATE_LECTURE: {
                '$gte': self.temps_debut_rapport.timestamp(),
                '$lt': self.temps_fin_rapport.timestamp(),
            },
        }

        self.regroupement_periode = {
            'year': {'$year': '$_evenements._estampille'},
            'month': {'$month': '$_evenements._estampille'},
            'day': {'$dayOfMonth': '$_evenements._estampille'},
            'hour': {'$hour': '$_evenements._estampille'},
        }

        self._regroupement_elem_numeriques = [
            # 'temperature', 'humidite', 'pression', 'millivolt', 'reserve'
            'temperature'
        ]

        # self._accumulateurs = ['max', 'min', 'avg']
        self._accumulateurs = ['avg']

        self.hint = {'_evenements._estampille': -1}

    def on_channel_open(self, channel):
        # Enregistrer la reply-to queue
        self.channel = channel
        channel.queue_declare(durable=True, exclusive=True, callback=self.queue_open_local)

    def queue_open_local(self, queue):
        self.queue_name = queue.method.queue
        print("Queue: %s" % str(self.queue_name))

        self.channel.basic_consume(self.callbackAvecAck, queue=self.queue_name, no_ack=False)
        self.executer()

    def run_ioloop(self):
        self.contexte.message_dao.run_ioloop()

    def deconnecter(self):
        self.contexte.message_dao.deconnecter()

    def traiter_message(self, ch, method, properties, body):
        print("Message recu, correlationId: %s" % properties.correlation_id)
        message = json.loads(str(body, 'utf-8'))
        print(json.dumps(message, indent=4))

    def requete_filtre_1(self):
        curseur_resultat = self.collection_transactions.find(self.filtre).limit(10)
        resultats = list()
        for resultat in curseur_resultat:
            resultats.append({
                'uuid_senseur': resultat['uuid_senseur'],
                'timestamp': resultat['timestamp'],
                'senseurs': resultat['senseurs'],
            })

        print(json.dumps(resultats, indent=2))

    def requete_aggr_1(self):
        regroupement = {
            '_id': {
                'uuid_senseur': '$uuid_senseur',
                'appareil_type': '$senseurs.type',
                'appareil_adresse': '$senseurs.adresse',
                'timestamp': {
                    '$dateFromParts': self.regroupement_periode
                },
            },
        }

        for elem_regroupement in self._regroupement_elem_numeriques:
            for accumulateur in self._accumulateurs:
                key = '%s_%s' % (elem_regroupement, accumulateur)
                regroupement[key] = {'$%s' % accumulateur: '$senseurs.%s' % elem_regroupement}

        operation = [
            {'$match': self.filtre},
            {'$unwind': '$senseurs'},
            {'$group': regroupement},
        ]

        curseur_resultat = self.collection_transactions.aggregate(operation, hint=self.hint)

        resultats = list()
        for resultat in curseur_resultat:
            resultats.append(resultat)

        print(json.dumps(resultats, cls=MongoJSONEncoder, indent=2))
        return resultats

    def projeter_rapport(self):
        resultats = self.requete_aggr_1()

        colonnes = set()
        rangees = dict()
        for resultat in resultats:
            id_result = resultat['_id']
            if id_result.get('appareil_adresse') is not None:
                colonne = id_result['uuid_senseur'] + '/' + id_result['appareil_adresse']
            else:
                colonne = id_result['uuid_senseur'] + '/' + id_result['appareil_type']

            timestamp = id_result['timestamp']
            rangee = rangees.get(timestamp)
            if rangee is None:
                rangee = dict()
                rangees[timestamp] = rangee

            for donnee in resultat.keys():
                if donnee != '_id' and resultat.get(donnee) is not None:
                    colonne_donnee = colonne + '/' + donnee
                    colonnes.add(colonne_donnee)
                    rangee[colonne_donnee] = resultat[donnee]

        colonnes = sorted(colonnes)
        print("Colonnes: " + str(colonnes))

        for timestamp in sorted(rangees.keys()):
            ligne = "Timestamp %s : " % (timestamp)
            rangee = rangees[timestamp]
            for colonne in colonnes:
                if rangee.get(colonne) is not None:
                    ligne = ligne + ', ' + colonne + "=" + str(rangee[colonne])
            print("Timestamp %s : %s" % (timestamp, ligne))

    def executer(self):
        self.projeter_rapport()


# --- MAIN ---
sample = RequeteMongo()

# TEST

# FIN TEST
sample.event_recu.wait(2)
sample.deconnecter()


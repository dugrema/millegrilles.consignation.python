# Script de test pour transmettre message de transaction


# Script de test pour transmettre message de transaction

import datetime
import time

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles import Constantes
from millegrilles.domaines.Principale import ConstantesPrincipale
from threading import Thread, Event


contexte = ContexteRessourcesMilleGrilles()
contexte.initialiser()


class MessagesSample(BaseCallback):

    def __init__(self):
        super().__init__(contexte)
        self.contexte.message_dao.register_channel_listener(self)
        self.generateur = GenerateurTransaction(self.contexte)

        self.fichier_fuuid = "39c1e1b0-b6ee-11e9-b0cd-d30e8fab842j"

        self.channel = None
        self.event_recu = Event()

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
        print(body)

    def transaction_nouvelle_version_metadata(self):
        transaction = {
            "fuuid": self.fichier_fuuid,
            "securite": "2.prive",
            "nom": "ExplorationGrosFichiers10.txt",
            "taille": 5478,
            "sha256": "739291ef2f7f3e0f945712112df9a62aeb2642d3828551f9fa3c95449a415e31",
            "mimetype": "test/plain",
            "reception": {
                "methode": "coupdoeil",
                "noeud": "public1.maple.mdugre.info"
            },
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.nouvelleVersion.metadata',
            reply_to=self.queue_name, correlation_id='efgh')

        print("Envoi metadata: %s" % enveloppe_val)
        return enveloppe_val

    def transmettre_lecture(self):
        temps_lecture = datetime.datetime.now()
        # temps_lecture_ajuste = temps_lecture + datetime.timedelta(hours=4)

        senseurs = [
            # {
            #     "humidite": 31.6,
            #     "temperature": 26,
            #     "type": "am2302",
            # },
            # {
            #     "humidite": 20,
            #     "temperature": 27,
            #     "type": "th",
            # },
            {
                "pression": 99.7,
                "temperature": 38,
                "type": "tp",
            },
            {
                "temperature": 52.1,
                "type": "onewire/temperature",
                "adresse": '2854ab799711030c'
            },
            {
                "temperature": 32.1,
                "type": "onewire/temperature",
                "adresse": '3854ab799711030c'
            },
            {
                "temperature": -24.9,
                "type": "onewire/temperature",
                "adresse": '4854ab799711030c'
            },
            {
                "temperature": None,
                "type": "tpvide",
            },
            {
                "temperature": None,
                "type": "battery",
            },
            {
                "alerte": 0,
                "millivolt": 4047,
                "reserve": 92,
                "type": "batterie"
            }

        ]

        message_dict = dict()
        message_dict['uuid_senseur'] = '514951f2f43211e99259b827eb53ee51'
        message_dict['noeud'] = 'domaine_SenseursPassifs'
        message_dict['timestamp'] = int(temps_lecture.timestamp())
        message_dict['senseurs'] = senseurs

        enveloppe_val = self.generateur.soumettre_transaction(
            message_dict, 'millegrilles.domaines.SenseursPassifs.lecture',
            reply_to=self.queue_name, correlation_id='efgh')

        print("Sent: %s" % enveloppe_val)

    def changer_nom(self):
        temps_lecture = datetime.datetime.now()
        # temps_lecture_ajuste = temps_lecture + datetime.timedelta(hours=4)

        message_dict = {
            'senseur': 5,
            'noeud': 'domaine_SenseursPassifs',
            'location': "Bazaar"
        }

        enveloppe_val = self.generateur.soumettre_transaction(
            message_dict,
            'millegrilles.domaines.SenseursPassifs.changementAttributSenseur',
            reply_to=self.queue_name,
            correlation_id='efgh'
        )

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def supprimer_senseur(self):
        temps_lecture = datetime.datetime.now()
        # temps_lecture_ajuste = temps_lecture + datetime.timedelta(hours=4)

        message_dict = {
            'senseurs': [6, 7],
            'noeud': 'domaine_SenseursPassifs',
        }

        enveloppe_val = self.generateur.soumettre_transaction(
            message_dict,
            'millegrilles.domaines.SenseursPassifs.suppressionSenseur',
            reply_to=self.queue_name,
            correlation_id='efgh'
        )

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def requete_profil_usager(self):
        requete_profil = {
            'filtre': {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPrincipale.LIBVAL_PROFIL_USAGER,
            }
        }
        requetes = {'requetes': [requete_profil]}
        enveloppe_requete = self.generateur.transmettre_requete(
            requetes, 'millegrilles.domaines.Principale', reply_to=self.queue_name, correlation_id='abcd-1234')

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def commande_generer_rapport_hebdomadaire(self):
        commande = {
            'senseurs': ['731bf65cf35811e9b135b827eb9064af'],
        }
        enveloppe_requete = self.generateur.transmettre_commande(
            commande, 'commande.millegrilles.domaines.SenseursPassifs.rapportHebdomadaire',
            exchange=Constantes.DEFAUT_MQ_EXCHANGE_MIDDLEWARE,
            reply_to=self.queue_name, correlation_id='abcd-1234')

        print("Envoi commande: %s" % enveloppe_requete)
        return enveloppe_requete

    def executer(self):
        sample.commande_generer_rapport_hebdomadaire()


# --- MAIN ---
sample = MessagesSample()

# TEST

# FIN TEST
sample.event_recu.wait(10)
sample.deconnecter()
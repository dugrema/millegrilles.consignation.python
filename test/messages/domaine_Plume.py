# Script de test pour transmettre message de transaction
import datetime, time

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesPlume
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from threading import Event

import json

contexte = ContexteRessourcesMilleGrilles()
contexte.initialiser()


class MessagesSample(BaseCallback):

    def __init__(self):
        super().__init__(contexte)
        self.contexte.message_dao.register_channel_listener(self)
        self.generateur = GenerateurTransaction(self.contexte)

        self.queue_name = None

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
        message = json.loads(str(body, 'utf-8'))
        print(json.dumps(message, indent=4))

    def requete_liste(self):
        requete_document = {
            'filtre': {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPlume.LIBVAL_PLUME,
                ConstantesPlume.LIBELLE_DOC_CATEGORIES: {'$in': ['cat1']},
            },
            'sort': [(Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION, -1)],
            'projection': {
                ConstantesPlume.LIBELLE_DOC_PLUME_UUID: 1,
                ConstantesPlume.LIBELLE_DOC_CATEGORIES: 1,
                ConstantesPlume.LIBELLE_DOC_TITRE: 1,
                ConstantesPlume.LIBELLE_DOC_SECURITE: 1,
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: 1,
                Constantes.DOCUMENT_INFODOC_DATE_CREATION: 1,
            }
        }
        requetes = {'requetes': [requete_document]}
        enveloppe_requete = self.generateur.transmettre_requete(
            requetes, 'millegrilles.domaines.Plume', 'abcd-1234', self.queue_name)

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def requete_document(self):
        requete_document = {
            'filtre': {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPlume.LIBVAL_PLUME,
                ConstantesPlume.LIBELLE_DOC_PLUME_UUID: self.uuid,
            }
        }
        requetes = {'requetes': [requete_document]}
        enveloppe_requete = self.generateur.transmettre_requete(
            requetes, 'millegrilles.domaines.Plume', 'abcd-1234', self.queue_name)

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def nouveau_document(self):

        document = {
            ConstantesPlume.LIBELLE_DOC_TITRE: 'Document Unit Test',
            ConstantesPlume.LIBELLE_DOC_CATEGORIES: 'cat1 cat2 Cat3',
            ConstantesPlume.LIBELLE_DOC_SECURITE: Constantes.SECURITE_PRIVE,
            ConstantesPlume.LIBELLE_DOC_QUILL_DELTA: {"ops": [{"insert": "Un document de test.\n"}]},
            ConstantesPlume.LIBELLE_DOC_TEXTE: "Un document de test.\n",
        }

        enveloppe_val = self.generateur.soumettre_transaction(
            document, 'millegrilles.domaines.Plume.nouveauDocument', reply_to=self.queue_name, correlation_id='efgh')

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def modifier_document(self):

        document = {
            ConstantesPlume.LIBELLE_DOC_PLUME_UUID: self.uuid,
            ConstantesPlume.LIBELLE_DOC_TITRE: 'Document Unit Test modifie 1',
            ConstantesPlume.LIBELLE_DOC_CATEGORIES: 'cat1 cat4 Cat3',
            ConstantesPlume.LIBELLE_DOC_SECURITE: Constantes.SECURITE_PRIVE,
            ConstantesPlume.LIBELLE_DOC_QUILL_DELTA: {"ops": [{"insert": "Un document de test modifie 1.\n"}]},
            ConstantesPlume.LIBELLE_DOC_TEXTE: "Un document de test modifie 1.\n",
        }

        enveloppe_val = self.generateur.soumettre_transaction(
            document, 'millegrilles.domaines.Plume.modifierDocument', reply_to=self.queue_name, correlation_id='efgh')

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def supprimer_document(self):

        document = {
            ConstantesPlume.LIBELLE_DOC_PLUME_UUID: self.uuid,
        }

        enveloppe_val = self.generateur.soumettre_transaction(
            document, 'millegrilles.domaines.Plume.supprimerDocument', reply_to=self.queue_name, correlation_id='efgh')

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def publier_document(self):

        document = {
            ConstantesPlume.LIBELLE_DOC_PLUME_UUID: self.uuid,
        }

        enveloppe_val = self.generateur.soumettre_transaction(
            document, 'millegrilles.domaines.Plume.publierDocument', reply_to=self.queue_name, correlation_id='efgh')

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def creerAnnonce(self):
        document = ConstantesPlume.DOCUMENT_ANNONCE.copy()
        document[ConstantesPlume.LIBELLE_DOC_TEXTE] = 'Une nouvelle annonce sous Plume'
        document[ConstantesPlume.LIBELLE_DOC_SUJET] = 'Mon sujet'

        enveloppe_val = self.generateur.soumettre_transaction(
            document, ConstantesPlume.TRANSACTION_CREER_ANNONCE, reply_to=self.queue_name, correlation_id='efgh')

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def supprimerAnnonce(self):
        document = {
            ConstantesPlume.LIBELLE_DOC_PLUME_UUID: '6b55ce50-32fc-11ea-adb2-00155d011f09'
        }

        enveloppe_val = self.generateur.soumettre_transaction(
            document, ConstantesPlume.TRANSACTION_SUPPRIMER_ANNONCE, reply_to=self.queue_name, correlation_id='efgh')

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def remplacerAnnonce(self):
        document = ConstantesPlume.DOCUMENT_ANNONCE.copy()
        document[ConstantesPlume.LIBELLE_DOC_TEXTE] = 'Un remplacement dans Plumeau'
        document[ConstantesPlume.LIBELLE_DOC_SUJET] = 'Tu es remplace'
        document[ConstantesPlume.LIBELLE_DOC_REMPLACE] = '974c9442-32fe-11ea-adb2-00155d011f09'

        enveloppe_val = self.generateur.soumettre_transaction(
            document, ConstantesPlume.TRANSACTION_CREER_ANNONCE, reply_to=self.queue_name, correlation_id='efgh')

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def requete_annonces_recentes(self):
        self.generateur.transmettre_requete(
            {},
            ConstantesPlume.REQUETE_CHARGER_ANNONCES_RECENTES,
            reply_to=self.queue_name,
            correlation_id='abcd',
            securite=Constantes.SECURITE_PUBLIC
        )

    def executer(self):
        # self.creerAnnonce()
        # self.supprimerAnnonce()
        # self.remplacerAnnonce()
        self.requete_annonces_recentes()


# --- MAIN ---
sample = MessagesSample()

# TEST

# FIN TEST
sample.event_recu.wait(5)
sample.deconnecter()


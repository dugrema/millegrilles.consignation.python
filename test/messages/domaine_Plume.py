# Script de test pour transmettre message de transaction

import datetime
import uuid

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles import Constantes
from millegrilles.domaines.Plume import ConstantesPlume
from millegrilles.util.BaseSendMessage import BaseEnvoyerMessageEcouter


class MessagesSample(BaseEnvoyerMessageEcouter):

    def __init__(self):
        super().__init__()

    def deconnecter(self):
        self.contexte.message_dao.deconnecter()

    def traiter_message(self, ch, method, properties, body):
        print("Message recu, correlationId: %s" % properties.correlation_id)
        print(body)

    def requete_document(self):
        requete_document = {
            'filtre': {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPlume.LIBVAL_PLUME,
                ConstantesPlume.DOCUMENT_PLUME_UUID: '',
            }
        }
        requetes = {'requetes': [requete_document]}
        enveloppe_requete = self.generateur.transmettre_requete(
            requetes, 'millegrilles.domaines.Plume', 'abcd-1234', self.queue_name)

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def nouveau_document(self):

        document = {
            ConstantesPlume.DOCUMENT_TITRE: 'Document Unit Test',
            ConstantesPlume.DOCUMENT_CATEGORIES: 'cat1 cat2 Cat3',
            ConstantesPlume.DOCUMENT_SECURITE: Constantes.SECURITE_PRIVE,
            ConstantesPlume.DOCUMENT_TEXTE: {"ops": [{"insert": "Un document de test.\n"}]}
        }

        enveloppe_val = self.generateur.soumettre_transaction(
            document, 'millegrilles.domaines.Plume.nouveauDocument', reply_to=self.queue_name, correlation_id='efgh')

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def modifier_document(self):

        document = {
        }

        enveloppe_val = self.generateur.soumettre_transaction(
            document, 'millegrilles.domaines.Plume.modifierDocument', reply_to=self.queue_name, correlation_id='efgh')

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def supprimer_document(self):

        document = {
        }

        enveloppe_val = self.generateur.soumettre_transaction(
            document, 'millegrilles.domaines.Plume.supprimerDocument', reply_to=self.queue_name, correlation_id='efgh')

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val


# --- MAIN ---
sample = MessagesSample()

# TEST
# enveloppe = sample.requete_profil_usager()
enveloppe = sample.nouveau_document()
# enveloppe = sample.modifier_document()

sample.recu.wait(10)

# FIN TEST
sample.deconnecter()

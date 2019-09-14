# Script de test pour transmettre message de transaction

import datetime
import uuid

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles import Constantes
from millegrilles.domaines.Parametres import ConstantesParametres
from millegrilles.domaines.MaitreDesCles import ConstantesMaitreDesCles
from millegrilles.util.BaseSendMessage import BaseEnvoyerMessageEcouter


class MessagesSample(BaseEnvoyerMessageEcouter):

    def __init__(self):
        super().__init__()

        self.uuid = '16b85142-d406-11e9-af0b-00155d011f00'
        # self.uuid = 'bb58dc23-bf28-49b6-b3f6-a534794d6de4'

    def deconnecter(self):
        self.contexte.message_dao.deconnecter()

    def traiter_message(self, ch, method, properties, body):
        print("Message recu, correlationId: %s" % properties.correlation_id)
        print(body)

    def maj_email_smtp_avecpassword(self):
        email_smtp_transaction = {
            ConstantesParametres.DOCUMENT_CHAMP_ACTIF: True,
            ConstantesParametres.DOCUMENT_CHAMP_HOST: 'mg-maple.local',
            ConstantesParametres.DOCUMENT_CHAMP_PORT: 443,
            ConstantesParametres.DOCUMENT_CHAMP_COURRIEL_ORIGINE: 'mathieu.dugre@mdugre.info',
            ConstantesParametres.DOCUMENT_CHAMP_COURRIEL_DESTINATIONS: 'mail@mdugre.info',
            ConstantesParametres.DOCUMENT_CHAMP_USER: 'mathieu',
            Constantes.DOCUMENT_SECTION_CRYPTE: 'du contenu crypte, mot de passe, etc.',
        }

        enveloppe_val = self.generateur.soumettre_transaction(
            email_smtp_transaction,
            ConstantesParametres.TRANSACTION_MODIFIER_EMAIL_SMTP,
            reply_to=self.queue_name,
            correlation_id='efgh'
        )

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def transmettre_cles(self, uuid):
        email_smtp_transaction = {
            'domaine': ConstantesParametres.DOMAINE_NOM,
            ConstantesParametres.TRANSACTION_CHAMP_MGLIBELLE: ConstantesParametres.LIBVAL_EMAIL_SMTP,
            'uuid': uuid,
        }

        routing = ConstantesParametres.TRANSACTION_CLES_RECUES

        enveloppe_val = self.generateur.soumettre_transaction(
            email_smtp_transaction,
            routing,
            reply_to=self.queue_name,
            correlation_id='efgh'
        )

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def maj_email_smtp_sanspassword(self):
        email_smtp_transaction = {
            ConstantesParametres.DOCUMENT_CHAMP_ACTIF: True,
            ConstantesParametres.DOCUMENT_CHAMP_HOST: 'mg-maple.local',
            ConstantesParametres.DOCUMENT_CHAMP_PORT: 443,
            ConstantesParametres.DOCUMENT_CHAMP_COURRIEL_ORIGINE: 'mathieu.dugre@mdugre.info',
            ConstantesParametres.DOCUMENT_CHAMP_COURRIEL_DESTINATIONS: 'mail@mdugre.info',
            ConstantesParametres.DOCUMENT_CHAMP_USER: 'mathieu',
        }

        enveloppe_val = self.generateur.soumettre_transaction(
            email_smtp_transaction,
            ConstantesParametres.TRANSACTION_MODIFIER_EMAIL_SMTP,
            reply_to=self.queue_name,
            correlation_id='efgh'
        )

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

# --- MAIN ---
sample = MessagesSample()

# TEST
# enveloppe = sample.maj_email_smtp_sanspassword()
uuid = sample.maj_email_smtp_avecpassword()
enveloppe = sample.transmettre_cles(uuid)


sample.recu.wait(10)

# FIN TEST
sample.deconnecter()

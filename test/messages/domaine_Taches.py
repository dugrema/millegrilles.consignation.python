# Script de test pour transmettre message de transaction

from millegrilles import Constantes
from millegrilles.util.BaseSendMessage import BaseEnvoyerMessageEcouter
from millegrilles.domaines.Taches import FormatteurEvenementNotification, TachesConstantes

class MessagesSample(BaseEnvoyerMessageEcouter):

    def __init__(self):
        super().__init__()
        self.transmettre_certificat()

    def deconnecter(self):
        self.contexte.message_dao.deconnecter()

    def traiter_message(self, ch, method, properties, body):
        print("Message recu, correlationId: %s" % properties.correlation_id)
        print(body)

    def notification_tache(self):
        formatteur = FormatteurEvenementNotification(
            TachesConstantes.DOMAINE_NOM,
            TachesConstantes.COLLECTION_DOCUMENTS_NOM,
            self.contexte.generateur_transactions,
        )

        source = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: 'configuration',
        }
        collateur = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: 'configuration_4',
        }
        valeurs = {
            'version': 4
        }

        formatteur.emettre_notification_tache(source, collateur, valeurs)
        print("Sent")


# --- MAIN ---
sample = MessagesSample()

# TEST
# enveloppe = sample.maj_email_smtp_sanspassword()
enveloppe = sample.notification_tache()


sample.recu.wait(10)

# FIN TEST
sample.deconnecter()

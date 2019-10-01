# Script de test pour transmettre message de transaction

from millegrilles.util.BaseSendMessage import BaseEnvoyerMessageEcouter


class MessagesSample(BaseEnvoyerMessageEcouter):

    def __init__(self):
        super().__init__()

    def deconnecter(self):
        self.contexte.message_dao.deconnecter()

    def traiter_message(self, ch, method, properties, body):
        print("Message recu, correlationId: %s" % properties.correlation_id)
        print(body)

    def notification_tache(self):
        transaction = {

        }

        enveloppe_val = self.generateur.soumettre_transaction(
            transaction,
            ConstantesTaches.TRANSACTION_,
            reply_to=self.queue_name,
            correlation_id='efgh'
        )

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val


# --- MAIN ---
sample = MessagesSample()

# TEST
# enveloppe = sample.maj_email_smtp_sanspassword()
enveloppe = sample.notification_tache()


sample.recu.wait(10)

# FIN TEST
sample.deconnecter()

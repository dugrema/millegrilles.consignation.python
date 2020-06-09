from millegrilles import Constantes
from millegrilles.Constantes import ConstantesMaitreDesComptes
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

    def requete_profil_usager(self):
        requete = {'nomUsager': 'test'}
        domaine_action = '.'.join([ConstantesMaitreDesComptes.DOMAINE_NOM, ConstantesMaitreDesComptes.REQUETE_CHARGER_USAGER])
        enveloppe = self.generateur.transmettre_requete(requete, domaine_action, 'abcd-1234', self.queue_name)

        print("Envoi : %s" % enveloppe)
        return enveloppe

    def requete_info_proprietaire(self):
        requete = {}
        domaine_action = '.'.join([ConstantesMaitreDesComptes.DOMAINE_NOM, ConstantesMaitreDesComptes.REQUETE_INFO_PROPRIETAIRE])
        enveloppe = self.generateur.transmettre_requete(requete, domaine_action, 'abcd-1234', self.queue_name)

        print("Envoi : %s" % enveloppe)
        return enveloppe

    def transaction_inscrire_proprietaire(self):
        transaction = {ConstantesMaitreDesComptes.CHAMP_CLE: {'ma_cle': 56896, 'autre_info': 'Da da daah'},}
        domaine_action = '.'.join([ConstantesMaitreDesComptes.DOMAINE_NOM, ConstantesMaitreDesComptes.TRANSACTION_INSCRIRE_PROPRIETAIRE])
        enveloppe = self.generateur.soumettre_transaction(transaction, domaine_action, 'abcd-1234', self.queue_name)
        print("Envoi : %s" % enveloppe)
        return enveloppe

    def transaction_inscrire_usager(self):
        transaction = {'nomUsager': 'test', 'mon_info': 237}
        domaine_action = '.'.join([ConstantesMaitreDesComptes.DOMAINE_NOM, ConstantesMaitreDesComptes.TRANSACTION_INSCRIRE_USAGER])
        enveloppe = self.generateur.soumettre_transaction(transaction, domaine_action, 'abcd-1234', self.queue_name)
        print("Envoi : %s" % enveloppe)
        return enveloppe

    def transaction_maj_motdepasse(self):
        transaction = {
            ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: 'test',
            ConstantesMaitreDesComptes.CHAMP_MOTDEPASSE: {'info-mot-de-passe': 1234},
        }
        domaine_action = '.'.join([ConstantesMaitreDesComptes.DOMAINE_NOM, ConstantesMaitreDesComptes.TRANSACTION_MAJ_MOTDEPASSE])
        enveloppe = self.generateur.soumettre_transaction(transaction, domaine_action, 'abcd-1234', self.queue_name)
        print("Envoi : %s" % enveloppe)
        return enveloppe

    def transaction_maj_motdepasse_proprietaire(self):
        transaction = {
            ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: 'test',
            ConstantesMaitreDesComptes.CHAMP_MOTDEPASSE: {'info-mot-de-passe': 1234},
            ConstantesMaitreDesComptes.CHAMP_EST_PROPRIETAIRE: True,
        }
        domaine_action = '.'.join([ConstantesMaitreDesComptes.DOMAINE_NOM, ConstantesMaitreDesComptes.TRANSACTION_MAJ_MOTDEPASSE])
        enveloppe = self.generateur.soumettre_transaction(transaction, domaine_action, 'abcd-1234', self.queue_name)
        print("Envoi : %s" % enveloppe)
        return enveloppe

    def transaction_supprimer_motdepasse(self):
        transaction = {
            ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: 'test',
        }
        domaine_action = '.'.join([ConstantesMaitreDesComptes.DOMAINE_NOM, ConstantesMaitreDesComptes.TRANSACTION_SUPPRESSION_MOTDEPASSE])
        enveloppe = self.generateur.soumettre_transaction(transaction, domaine_action, 'abcd-1234', self.queue_name)
        print("Envoi : %s" % enveloppe)
        return enveloppe

    def transaction_ajouter_cle(self):
        transaction = {
            ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: 'test',
            ConstantesMaitreDesComptes.CHAMP_CLE: {'ma_cle': 56896, 'autre_info': 'Da da daah'},
            ConstantesMaitreDesComptes.CHAMP_RESET_CLES: False,
        }
        domaine_action = '.'.join([ConstantesMaitreDesComptes.DOMAINE_NOM, ConstantesMaitreDesComptes.TRANSACTION_AJOUTER_CLE])
        enveloppe = self.generateur.soumettre_transaction(transaction, domaine_action, 'abcd-1234', self.queue_name)
        print("Envoi : %s" % enveloppe)
        return enveloppe

    def transaction_ajouter_cle_proprietaire(self):
        transaction = {
            ConstantesMaitreDesComptes.CHAMP_EST_PROPRIETAIRE: True,
            ConstantesMaitreDesComptes.CHAMP_CLE: {'ma_cle': 56896, 'autre_info': 'Da da daah'},
            ConstantesMaitreDesComptes.CHAMP_RESET_CLES: False,
        }
        domaine_action = '.'.join([ConstantesMaitreDesComptes.DOMAINE_NOM, ConstantesMaitreDesComptes.TRANSACTION_AJOUTER_CLE])
        enveloppe = self.generateur.soumettre_transaction(transaction, domaine_action, 'abcd-1234', self.queue_name)
        print("Envoi : %s" % enveloppe)
        return enveloppe

    def transaction_supprimer_cles(self):
        transaction = {
            ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: 'test',
        }
        domaine_action = '.'.join([ConstantesMaitreDesComptes.DOMAINE_NOM, ConstantesMaitreDesComptes.TRANSACTION_SUPPRIMER_CLES])
        enveloppe = self.generateur.soumettre_transaction(transaction, domaine_action, 'abcd-1234', self.queue_name)
        print("Envoi : %s" % enveloppe)
        return enveloppe

    def transaction_supprimer_usager(self):
        transaction = {
            ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: 'test',
        }
        domaine_action = '.'.join([ConstantesMaitreDesComptes.DOMAINE_NOM, ConstantesMaitreDesComptes.TRANSACTION_SUPPRIMER_USAGER])
        enveloppe = self.generateur.soumettre_transaction(transaction, domaine_action, 'abcd-1234', self.queue_name)
        print("Envoi : %s" % enveloppe)
        return enveloppe

    def transaction_associer_idmg(self):
        transaction = {
            ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: 'test',
            Constantes.CONFIG_IDMG: 'A_abcd1234EFGHI',
            ConstantesMaitreDesComptes.CHAMP_CHAINE_CERTIFICAT: ['cert1', 'cert5'],
            ConstantesMaitreDesComptes.CHAMP_CLE: 'Une cle chiffree 5',
            ConstantesMaitreDesComptes.CHAMP_RESET_CERTIFICATS: False,
        }
        domaine_action = '.'.join([ConstantesMaitreDesComptes.DOMAINE_NOM, ConstantesMaitreDesComptes.TRANSACTION_ASSOCIER_CERTIFICAT])
        enveloppe = self.generateur.soumettre_transaction(transaction, domaine_action, 'abcd-1234', self.queue_name)
        print("Envoi : %s" % enveloppe)
        return enveloppe

    def executer(self):
        # self.requete_info_proprietaire()
        # self.requete_profil_usager()
        # self.transaction_inscrire_proprietaire()
        # self.transaction_inscrire_usager()
        # self.transaction_maj_motdepasse()
        # self.transaction_maj_motdepasse_proprietaire()
        # self.transaction_supprimer_motdepasse()
        # self.transaction_ajouter_cle()
        # self.transaction_ajouter_cle_proprietaire()
        # self.transaction_supprimer_cles()
        # self.transaction_supprimer_usager()
        self.transaction_associer_idmg()


# --- MAIN ---
sample = MessagesSample()

# TEST

# FIN TEST
sample.event_recu.wait(5)
sample.deconnecter()



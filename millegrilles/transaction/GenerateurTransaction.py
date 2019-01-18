import uuid
import datetime
import getpass
import socket
import re

from millegrilles import Constantes
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.SecuritePKI import SignateurTransaction, GestionnaireEvenementsCertificat


# Generateur de transaction - peut etre reutilise.
class GenerateurTransaction:

    def __init__(self, contexte=None):
        if contexte is not None:
            self._contexte = contexte
        else:
            self._contexte = ContexteRessourcesMilleGrilles()
            self._contexte.initialiser(init_message=True, init_document=False, connecter=True)

        # Initialiser la configuration et dao au besoin
        self.signateur_transaction = SignateurTransaction(self._contexte)
        self.signateur_transaction.initialiser()

        # Transmettre le certificat pour etre sur que tous les participants l'ont
        gestionnaire_certificats = GestionnaireEvenementsCertificat(self._contexte, self.signateur_transaction)
        gestionnaire_certificats.transmettre_certificat()

    # def connecter(self):
    #     self._message_dao.connecter()
    #
    # def deconnecter(self):
    #     self._message_dao.deconnecter()

    ''' 
    Transmet un message. La connexion doit etre ouverte.
    
    :param message_dict: Dictionnaire du contenu (payload) du message.
    :param domaine: Domaine du message. Utilise pour le routage de la transaction apres persistance.  
    :returns: UUID de la transaction. Permet de retracer la transaction dans MilleGrilles une fois persistee.
    '''
    def soumettre_transaction(self, message_dict, domaine=None):
        # Preparer la structure du message reconnue par MilleGrilles
        enveloppe = self.preparer_enveloppe(message_dict, domaine)

        # Extraire le UUID pour le retourner a l'invoqueur de la methode. Utilise pour retracer une soumission.
        uuid_transaction = enveloppe.get(
            Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION).get(
                Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID)

        self._contexte.message_dao.transmettre_nouvelle_transaction(enveloppe)

        return uuid_transaction

    def preparer_enveloppe(self, message_dict, domaine=None):

        # Identifier usager du systeme, nom de domaine
        identificateur_systeme = '%s@%s' % (getpass.getuser(), socket.getfqdn())

        # Ajouter identificateur unique et temps de la transaction
        uuid_transaction = uuid.uuid1()

        meta = dict()
        meta[Constantes.TRANSACTION_MESSAGE_LIBELLE_SOURCE_SYSTEME] = identificateur_systeme
        meta[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID] = "%s" % uuid_transaction
        meta[Constantes.TRANSACTION_MESSAGE_LIBELLE_ESTAMPILLE] = int(datetime.datetime.utcnow().timestamp())
        meta[Constantes.TRANSACTION_MESSAGE_LIBELLE_VERSION] = Constantes.TRANSACTION_MESSAGE_LIBELLE_VERSION_COURANTE
        if domaine is not None:
            meta[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE] = domaine

        enveloppe = dict()
        enveloppe[Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION] = meta
        enveloppe.update(message_dict)

        # Hacher le contenu avec SHA2-256 et signer le message avec le certificat du noeud
        meta[Constantes.TRANSACTION_MESSAGE_LIBELLE_HACHAGE] = self.signateur_transaction.hacher_contenu(enveloppe)
        message_signe = self.signateur_transaction.signer(enveloppe)

        return message_signe


class TransactionOperations:

    def __init__(self):
        pass

    def enlever_champsmeta(self, transaction):
        copie = transaction.copy()

        regex_ignorer = re.compile('^_.+')
        for cle in transaction.keys():
            m = regex_ignorer.match(cle)
            if m:
                del copie[cle]

        return copie
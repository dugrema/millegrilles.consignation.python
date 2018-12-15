import uuid
import datetime
import getpass
import socket

from millegrilles import Constantes
from millegrilles.dao.MessageDAO import PikaDAO
from millegrilles.dao.Configuration import TransactionConfiguration


# Generateur de transaction - peut etre reutilise.
class GenerateurTransaction:

    def __init__(self, configuration=None, message_dao=None):
        # Initialiser la configuraiton et dao au besoin
        if configuration is None:
            self._configuration = TransactionConfiguration()
            self._configuration.loadEnvironment()
        else:
            self._configuration = configuration

        if message_dao is None:
            self._message_dao = PikaDAO(self._configuration)
        else:
            self._message_dao = message_dao

    def connecter(self):
        self._message_dao.connecter()

    def deconnecter(self):
        self._message_dao.deconnecter()

    ''' 
    Transmet un message. La connexion doit etre ouverte.
    
    :param message_dict: Dictionnaire du contenu (payload) du message.
    :param domaine: Domaine du message. Utilise pour le routage de la transaction apres persistance.  
    :returns: UUID de la transaction. Permet de retracer la transaction dans MilleGrilles une fois persistee.
    '''
    def soumettre_transaction(self, message_dict, domaine=None):
        # Preparer la structure du message reconnue par MilleGrilles
        enveloppe = GenerateurTransaction.preparer_enveloppe(message_dict, domaine)

        # Extraire le UUID pour le retourner a l'invoqueur de la methode. Utilise pour retracer une soumission.
        uuid_transaction = enveloppe.get(
            Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION).get(
                Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID)

        self._message_dao.transmettre_nouvelle_transaction(enveloppe)

        return uuid_transaction

    @staticmethod
    def preparer_enveloppe(message_dict, domaine=None):

        # Identifier usager du systeme, nom de domaine
        identificateur_systeme = '%s@%s' % (getpass.getuser(), socket.getfqdn())

        # Ajouter identificateur unique et temps de la transaction
        uuid_transaction = uuid.uuid1()

        meta = dict()
        meta[Constantes.TRANSACTION_MESSAGE_LIBELLE_SOURCE_SYSTEME] = identificateur_systeme
        meta[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID] = "%s" % uuid_transaction
        meta[Constantes.TRANSACTION_MESSAGE_LIBELLE_ESTAMPILLE] = int(datetime.datetime.utcnow().timestamp())
        meta[Constantes.TRANSACTION_MESSAGE_LIBELLE_SIGNATURE] = ""
        if domaine is not None:
            meta[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE] = domaine

        enveloppe = dict()
        enveloppe[Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION] = meta
        enveloppe[Constantes.TRANSACTION_MESSAGE_LIBELLE_CHARGE_UTILE] = message_dict

        return enveloppe

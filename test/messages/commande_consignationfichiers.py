# Script de test pour transmettre message de transaction
import logging
import os

from uuid import uuid4
from threading import Event

from millegrilles.util.BaseTestMessages import DomaineTest
from millegrilles import Constantes
from millegrilles.Constantes import ConstantesGrosFichiers


class TestConsignationFichiers(DomaineTest):

    def __init__(self):
        super().__init__()
        self.__logger = logging.getLogger(self.__class__.__name__)

        self.__fuuid = 'z8VwJR6hCq6z7TJY2MjsJsfAGTkjEimw9yduR6dDnHnUf4uF7cJFJxCWKmy2tw5kpRJtgvaZCatQKu5dDbCC63fVk6t'
        self.event_termine = Event()

        self.__awss3_secret_access_key = os.environ['AWSS3_SECRET']

    def commande_restaurerGrosFichiers(self):
        params = {
        }
        domaine = 'commande.backup.restaurerGrosFichiers'
        self.generateur.transmettre_commande(
            params, domaine, reply_to=self.queue_name, correlation_id='reply_regenerer')

    def commande_transcoderVideo(self):
        # permission = self.preparer_permission_dechiffrage_fichier(self.__fuuid)
        params = {
            'fuuid': self.__fuuid,
            # 'mimetype': 'video/webm',
            'mimetype': 'video/mp4',
        }
        domaine = 'commande.fichiers.transcoderVideo'
        self.generateur.transmettre_commande(
            params, domaine, reply_to=self.queue_name, correlation_id='reply_regenerer')

    def requete_getclessh(self):
        # permission = self.preparer_permission_dechiffrage_fichier(self.__fuuid)
        requete = dict()
        domaine = 'requete.fichiers.getPublicKeySsh'
        self.generateur.transmettre_requete(
            requete, domaine, reply_to=self.queue_name, correlation_id='requete_getclessh')

    def commande_publier_fichier_ssh(self):
        params = {
            'fuuid': self.__fuuid,
            # 'mimetype': 'video/mp4',
            'host': '192.168.2.131',
            'port': 22,
            'username': 'sftptest',
            # 'basedir': '/home/sftptest/consignation'
        }
        domaine = 'commande.fichiers.publierFichierSftp'
        self.generateur.transmettre_commande(
            params, domaine, reply_to=self.queue_name, correlation_id='commande_publier_fichier_ssh')

    def commande_publier_fichier_ipfs(self):
        params = {
            'fuuid': self.__fuuid,
            # 'mimetype': 'video/mp4',
        }
        domaine = 'commande.fichiers.publierFichierIpfs'
        self.generateur.transmettre_commande(
            params, domaine, reply_to=self.queue_name, correlation_id='commande_publier_fichier_ipfs')

    def commande_publier_fichier_awss3(self):
        params = {
            'uuid': str(uuid4()),
            'fuuid': self.__fuuid,
            'bucketRegion': 'us-east-1',
            'credentialsAccessKeyId': 'AKIA2JHYIVE5E3HWIH7K',
            'secretAccessKey': self.__awss3_secret_access_key,
            # 'mimetype': 'video/mp4',
            'bucketName': 'millegrilles',
            'bucketDirfichier': 'mg-dev4',
        }
        domaine = 'commande.fichiers.publierFichierAwsS3'
        self.generateur.transmettre_commande(
            params, domaine, reply_to=self.queue_name, correlation_id='commande_publier_fichier_awss3')

    def executer(self):
        self.__logger.debug("Executer")
        # self.commande_restaurerGrosFichiers()
        # self.commande_transcoderVideo()
        # self.requete_getclessh()
        # self.commande_publier_fichier_ssh()
        # self.commande_publier_fichier_ipfs()
        self.commande_publier_fichier_awss3()

    # def demander_permission(self, fuuid):
    #     requete_cert_maitredescles = {
    #         'fuuid': fuuid,
    #         'permission': self.preparer_permission_dechiffrage_fichier(self.__fuuid)
    #     }
    #
    #     enveloppe_requete = self.generateur.transmettre_commande(
    #         requete_cert_maitredescles,
    #         'fichiers.',
    #         correlation_id='abcd-1234',
    #         reply_to=self.queue_name
    #     )
    #
    #     print("Envoi requete: %s" % enveloppe_requete)
    #     self.event_recu.wait(3)
    #     if self.event_recu.is_set():
    #         self.event_recu.clear()
    #         return self.messages.pop()
    #
    #     raise Exception("Permission non recue")

    # def preparer_permission_dechiffrage_fichier(self, fuuid):
    #     permission = {
    #         ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID: fuuid,
    #         Constantes.ConstantesMaitreDesCles.TRANSACTION_CHAMP_ROLES_PERMIS: ['fichiers'],
    #         Constantes.ConstantesMaitreDesCles.TRANSACTION_CHAMP_DUREE_PERMISSION: (2 * 60),  # 2 minutes
    #     }
    #     # Signer
    #     generateur_transactions = self._contexte.generateur_transactions
    #     commande_permission = generateur_transactions.preparer_enveloppe(
    #         permission,
    #         '.'.join([Constantes.ConstantesMaitreDesCles.DOMAINE_NOM,
    #                   Constantes.ConstantesMaitreDesCles.REQUETE_DECRYPTAGE_GROSFICHIER])
    #     )
    #
    #     return commande_permission

# --- MAIN ---
if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger('millegrilles').setLevel(logging.DEBUG)
    logging.getLogger('TestConsignationFichiers').setLevel(logging.DEBUG)
    test = TestConsignationFichiers()
    # TEST

    # FIN TEST
    test.event_termine.wait(10)
    test.deconnecter()

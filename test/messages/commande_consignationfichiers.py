# Script de test pour transmettre message de transaction
import logging
import os
import requests
import json
import multibase

from uuid import uuid4
from threading import Event

from millegrilles.util.BaseTestMessages import DomaineTest
from millegrilles import Constantes
from millegrilles.Constantes import ConstantesGrosFichiers, ConstantesMaitreDesCles
from millegrilles.util.Hachage import hacher


class TestConsignationFichiers(DomaineTest):

    def __init__(self):
        super().__init__()
        self.__logger = logging.getLogger(self.__class__.__name__)

        self.__fuuid = 'z8VxkTYUqqHGUUXPncjp96NfnrM9xSQpQDQGBinaGQWS7rrS6uYpJbSRig4UfZwRVHRJwJv54oQkuqD2hY922NG7U1o'
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
            'host': '192.168.2.131',
            'port': 22,
            'username': 'sftptest',
            'basedir': '/home/sftptest/consignation',
            'mimetype': 'image/gif',
            'keyType': 'rsa',
            # 'securite': '1.public',
        }
        domaine = 'commande.fichiers.publierFichierSftp'
        self.generateur.transmettre_commande(
            params, domaine, reply_to=self.queue_name, correlation_id='commande_publier_fichier_ssh')

    def commande_publier_vitrine_ssh(self):
        params = {
            'host': '192.168.2.131',
            'port': 22,
            'username': 'sftptest',
            'repertoireRemote': '/var/opt/millegrilles/nginx/html/site1',
            'identificateur_document': {'application': 'vitrine'},
            'cdn_id' : 'DUMMY',
            # 'securite': '1.public',
            'keyType': 'rsa',
        }
        domaine = 'commande.fichiers.publierVitrineSftp'
        self.generateur.transmettre_commande(
            params, domaine, reply_to=self.queue_name, correlation_id='commande_publier_vitrine_ssh')

    def commande_publier_vitrine_ipfs(self):
        params = {
            # 'securite': '1.public',
        }
        domaine = 'commande.fichiers.publierVitrineIpfs'
        self.generateur.transmettre_commande(
            params, domaine, reply_to=self.queue_name, correlation_id='commande_publier_vitrine_ssh')

    def commande_publier_fichier_ipfs(self):
        params = {
            'fuuid': self.__fuuid,
            'mimetype': 'image/gif',
            'securite': '1.public',
        }
        domaine = 'commande.fichiers.publierFichierIpfs'
        self.generateur.transmettre_commande(
            params, domaine, reply_to=self.queue_name, correlation_id='commande_publier_fichier_ipfs')

    def commande_publier_fichier_awss3(self):
        secret_chiffre = 'm0M2DADXJBB4wF/4n1rNum71zBH5f3E/dDpRjUof8pqMXvDG8SzvD5Q'
        permission = self.preparer_permission_secretawss3(secret_chiffre)

        params = {
            'uuid': str(uuid4()),
            'fuuid': self.__fuuid,
            'mimetype': 'image/gif',
            # 'securite': '1.public',
            'bucketRegion': 'us-east-1',
            'credentialsAccessKeyId': 'AKIA2JHYIVE5E3HWIH7K',
            # 'secretAccessKey': self.__awss3_secret_access_key,
            'secretAccessKey_chiffre': 'm0M2DADXJBB4wF/4n1rNum71zBH5f3E/dDpRjUof8pqMXvDG8SzvD5Q',
            'permission': permission,
            'bucketName': 'millegrilles',
            'bucketDirfichier': 'mg-dev4/fichiers',
        }
        domaine = 'commande.fichiers.publierFichierAwsS3'
        self.generateur.transmettre_commande(
            params, domaine, reply_to=self.queue_name, correlation_id='commande_publier_fichier_awss3')

    def put_publier_repertoire_ssh(self):
        files = list()
        files.append(('files', ('think002ca.json', open('/home/mathieu/temp/uploadTest/think002ca.pub', 'rb'),
                                'application/octet-stream')))
        files.append(('files', ('test1/test.json', open('/home/mathieu/temp/uploadTest/test1/test.json', 'rb'),
                                'application/octet-stream')))
        files.append(('files', ('test2/test3/mq.log', open('/home/mathieu/temp/uploadTest/test2/test3/mq.log', 'rb'),
                                'application/octet-stream')))

        publier_ssh = {
            'host': '192.168.2.131',
            'port': 22,
            'username': 'sftptest',
            'repertoireRemote': '/home/sftptest/pythontest',
            'correlation': 'upload_ssh',
        }
        publier_ssh = json.dumps(publier_ssh)

        r = requests.put(
            'https://fichiers:3021/publier/repertoire',
            files=files,
            data={'publierSsh': publier_ssh},
            verify=self._contexte.configuration.mq_cafile,
            cert=(self._contexte.configuration.mq_certfile, self._contexte.configuration.mq_keyfile)
        )

    def put_publier_repertoire_awss3(self):
        secret_chiffre = 'm0M2DADXJBB4wF/4n1rNum71zBH5f3E/dDpRjUof8pqMXvDG8SzvD5Q'
        permission = self.preparer_permission_secretawss3(secret_chiffre)

        files = list()
        files.append(('files', ('think002ca.json', open('/home/mathieu/temp/uploadTest/think002ca.pub', 'rb'),
                                'application/octet-stream')))
        files.append(('files', ('test1/test.json', open('/home/mathieu/temp/uploadTest/test1/test.json', 'rb'),
                                'application/octet-stream')))
        files.append(
            ('files', ('test2/test3/mq.log', open('/home/mathieu/temp/uploadTest/test2/test3/mq.log', 'rb'),
                       'application/octet-stream')))

        publier_awss3 = {
            'bucketRegion': 'us-east-1',
            'credentialsAccessKeyId': 'AKIA2JHYIVE5E3HWIH7K',
            # 'secretAccessKey': self.__awss3_secret_access_key,
            'secretAccessKey_chiffre': 'm0M2DADXJBB4wF/4n1rNum71zBH5f3E/dDpRjUof8pqMXvDG8SzvD5Q',
            'permission': permission,
            'bucketName': 'millegrilles',
            'bucketDirfichier': 'mg-dev4/fichiers/testrep',
            'correlation': 'upload_awss3',
        }
        publier_awss3 = json.dumps(publier_awss3)

        r = requests.put(
            'https://fichiers:3021/publier/repertoire',
            files=files,
            data={'publierAwsS3': publier_awss3},
            verify=self._contexte.configuration.mq_cafile,
            cert=(self._contexte.configuration.mq_certfile, self._contexte.configuration.mq_keyfile)
        )

    def put_publier_repertoire_ipfs(self):
        repertoire_test = '/home/mathieu/temp/uploadTest'
        files = list()
        files.append(('files', ('think002ca.json', open('/home/mathieu/temp/uploadTest/think002ca.pub', 'rb'),
                                'application/octet-stream')))
        files.append(('files', ('test1/test.json', open('/home/mathieu/temp/uploadTest/test1/test.json', 'rb'),
                                'application/octet-stream')))
        files.append(('files', ('test2/test3/mq.log', open('/home/mathieu/temp/uploadTest/test2/test3/mq.log', 'rb'),
                                'application/octet-stream')))

        publier_ipfs = {
            'ipns_key_name': 'vitrine1',
            'correlation': 'upload_ipfs',
        }
        publier_ipfs = json.dumps(publier_ipfs)

        r = requests.put(
            'https://fichiers:3021/publier/repertoire',
            files=files,
            data={'publierIpfs': publier_ipfs},
            verify=self._contexte.configuration.mq_cafile,
            cert=(self._contexte.configuration.mq_certfile, self._contexte.configuration.mq_keyfile)
        )

    def lister_consignation_sftp(self):
        data = {
            'host': '192.168.2.131',
            'port': 22,
            'username': 'sftptest',
            'repertoireRemote': '/home/sftptest/consignation',
        }

        r = requests.post(
            'https://fichiers:3021/publier/listerConsignationSftp',
            data=data,
            verify=self._contexte.configuration.mq_cafile,
            cert=(self._contexte.configuration.mq_certfile, self._contexte.configuration.mq_keyfile),
            stream=True
        )

        self.__logger.debug("Reponse")
        self.__logger.debug("----")
        r.raise_for_status()
        for info_fichier in r.iter_lines(chunk_size=8192):
            dict_fichier = json.loads(info_fichier)
            self.__logger.debug(str(dict_fichier))
        # with open('/tmp/fuuids.txt', 'wb') as fichier:
        #     for chunk in r.iter_content(chunk_size=32768):
        #         fichier.write(chunk)
        self.__logger.debug("----")

    def lister_consignation_ipfs(self):
        data = {}

        r = requests.post(
            'https://fichiers:3021/publier/listerPinsIpfs',
            # data=data,
            verify=self._contexte.configuration.mq_cafile,
            cert=(self._contexte.configuration.mq_certfile, self._contexte.configuration.mq_keyfile),
            stream=True
        )

        self.__logger.debug("Reponse")
        self.__logger.debug("----")
        r.raise_for_status()
        for info_pin_str in r.iter_lines(chunk_size=8192):
            info_pin = json.loads(info_pin_str)
            cid = info_pin['Cid']
            type_pin = info_pin['Type']
            self.__logger.debug('cid %s (%s)' % (cid, type_pin))
        # with open('/tmp/fuuids.txt', 'wb') as fichier:
        #     for chunk in r.iter_content(chunk_size=32768):
        #         fichier.write(chunk)
        self.__logger.debug("----")

    def lister_consignation_awss3(self):
        secret_chiffre = 'm0M2DADXJBB4wF/4n1rNum71zBH5f3E/dDpRjUof8pqMXvDG8SzvD5Q'
        permission = self.preparer_permission_secretawss3(secret_chiffre)

        data = {
            'bucketRegion': 'us-east-1',
            'credentialsAccessKeyId': 'AKIA2JHYIVE5E3HWIH7K',
            # 'secretAccessKey': self.__awss3_secret_access_key,
            'secretAccessKey_chiffre': secret_chiffre,
            'permission': permission,
            'bucketName': 'millegrilles',
            'bucketDirfichier': 'mg-dev4/fichiers',
        }

        r = requests.post(
            'https://fichiers:3021/publier/listerConsignationAwss3',
            data={'data': json.dumps(data)},
            verify=self._contexte.configuration.mq_cafile,
            cert=(self._contexte.configuration.mq_certfile, self._contexte.configuration.mq_keyfile),
            stream=True
        )

        self.__logger.debug("Reponse")
        self.__logger.debug("----")
        r.raise_for_status()
        for info_fichier in r.iter_lines(chunk_size=8192):
            dict_fichier = json.loads(info_fichier)
            self.__logger.debug(str(dict_fichier))
        # with open('/tmp/fuuids.txt', 'wb') as fichier:
        #     for chunk in r.iter_content(chunk_size=32768):
        #         fichier.write(chunk)
        self.__logger.debug("----")

    def preparer_permission_secretawss3(self, secret_chiffre):
        secret_bytes = multibase.decode(secret_chiffre)
        secret_hachage = hacher(secret_bytes, encoding='base58btc')
        permission = {
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_LISTE_HACHAGE_BYTES: [secret_hachage],
            'duree': 30 * 60 * 60,  # 30 minutes
            'securite': '3.protege',
            'roles_permis': ['Publication'],
        }
        permission = self.generateur.preparer_enveloppe(permission)
        return permission

    def commande_publier_cle_ipns(self):
        params = {
            'cid': 'QmPbUVmHccqr1cTB99XV2K1spqiU9iugQbeTAVKQewxU3V',
            'keyName': 'vitrine2',
        }
        domaine = 'commande.fichiers.publierIpns'
        self.generateur.transmettre_commande(
            params, domaine, reply_to=self.queue_name, correlation_id='commande_publier_cle_ipns')

    def commande_creer_cle_ipns(self):
        domaine = 'commande.fichiers.creerCleIpns'
        commande = {
            'nom': '0-cle-1.2.3-5'
        }
        self.generateur.transmettre_commande(
            commande, domaine, reply_to=self.queue_name, correlation_id='commande_creer_cle_ipns')

    def put_publier_fichier_ipns(self):
        files = list()
        files.append(('files', ('think002ca.json', open('/home/mathieu/temp/uploadTest/think002ca.pub', 'rb'),
                                'application/octet-stream')))

        data = {
            'cdns': 'JSON str',
            'ipns_key': 'ABCD-1234...PEM',
            'ipns_key_name': '60c12a04-de97-4693-a14b-5010cfd6dc10',
            'permission': 'JSON str',
        }

        r = requests.put(
            'https://fichiers:3021/publier/fichierIpns',
            files=files,
            data=data,
            verify=self._contexte.configuration.mq_cafile,
            cert=(self._contexte.configuration.mq_certfile, self._contexte.configuration.mq_keyfile),
            timeout=120000,  # 2 minutes max
        )
        r.raise_for_status()

    def executer(self):
        self.__logger.debug("Executer")
        # self.commande_restaurerGrosFichiers()
        # self.commande_transcoderVideo()
        # self.requete_getclessh()
        # self.commande_publier_fichier_ssh()
        # self.commande_publier_fichier_ipfs()
        # self.commande_publier_fichier_awss3()
        # self.put_publier_repertoire_ipfs()
        # self.put_publier_repertoire_ssh()
        # self.put_publier_repertoire_awss3()
        # self.lister_consignation_sftp()
        # self.lister_consignation_ipfs()
        # self.lister_consignation_awss3()
        # self.commande_publier_cle_ipns()
        # self.commande_creer_cle_ipns()
        # self.put_publier_fichier_ipns()
        # self.commande_publier_vitrine_ssh()
        self.commande_publier_vitrine_ipfs()

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

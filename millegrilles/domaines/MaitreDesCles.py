# Domaine MaitreDesCles
# Responsable de la gestion et de l'acces aux cles secretes pour les niveaux 3.Protege et 4.Secure.

from millegrilles import Constantes
from millegrilles.Domaines import GestionnaireDomaine
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.MGProcessus import MGProcessusTransaction
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles.dao.DocumentDAO import MongoJSONEncoder

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from base64 import b64encode, b64decode

import logging
import datetime
import os
import re


class ConstantesMaitreDesCles:

    DOMAINE_NOM = 'millegrilles.domaines.MaitreDesCles'
    COLLECTION_NOM = DOMAINE_NOM

    COLLECTION_TRANSACTIONS_NOM = COLLECTION_NOM
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_NOM
    QUEUE_NOM = DOMAINE_NOM

    LIBVAL_CONFIGURATION = 'configuration'

    TRANSACTION_NOUVELLE_CLE_GROSFICHIER = 'nouvelleCle.grosFichier'
    TRANSACTION_NOUVELLE_CLE_DOCUMENT = 'nouvelleCle.document'
    TRANSACTION_MAJ_DOCUMENT_CLES = 'majcles'

    REQUETE_CERT_MAITREDESCLES = 'certMaitreDesCles'
    REQUETE_DECRYPTAGE_DOCUMENT = 'decryptageDocument'
    REQUETE_DECRYPTAGE_GROSFICHIER = 'decryptageGrosFichier'

    TRANSACTION_CHAMP_CLESECRETE = 'cle'
    TRANSACTION_CHAMP_SUJET_CLE = 'sujet'

    DOCUMENT_LIBVAL_CLES_GROSFICHIERS = 'cles.grosFichiers'

    DOCUMENT_SECURITE = 'securite'

    DOCUMENT_DEFAUT = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_CONFIGURATION
    }

    # Document utilise pour conserver un ensemble de cles lie a un document
    DOCUMENT_CLES_GROSFICHIERS = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: DOCUMENT_LIBVAL_CLES_GROSFICHIERS,

        # Template a remplir
        'fuuid': None,    # Identificateur unique de version de fichier
        'cles': dict(),   # Dictionnaire indexe par fingerprint de certificat signataire. Valeur: cle secrete cryptee
    }

    DOCUMENT_TRANSACTION_CONSERVER_CLES = {
        TRANSACTION_CHAMP_SUJET_CLE: DOCUMENT_LIBVAL_CLES_GROSFICHIERS,  # Mettre le sujet approprie
        'fuuid': None,  # Identificateur unique de version de fichier
        'cles': dict(),  # Dictionnaire indexe par fingerprint de certificat signataire. Valeur: cle secrete cryptee
    }


class GestionnaireMaitreDesCles(GestionnaireDomaine):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

        nom_millegrille = contexte.configuration.nom_millegrille

        self.__repertoire_cles = '/opt/millegrilles/%s/pki/keys' % nom_millegrille
        self.__repertoire_certs = '/opt/millegrilles/%s/pki/certs' % nom_millegrille
        self.__repertoire_motsdepasse = '/opt/millegrilles/%s/pki/passwords' % nom_millegrille
        self.__prefix_maitredescles = '%s_maitredescles' % nom_millegrille

        self.__certificat_courant = None
        self.__certificat_courant_pem = None
        self.__cle_courante = None
        self.__certificats_backup = None  # Liste de certificats backup utilises pour conserver les cles secretes.

        # Queue message handlers
        self.__handler_transaction = None
        self.__handler_cedule = None
        self.__handler_requetes_noeuds = None

        self.generateur = GenerateurTransaction(self.contexte, encodeur_json=MongoJSONEncoder)

    def configurer(self):
        super().configurer()

        self.initialiser_document(ConstantesMaitreDesCles.LIBVAL_CONFIGURATION, ConstantesMaitreDesCles.DOCUMENT_DEFAUT)

        self.charger_certificat_courant()
        self.charger_certificats_backup()

        # Index collection domaine
        collection_domaine = self.get_collection()
        # Index par fingerprint de certificat
        # collection_domaine.create_index([
        #     (ConstantesPki.LIBELLE_FINGERPRINT, 1)
        # ], unique=True)
        # # Index par chaine de certificat verifie
        # collection_domaine.create_index([
        #     (ConstantesPki.LIBELLE_CHAINE_COMPLETE, 2),
        #     (Constantes.DOCUMENT_INFODOC_LIBELLE, 1)
        # ])
        # # Index pour trouver l'autorite qui a signe un certificat (par son subject)
        # collection_domaine.create_index([
        #     (ConstantesPki.LIBELLE_SUBJECT_KEY, 1),
        #     (ConstantesPki.LIBELLE_NOT_VALID_BEFORE, 1),
        #     (ConstantesPki.LIBELLE_NOT_VALID_AFTER, 1)
        # ])

    def charger_certificat_courant(self):
        fichier_cert = '%s/%s.cert.pem' % (self.__repertoire_certs, self.__prefix_maitredescles)
        fichier_cle = '%s/%s.key.pem' % (self.__repertoire_cles, self.__prefix_maitredescles)
        mot_de_passe = '%s/%s.password.txt' % (self.__repertoire_motsdepasse, self.__prefix_maitredescles)

        with open(mot_de_passe, 'rb') as motpasse_courant:
            motpass = motpasse_courant.readline()[0:-1]  # Enlever newline a la fin.
            with open(fichier_cle, "rb") as keyfile:
                cle = serialization.load_pem_private_key(
                    keyfile.read(),
                    password=motpass,
                    backend=default_backend()
                )
                self.__cle_courante = cle

        self._logger.info("Cle courante: %s" % str(self.__cle_courante))

        with open(fichier_cert, 'rb') as certificat_pem:
            certificat_courant_pem = certificat_pem.read()
            # certificat_pem = bytes(certificat_pem, 'utf-8')
            cert = x509.load_pem_x509_certificate(
                certificat_courant_pem,
                backend=default_backend()
            )
            self.__certificat_courant = cert
            self.__certificat_courant_pem = certificat_courant_pem.decode('utf8')

        self._logger.info("Certificat courant: %s" % str(self.__certificat_courant))

    def charger_certificats_backup(self):
        """
        Charge les certificats de backup presents dans le repertoire des certificats.
        Les cles publiques des backups sont utilisees pour re-encrypter les cles secretes.
        :return:
        """
        certificats_backup = list()

        p = re.compile("%s_backup_[0-9]*.cert.pem" % self.configuration.nom_millegrille)
        for file in os.listdir(self.__repertoire_certs):
            if p.match(file) is not None:
                self._logger.debug('Fichier cert backup %s' % os.path.join(self.__repertoire_certs, file))
                certfilepath = os.path.join(self.__repertoire_certs, file)
                with open(certfilepath, 'rb') as certificat_pem:
                    certificat_courant_pem = certificat_pem.read()
                    # certificat_pem = bytes(certificat_pem, 'utf-8')
                    cert = x509.load_pem_x509_certificate(
                        certificat_courant_pem,
                        backend=default_backend()
                    )
                    certificats_backup.append(cert)

        if len(certificats_backup) > 0:
            self.__certificats_backup = certificats_backup

    def setup_rabbitmq(self, channel):

        # Queue message handlers
        self.__handler_transaction = TraitementTransactionPersistee(self)
        self.__handler_cedule = TraitementMessageCedule(self)
        self.__handler_requetes_noeuds = TraitementRequetesNoeuds(self)

        nom_queue_transactions = '%s.%s' % (self.get_nom_queue(), 'transactions')
        nom_queue_ceduleur = '%s.%s' % (self.get_nom_queue(), 'ceduleur')
        nom_queue_processus = '%s.%s' % (self.get_nom_queue(), 'processus')
        nom_queue_requetes_noeuds = '%s.%s' % (self.get_nom_queue(), 'requete.noeuds')

        # Configurer la Queue pour les transactions
        def callback_init_transaction(queue, self=self, callback=self.__handler_transaction.callbackAvecAck):
            self.inscrire_basicconsume(queue, callback)
            channel.queue_bind(
                exchange=self.configuration.exchange_middleware,
                queue=nom_queue_transactions,
                routing_key='destinataire.domaine.%s.#' % self.get_nom_queue(),
                callback=None,
            )

        channel.queue_declare(
            queue=nom_queue_transactions,
            durable=False,
            callback=callback_init_transaction,
        )

        # Configuration la queue pour le ceduleur
        def callback_init_cedule(queue, self=self, callback=self.__handler_cedule.callbackAvecAck):
            self.inscrire_basicconsume(queue, callback)
            channel.queue_bind(
                exchange=self.configuration.exchange_middleware,
                queue=nom_queue_ceduleur,
                routing_key='ceduleur.#',
                callback=None,
            )

        channel.queue_declare(
            queue=nom_queue_ceduleur,
            durable=False,
            callback=callback_init_cedule,
        )

        # Queue pour les processus
        def callback_init_processus(queue, self=self, callback=self.traitement_evenements.callbackAvecAck):
            self.inscrire_basicconsume(queue, callback)
            channel.queue_bind(
                exchange=self.configuration.exchange_middleware,
                queue=nom_queue_processus,
                routing_key='processus.domaine.%s.#' % ConstantesMaitreDesCles.DOMAINE_NOM,
                callback=None,
            )

        channel.queue_declare(
            queue=nom_queue_processus,
            durable=False,
            callback=callback_init_processus,
        )

        # Queue pour les requetes de noeuds
        def callback_init_requetes_noeuds(queue, self=self, callback=self.__handler_requetes_noeuds.callbackAvecAck):
            self.inscrire_basicconsume(queue, callback)
            channel.queue_bind(
                exchange=self.configuration.exchange_noeuds,
                queue=nom_queue_requetes_noeuds,
                routing_key='requete.%s.#' % ConstantesMaitreDesCles.DOMAINE_NOM,
                callback=None,
            )

        channel.queue_declare(
            queue=nom_queue_requetes_noeuds,
            durable=False,
            callback=callback_init_requetes_noeuds,
        )

    def decrypter_contenu(self, contenu):
        """
        Utilise la cle privee en memoire pour decrypter le contenu.
        :param contenu:
        :return:
        """
        contenu_bytes = b64decode(contenu)

        contenu_decrypte = self.__cle_courante.decrypt(
            contenu_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return contenu_decrypte

    def get_nom_queue(self):
        return ConstantesMaitreDesCles.QUEUE_NOM

    def get_nom_collection(self):
        return ConstantesMaitreDesCles.COLLECTION_DOCUMENTS_NOM

    def get_collection_transaction_nom(self):
        return ConstantesMaitreDesCles.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesMaitreDesCles.COLLECTION_PROCESSUS_NOM

    def get_nom_domaine(self):
        return ConstantesMaitreDesCles.DOMAINE_NOM

    @property
    def get_certificat(self):
        return self.__certificat_courant

    @property
    def get_certificat_pem(self):
        return self.__certificat_courant_pem

    @property
    def get_certificats_backup(self):
        return self.__certificats_backup


class TraitementMessageCedule(BaseCallback):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire.contexte)
        self._gestionnaire = gestionnaire

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)
        routing_key = method.routing_key


class TraitementTransactionPersistee(BaseCallback):

    def __init__(self, gestionnaire: GestionnaireMaitreDesCles):
        super().__init__(gestionnaire.contexte)
        self._gestionnaire = gestionnaire

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)

        # Verifier quel processus demarrer. On match la valeur dans la routing key.
        routing_key = method.routing_key
        routing_key_sansprefixe = routing_key.replace(
            'destinataire.domaine.%s.' % ConstantesMaitreDesCles.DOMAINE_NOM,
            ''
        )

        if routing_key_sansprefixe == ConstantesMaitreDesCles.TRANSACTION_NOUVELLE_CLE_GROSFICHIER:
            processus = "millegrilles_domaines_MaitreDesCles:ProcessusNouvelleCleGrosFichier"
            self._gestionnaire.demarrer_processus(processus, message_dict)
        elif routing_key_sansprefixe == ConstantesMaitreDesCles.TRANSACTION_MAJ_DOCUMENT_CLES:
            processus = "millegrilles_domaines_MaitreDesCles:ProcessusMAJDocumentCles"
            self._gestionnaire.demarrer_processus(processus, message_dict)
        else:
            # Type de transaction inconnue, on lance une exception
            raise ValueError("Type de transaction inconnue: routing: %s, message: %s" % (routing_key, message_dict))


class TraitementRequetesNoeuds(BaseCallback):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire.contexte)
        self._gestionnaire = gestionnaire
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)

        # Verifier quel processus demarrer. On match la valeur dans la routing key.
        routing_key = method.routing_key
        routing_key_sansprefixe = routing_key.replace(
            'requete.%s.' % ConstantesMaitreDesCles.DOMAINE_NOM,
            ''
        )

        if routing_key_sansprefixe == ConstantesMaitreDesCles.REQUETE_CERT_MAITREDESCLES:
            # Transmettre le certificat courant du maitre des cles
            self.transmettre_certificat(properties)

        elif routing_key_sansprefixe == ConstantesMaitreDesCles.REQUETE_DECRYPTAGE_GROSFICHIER:
            processus = "millegrilles_domaines_MaitreDesCles:RequeteDecryptageCleGrosFichier"
            self._gestionnaire.demarrer_processus(processus, message_dict)
        else:
            # Type de transaction inconnue, on lance une exception
            raise ValueError("Type de transaction inconnue: routing: %s, message: %s" % (routing_key, message_dict))

    def transmettre_certificat(self, properties):
        """
        Transmet le certificat courant du MaitreDesCles au demandeur.
        :param properties:
        :return:
        """
        self._logger.debug("Transmettre certificat a %s" % properties.reply_to)
        # Genere message reponse
        message_resultat = {
            'certificat': self._gestionnaire.get_certificat_pem
        }

        self._gestionnaire.generateur.transmettre_reponse(
            message_resultat, properties.reply_to, properties.correlation_id
        )


class ProcessusNouvelleCleGrosFichier(MGProcessusTransaction):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def initiale(self):
        transaction = self.transaction

        cles_secretes_encryptees = dict()

        # Decrypter la cle secrete et la re-encrypter avec toutes les cles backup
        cle_secrete_encryptee = transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_CLESECRETE]
        self._logger.debug("Cle secrete encryptee: %s" % cle_secrete_encryptee)

        # Ajouter la cle secrete encryptee d'origine a la liste des cles
        cert_maitredescles = self._controleur.gestionnaire.get_certificat
        fingerprint_certmaitredescles = b64encode(cert_maitredescles.fingerprint(hashes.SHA1())).decode('utf-8')
        cles_secretes_encryptees[fingerprint_certmaitredescles] = cle_secrete_encryptee

        cle_secrete = self._controleur.gestionnaire.decrypter_contenu(cle_secrete_encryptee)
        # self._logger.debug("Cle secrete: %s" % cle_secrete)

        # Re-encrypter la cle secrete avec les cles backup
        if self._controleur.gestionnaire.get_certificats_backup is not None:
            for backup in self._controleur.gestionnaire.get_certificats_backup:
                cle_secrete_backup = backup.public_key().encrypt(
                    cle_secrete,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                fingerprint = b64encode(backup.fingerprint(hashes.SHA1())).decode('utf-8')
                cles_secretes_encryptees[fingerprint] = b64encode(cle_secrete_backup).decode('utf-8')

        self.set_etape_suivante(ProcessusNouvelleCleGrosFichier.generer_transaction_cles_backup.__name__)

        return {'fuuid': transaction['fuuid'], 'cles_secretes_encryptees': cles_secretes_encryptees}

    def generer_transaction_cles_backup(self):
        """
        Sauvegarder les cles de backup sous forme de transaction dans le domaine MaitreDesCles.
        Va aussi declencher la mise a jour du document de cles associe.
        :return:
        """
        generateur_transaction = GenerateurTransaction(self.contexte)

        transaction_nouvellescles = ConstantesMaitreDesCles.DOCUMENT_TRANSACTION_CONSERVER_CLES.copy()
        transaction_nouvellescles[ConstantesMaitreDesCles.TRANSACTION_CHAMP_SUJET_CLE] = \
            ConstantesMaitreDesCles.DOCUMENT_LIBVAL_CLES_GROSFICHIERS
        transaction_nouvellescles['fuuid'] = self.parametres['fuuid']
        transaction_nouvellescles['cles'] = self.parametres['cles_secretes_encryptees']

        # La transaction va mettre a jour (ou creer) les cles pour
        generateur_transaction.soumettre_transaction(
            transaction_nouvellescles,
            '%s.%s' % (ConstantesMaitreDesCles.DOMAINE_NOM, ConstantesMaitreDesCles.TRANSACTION_MAJ_DOCUMENT_CLES)
        )

        self.set_etape_suivante(ProcessusNouvelleCleGrosFichier.mettre_token_resumer_transaction.__name__)

    def mettre_token_resumer_transaction(self):
        """
        Mettre le token pour permettre a GrosFichier de resumer son processus de sauvegarde du fichier.
        :return:
        """
        self.set_etape_suivante()  # Termine


class ProcessusMAJDocumentCles(MGProcessusTransaction):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def initiale(self):
        transaction = self.transaction

        # Preparer la mise a jour (ou creation par upsert) du document de cles
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_SUJET_CLE],
            'fuuid': transaction['fuuid'],
        }

        contenu_on_insert = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: transaction[ConstantesMaitreDesCles.TRANSACTION_CHAMP_SUJET_CLE],
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
            'fuuid': transaction['fuuid'],
        }

        contenu_date = {
            Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True,
        }

        contenu_set = dict()
        for fingerprint in transaction['cles'].keys():
            cle_dict = 'cles.%s' % fingerprint;
            valeur = transaction['cles'].get(fingerprint)
            contenu_set[cle_dict] = valeur

        if transaction.get(ConstantesMaitreDesCles.DOCUMENT_SECURITE) is not None:
            contenu_set[ConstantesMaitreDesCles.DOCUMENT_SECURITE] = transaction[ConstantesMaitreDesCles.DOCUMENT_SECURITE]
        else:
            # Par defaut, on met le document en mode secure
            contenu_on_insert[ConstantesMaitreDesCles.DOCUMENT_SECURITE] = Constantes.SECURITE_SECURE

        operations = {
            '$set': contenu_set,
            '$currentDate': contenu_date,
            '$setOnInsert': contenu_on_insert,
        }

        collection_documents = self.contexte.document_dao.get_collection(ConstantesMaitreDesCles.COLLECTION_DOCUMENTS_NOM)
        self.__logger.debug("Operations: %s" % str({'filtre': filtre, 'operation': operations}))

        resultat_update = collection_documents.update_one(filter=filtre, update=operations, upsert=True)
        self._logger.info("_id du nouveau document MaitreDesCles: %s" % str(resultat_update.upserted_id))

        self.set_etape_suivante()  # Termine

        return {'filtre': filtre, 'operation': operations}

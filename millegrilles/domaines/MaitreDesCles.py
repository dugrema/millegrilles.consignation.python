# Domaine MaitreDesCles
# Responsable de la gestion et de l'acces aux cles secretes pour les niveaux 3.Protege et 4.Secure.

from millegrilles import Constantes
from millegrilles.Domaines import GestionnaireDomaine
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.MGProcessus import MGProcessus, MGProcessusTransaction
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles.dao.DocumentDAO import MongoJSONEncoder

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography import x509

import logging
import datetime


class ConstantesMaitreDesCles:

    DOMAINE_NOM = 'millegrilles.domaines.MaitreDesCles'
    COLLECTION_NOM = DOMAINE_NOM

    COLLECTION_TRANSACTIONS_NOM = COLLECTION_NOM
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_NOM
    QUEUE_NOM = DOMAINE_NOM

    LIBVAL_CONFIGURATION = 'configuration'

    TRANSACTION_NOUVELLE_CLE_GROSFICHIER = 'nouvelleCle,grosFichier'
    TRANSACTION_NOUVELLE_CLE_DOCUMENT = 'nouvelleCle,document'

    REQUETE_CERT_MAITREDESCLES = 'certMaitreDesCles'
    REQUETE_DECRYPTAGE_DOCUMENT = 'decryptageDocument'
    REQUETE_DECRYPTAGE_GROSFICHIER = 'decryptageGrosFichier'

    DOCUMENT_DEFAUT = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_CONFIGURATION
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

        # Queue message handlers
        self.__handler_transaction = None
        self.__handler_cedule = None
        self.__handler_requetes_noeuds = None

        self.generateur = GenerateurTransaction(self.contexte, encodeur_json=MongoJSONEncoder)

    def configurer(self):
        super().configurer()

        self.initialiser_document(ConstantesMaitreDesCles.LIBVAL_CONFIGURATION, ConstantesMaitreDesCles.DOCUMENT_DEFAUT)

        self.charger_certificat_courant()

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


class TraitementMessageCedule(BaseCallback):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire.contexte)
        self._gestionnaire = gestionnaire

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)
        routing_key = method.routing_key


class TraitementTransactionPersistee(BaseCallback):

    def __init__(self, gestionnaire):
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
        # Decrypter la cle secrete et la re-encrypter avec toutes les cles backup
        transaction = self.transaction
        self._logger.info("Transaction GrosFichier secure: %s" % str(transaction))
        self.set_etape_suivante(ProcessusNouvelleCleGrosFichier.generer_transaction_cles_backup.__name__)

    def generer_transaction_cles_backup(self):
        """
        Sauvegarder les cles de backup sous forme de transaction dans le domaine MaitreDesCles.
        Va aussi declencher la mise a jour du document de cles associe.
        :return:
        """
        self.set_etape_suivante(ProcessusNouvelleCleGrosFichier.mettre_token_resumer_transaction.__name__)

    def mettre_token_resumer_transaction(self):
        """
        Mettre le token pour permettre a GrosFichier de resumer son processus de sauvegarde du fichier.
        :return:
        """
        self.set_etape_suivante()  # Termine

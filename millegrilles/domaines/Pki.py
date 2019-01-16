# Domaine Public Key Infrastructure (PKI)

from millegrilles import Constantes
from millegrilles.Domaines import GestionnaireDomaine
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.MGProcessus import MGProcessusTransaction
from millegrilles.SecuritePKI import EnveloppeCertificat

import logging
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class ConstantesPki:

    DOMAINE_NOM = 'millegrilles.domaines.Pki'
    COLLECTION_NOM = 'millegrilles_domaines_Pki'
    QUEUE_NOM = DOMAINE_NOM

    LIBELLE_CERTIFICAT_PEM = 'certificat_pem'
    LIBELLE_FINGERPRINT = 'fingerprint'
    LIBELLE_FINGERPRINT_ISSUER = 'fingerprint_issuer'
    LIBELLE_DOCID_ISSUER = '_id_issuer'
    LIBELLE_CHAINE_COMPLETE = 'chaine_complete'
    LIBELLE_SUBJECT = 'sujet'
    LIBELLE_ISSUER = 'issuer'
    LIBELLE_NOT_VALID_BEFORE = 'not_valid_before'
    LIBELLE_NOT_VALID_AFTER = 'not_valid_after'
    LIBELLE_SUBJECT_KEY = 'subject_key'
    LIBELLE_AUTHORITY_KEY = 'authority_key'

    LIBVAL_CONFIGURATION = 'configuration'
    LIBVAL_CERTIFICAT_ROOT = 'certificat.root'
    LIBVAL_CERTIFICAT_INTERMEDIAIRE = 'certificat.intermediaire'
    LIBVAL_CERTIFICAT_MILLEGRILLE = 'certificat.millegrille'
    LIBVAL_CERTIFICAT_NOEUD = 'certificat.noeud'

    DELIM_DEBUT_CERTIFICATS = '-----BEGIN CERTIFICATE-----'

    TRANSACTION_EVENEMENT_CERTIFICAT = 'certificat'  # Indique que c'est une transaction avec un certificat a ajouter

    EVENEMENT_CERTIFICAT = 'pki.certificat'  # Indique que c'est un evenement avec un certificat (reference)
    EVENEMENT_REQUETE = 'pki.requete'  # Indique que c'est une requete pour trouver un certificat par fingerprint

    # Document par defaut pour la configuration de l'interface principale
    DOCUMENT_DEFAUT = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_CONFIGURATION
    }

    DOCUMENT_CERTIFICAT_NOEUD = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_CERTIFICAT_NOEUD,
        LIBELLE_CERTIFICAT_PEM: '',
        LIBELLE_FINGERPRINT: '',
        LIBELLE_CHAINE_COMPLETE: False
    }


class GestionnairePki(GestionnaireDomaine):

    def __init__(self, configuration=None, message_dao=None, document_dao=None, contexte=None):
        super().__init__(configuration, message_dao, document_dao, contexte)
        self._logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

        self._traitement_message = None

    def configurer(self):
        super().configurer()
        self._traitement_message = TraitementMessagePki(self)

        nom_queue_domaine = self.get_nom_queue()

        # Configurer la Queue pour les rapports sur RabbitMQ
        self.message_dao.channel.queue_declare(
            queue=nom_queue_domaine,
            durable=True)

        self.message_dao.channel.queue_bind(
            exchange=self.configuration.exchange_evenements,
            queue=nom_queue_domaine,
            routing_key='destinataire.domaine.%s.#' % nom_queue_domaine
        )

        self.message_dao.channel.queue_bind(
            exchange=self.configuration.exchange_evenements,
            queue=nom_queue_domaine,
            routing_key='ceduleur.#'
        )

        # Ecouter les evenements de type pki - servent a echanger certificats et requetes de certificats
        self.message_dao.channel.queue_bind(
            exchange=self.configuration.exchange_evenements,
            queue=nom_queue_domaine,
            routing_key='pki.#'
        )

        self.initialiser_document(ConstantesPki.LIBVAL_CONFIGURATION, ConstantesPki.DOCUMENT_DEFAUT)
        self.initialiser_mgca()

        # Index collection domaine
        collection_domaine = self.get_collection()
        # Index par fingerprint de certificat
        collection_domaine.create_index([
            (ConstantesPki.LIBELLE_FINGERPRINT, 1)
        ], unique=True)
        # Index par chaine de certificat verifie
        collection_domaine.create_index([
            (ConstantesPki.LIBELLE_CHAINE_COMPLETE, 2),
            (Constantes.DOCUMENT_INFODOC_LIBELLE, 1)
        ])

    def traiter_transaction(self, ch, method, properties, body):
        self._traitement_message.callbackAvecAck(ch, method, properties, body)

    def traiter_cedule(self, message):
        pass

    def get_nom_queue(self):
        return ConstantesPki.QUEUE_NOM

    def get_nom_collection(self):
        return ConstantesPki.COLLECTION_NOM

    def initialiser_mgca(self):
        """ Initialise les root CA """
        ca_file = self.configuration.mq_cafile

        with open(ca_file) as f:
            contenu = f.read()
            cles = contenu.split(ConstantesPki.DELIM_DEBUT_CERTIFICATS)[1:]
            self._logger.debug("Certificats ROOT configures: %s" % cles)

        collection = self.document_dao.get_collection(ConstantesPki.COLLECTION_NOM)
        for cle in cles:
            certificat_pem = '%s%s' % (ConstantesPki.DELIM_DEBUT_CERTIFICATS, cle)
            enveloppe = EnveloppeCertificat(certificat_pem=bytes(certificat_pem, 'utf-8'))
            fingerprint = enveloppe.fingerprint_ascii
            self._logger.debug("Verifier si certificat root %s existe deja dans MongoDB, inserer au besoin" % fingerprint)

            self._logger.debug("OUN pour cert = %s" % enveloppe.subject_organizational_unit_name)

            document_certca = ConstantesPki.DOCUMENT_CERTIFICAT_NOEUD.copy()
            maintenant = datetime.datetime.now(tz=datetime.timezone.utc)
            document_certca[Constantes.DOCUMENT_INFODOC_DATE_CREATION] = maintenant
            document_certca[Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION] = maintenant

            if enveloppe.certificat.issuer == enveloppe.certificat.subject:
                document_certca[Constantes.DOCUMENT_INFODOC_LIBELLE] = ConstantesPki.LIBVAL_CERTIFICAT_ROOT
            elif enveloppe.subject_organizational_unit_name == 'MilleGrille':
                document_certca[Constantes.DOCUMENT_INFODOC_LIBELLE] = ConstantesPki.LIBVAL_CERTIFICAT_MILLEGRILLE
            else:
                document_certca[Constantes.DOCUMENT_INFODOC_LIBELLE] = ConstantesPki.LIBVAL_CERTIFICAT_INTERMEDIAIRE
            document_certca[ConstantesPki.LIBELLE_CERTIFICAT_PEM] = certificat_pem
            document_certca[ConstantesPki.LIBELLE_FINGERPRINT] = fingerprint
            document_certca[ConstantesPki.LIBELLE_CHAINE_COMPLETE] = True  # Les certificats sont trusted implicitement
            document_certca[ConstantesPki.LIBELLE_SUBJECT] = enveloppe.formatter_subject()
            document_certca[ConstantesPki.LIBELLE_NOT_VALID_BEFORE] = enveloppe.not_valid_before
            document_certca[ConstantesPki.LIBELLE_NOT_VALID_AFTER] = enveloppe.not_valid_after
            document_certca[ConstantesPki.LIBELLE_SUBJECT_KEY] = enveloppe.subject_key_identifier
            document_certca[ConstantesPki.LIBELLE_AUTHORITY_KEY] = enveloppe.authority_key_identifier

            filtre = {
                ConstantesPki.LIBELLE_FINGERPRINT: fingerprint
            }
            collection.update_one(filtre, {'$setOnInsert': document_certca}, upsert=True)


class TraitementMessagePki(BaseCallback):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire.configuration)
        self._gestionnaire = gestionnaire

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)

        if evenement == Constantes.EVENEMENT_CEDULEUR:
            # Ceduleur, verifier si action requise
            self._gestionnaire.traiter_cedule(message_dict)
        elif evenement == Constantes.EVENEMENT_TRANSACTION_PERSISTEE:
            # Verifier quel processus demarrer. On match la valeur dans la routing key.
            routing_key = method.routing_key
            routing_key_sansprefixe = routing_key.replace(
                'destinataire.domaine.%s.' % ConstantesPki.DOMAINE_NOM,
                ''
            )

            if routing_key_sansprefixe == ConstantesPki.TRANSACTION_EVENEMENT_CERTIFICAT:
                processus = "millegrilles_domaines_Pki:ProcessusAjouterCertificat"
                self._gestionnaire.demarrer_processus(processus, message_dict)
            else:
                # Type de transaction inconnue, on lance une exception
                raise ValueError("Type de transaction inconnue: routing: %s, message: %s" % (routing_key, evenement))
        elif evenement == Constantes.EVENEMENT_PKI:
            routing_key = method.routing_key
            routing_key_sansprefixe = routing_key.replace('pki.', '')

        else:
            # Type d'evenement inconnu, on lance une exception
            raise ValueError("Type d'evenement inconnu: %s" % str(evenement))


class ProcessusAjouterCertificat(MGProcessusTransaction):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.transaction
        fingerprint = transaction['fingerprint']
        self._logger.debug("Chargement certificat fingerprint: %s" % fingerprint)

        # Verifier si on a deja les certificats
        collection = self.document_dao().get_collection(ConstantesPki.COLLECTION_NOM)
        certificat_existant = collection.find_one({'fingerprint': fingerprint})

        if certificat_existant is None:
            # Si on n'a pas le certificat, on le conserve et on lance la verification de chaine
            enveloppe_certificat = EnveloppeCertificat(certificat_pem=bytes(transaction['certificat_pem'], 'utf-8'))

            # Sauvegarder certificat #
            document_certificat = ConstantesPki.DOCUMENT_CERTIFICAT_NOEUD.copy()
            document_certificat[ConstantesPki.LIBELLE_CERTIFICAT_PEM] = transaction['certificat_pem']
            document_certificat[ConstantesPki.LIBELLE_FINGERPRINT] = enveloppe_certificat.fingerprint_ascii

            collection.insert_one(document_certificat)

            self.set_etape_suivante(ProcessusAjouterCertificat.verifier_chaine.__name__)
        else:
            self.set_etape_suivante()  # Termine

    def verifier_chaine(self):
        self.set_etape_suivante()  # Termine

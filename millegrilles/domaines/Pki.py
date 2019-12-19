# Domaine Public Key Infrastructure (PKI)

from millegrilles import Constantes
from millegrilles.Domaines import GestionnaireDomaineStandard, RegenerateurDeDocumentsSansEffet, TraitementRequetesNoeuds
from millegrilles.dao.MessageDAO import TraitementMessageDomaine, TraitementMessageDomaineRequete, CertificatInconnu
from millegrilles.MGProcessus import MGPProcesseur, MGProcessus, MGProcessusTransaction
from millegrilles.SecuritePKI import ConstantesSecurityPki, EnveloppeCertificat, VerificateurCertificats
from millegrilles.util.X509Certificate import PemHelpers

import logging
import datetime


class ConstantesPki:

    DOMAINE_NOM = 'millegrilles.domaines.Pki'
    COLLECTION_TRANSACTIONS_NOM = 'millegrilles.domaines.Pki'
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_TRANSACTIONS_NOM
    COLLECTION_PROCESSUS_NOM = 'millegrilles.domaines.Pki/processus'
    QUEUE_NOM = DOMAINE_NOM
    QUEUE_NOM_CERTIFICATS = '%s.certificats' % QUEUE_NOM

    TRANSACTION_DOMAINE_NOUVEAU_CERTIFICAT = '%s.nouveauCertificat' % DOMAINE_NOM
    TRANSACTION_WEB_NOUVEAU_CERTIFICAT = '%s.nouveauCertificat.web' % DOMAINE_NOM
    TRANSACTION_CLES_RECUES = '%s.clesRecues' % DOMAINE_NOM
    TRANSACTION_CONFIRMER_CERTIFICAT = '%s.confirmerCertificat' % DOMAINE_NOM

    LIBELLE_CERTIFICAT_PEM = ConstantesSecurityPki.LIBELLE_CERTIFICAT_PEM
    LIBELLE_FINGERPRINT = ConstantesSecurityPki.LIBELLE_FINGERPRINT
    LIBELLE_IDMG = 'idmg'
    LIBELLE_FINGERPRINT_ISSUER = 'fingerprint_issuer'
    LIBELLE_DOCID_ISSUER = '_id_issuer'
    LIBELLE_CHAINE_COMPLETE = 'chaine_complete'
    LIBELLE_SUBJECT = 'sujet'
    LIBELLE_ISSUER = 'issuer'
    LIBELLE_NOT_VALID_BEFORE = 'not_valid_before'
    LIBELLE_NOT_VALID_AFTER = 'not_valid_after'
    LIBELLE_SUBJECT_KEY = 'subject_key'
    LIBELLE_AUTHORITY_KEY = 'authority_key'
    LIBELLE_TRANSACTION_FAITE = 'transaction_faite'
    LIBELLE_CHAINES = 'chaines'
    LIBELLE_MGLIBELLE = 'mg-libelle'
    LIBELLE_CLE_CRYPTEE = 'cle_cryptee'

    LIBVAL_CONFIGURATION = 'configuration'
    LIBVAL_CERTIFICAT_ROOT = 'certificat.root'
    LIBVAL_CERTIFICAT_INTERMEDIAIRE = 'certificat.intermediaire'
    LIBVAL_CERTIFICAT_MILLEGRILLE = 'certificat.millegrille'
    LIBVAL_CERTIFICAT_NOEUD = 'certificat.noeud'
    LIBVAL_PKI_WEB = 'pki.web'

    REQUETE_CERTIFICAT_EMIS = 'pki.certificat'
    REQUETE_CERTIFICAT_DEMANDE = 'pki.requete.certificat'
    REQUETE_LISTE_CA = 'pki.requete.ca'
    TRANSACTION_EVENEMENT_CERTIFICAT = 'certificat'  # Indique que c'est une transaction avec un certificat a ajouter

    # Indique que c'est un evenement avec un certificat (reference)
    EVENEMENT_CERTIFICAT = ConstantesSecurityPki.EVENEMENT_CERTIFICAT
    # Indique que c'est une requete pour trouver un certificat par fingerprint
    EVENEMENT_REQUETE = ConstantesSecurityPki.EVENEMENT_REQUETE

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


class GestionnairePki(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

        self._pki_document_helper = None
        self.__traitement_certificats = None
        self.__traitement_requetes_noeuds = None

    def configurer(self):
        super().configurer()
        self._pki_document_helper = PKIDocumentHelper(self._contexte, self.demarreur_processus)
        self.__traitement_certificats = TraitementRequeteCertificat(self, self._pki_document_helper)
        self.__traitement_requetes_noeuds = TraitementRequetePki(self, self._pki_document_helper)

        self.initialiser_mgca()  # S'assurer que les certs locaux sont prets avant les premieres transactions

        # Index collection domaine
        collection_domaine = self.get_collection()
        # Index par fingerprint de certificat
        collection_domaine.create_index(
            [
                (ConstantesPki.LIBELLE_FINGERPRINT, 1)
            ],
            name='fingerprinte',
            unique=True
        )
        # Index par chaine de certificat verifie
        collection_domaine.create_index(
            [
                (ConstantesPki.LIBELLE_CHAINE_COMPLETE, 2),
                (Constantes.DOCUMENT_INFODOC_LIBELLE, 1)
            ],
            name='complete-mglibelle'
        )
        # Index pour trouver l'autorite qui a signe un certificat (par son subject)
        collection_domaine.create_index(
            [
                (ConstantesPki.LIBELLE_SUBJECT_KEY, 1),
                (ConstantesPki.LIBELLE_NOT_VALID_BEFORE, 1),
                (ConstantesPki.LIBELLE_NOT_VALID_AFTER, 1)
            ],
            name='subject-valid'
        )

    def demarrer(self):
        super().demarrer()
        self.initialiser_document(ConstantesPki.LIBVAL_CONFIGURATION, ConstantesPki.DOCUMENT_DEFAUT)

    def get_queue_configuration(self):
        configuration = super().get_queue_configuration()

        configuration_pki = [
            {
                'nom': '%s.%s' % (self.get_nom_queue(), 'certificats'),
                'routing': [
                    '%s.#' % ConstantesPki.REQUETE_CERTIFICAT_EMIS,
                ],
                'exchange': self.configuration.exchange_middleware,
                'callback': self.__traitement_certificats.callbackAvecAck
            },
            {
                'nom': '%s.%s' % (self.get_nom_queue(), 'certificats'),
                'routing': [
                    '%s.#' % ConstantesPki.REQUETE_CERTIFICAT_EMIS,
                    ConstantesPki.REQUETE_LISTE_CA,
                ],
                'exchange': self.configuration.exchange_noeuds,
                'callback': self.__traitement_certificats.callbackAvecAck
            },
            {
                'nom': '%s.%s' % (self.get_nom_queue(), 'certificats'),
                'routing': [
                    '%s.#' % ConstantesPki.REQUETE_CERTIFICAT_EMIS,
                ],
                'exchange': self.configuration.exchange_prive,
                'callback': self.__traitement_certificats.callbackAvecAck
            },
        ]

        configuration.extend(configuration_pki)

        return configuration

    def traiter_cedule(self, evenement):

        indicateurs = evenement['indicateurs']
        self._logger.debug("Cedule webPoll: %s" % str(indicateurs))

        # Faire la liste des cedules a declencher
        if 'heure' in indicateurs:
            # declencher workflow pour trouver les certificats dans MongoDB qui ne sont pas encore valides
            processus = "%s:%s" % (
                ConstantesPki.DOMAINE_NOM,
                ProcessusVerifierChaineCertificatsNonValides.__name__
            )
            self.demarrer_processus(processus, dict())

    def get_nom_queue(self):
        return ConstantesPki.QUEUE_NOM

    def get_nom_queue_certificats(self):
        return ConstantesPki.QUEUE_NOM

    def get_nom_collection(self):
        return ConstantesPki.COLLECTION_DOCUMENTS_NOM

    def get_collection_transaction_nom(self):
        return ConstantesPki.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesPki.COLLECTION_PROCESSUS_NOM

    def initialiser_mgca(self):
        """ Initialise les root CA et noeud middleware (ou local) """

        verificateur = self._contexte.verificateur_certificats

        with open(self.configuration.pki_cafile, 'r') as f:
            contenu = f.read()
            pems = PemHelpers.split_certificats(contenu)
            self._logger.debug("Certificats ROOT configures: %s" % pems)

        for cert in pems:
            enveloppe = EnveloppeCertificat(certificat_pem=cert.encode('utf-8'))
            self._logger.debug("OUN pour cert = %s" % enveloppe.subject_organizational_unit_name)
            self._pki_document_helper.inserer_certificat(enveloppe, trusted=True)
            verificateur.charger_certificat(enveloppe=enveloppe)

        mq_certfile = self.configuration.mq_certfile
        with open(mq_certfile, 'r') as f:
            contenu_pem = f.read()
        pems = PemHelpers.split_certificats(contenu_pem)
        pems.reverse()  # Commencer par les certs intermediaires
        for cert_pem in pems:
            enveloppe = EnveloppeCertificat(certificat_pem=cert_pem.encode('utf-8'))
            verificateur.charger_certificat(enveloppe=enveloppe)
            self._logger.debug("Certificats noeud local: %s" % contenu)

            # Verifier la chaine immediatement, permet d'ajouter le cert avec Trusted=True
            self._pki_document_helper.inserer_certificat(enveloppe, trusted=True)

        # Demarrer validation des certificats
        # declencher workflow pour trouver les certificats dans MongoDB qui ne sont pas encore valides
        # processus = "%s:%s" % (
        #     ConstantesPki.DOMAINE_NOM,
        #     ProcessusVerifierChaineCertificatsNonValides.__name__
        # )
        # self.demarrer_processus(processus, dict())

    def get_nom_domaine(self):
        return ConstantesPki.DOMAINE_NOM

    def identifier_processus(self, domaine_transaction):
        if domaine_transaction == ConstantesPki.TRANSACTION_DOMAINE_NOUVEAU_CERTIFICAT:
            processus = "millegrilles_domaines_Pki:ProcessusAjouterCertificat"
        elif domaine_transaction == ConstantesPki.TRANSACTION_WEB_NOUVEAU_CERTIFICAT:
            processus = "millegrilles_domaines_Pki:ProcessusAjouterCertificatWeb"
        elif domaine_transaction == ConstantesPki.TRANSACTION_CLES_RECUES:
            processus = "millegrilles_domaines_Pki:ProcessusClesRecues"
        else:
            processus = super().identifier_processus(domaine_transaction)
        return processus

    def creer_regenerateur_documents(self):
        return RegenerateurDeDocumentsSansEffet(self)

    def get_handler_requetes_noeuds(self):
        return self.__traitement_requetes_noeuds


class PKIDocumentHelper:

    def __init__(self, contexte, mg_processus_demarreur):
        self._contexte = contexte
        # self._mg_processus_demarreur = MGPProcessusDemarreur(self._contexte)
        self._mg_processus_demarreur = mg_processus_demarreur

    def inserer_certificat(self, enveloppe, trusted=False, correlation_csr: str = None):
        document_cert = ConstantesPki.DOCUMENT_CERTIFICAT_NOEUD.copy()
        fingerprint = enveloppe.fingerprint_ascii

        maintenant = datetime.datetime.now(tz=datetime.timezone.utc)
        document_cert[Constantes.DOCUMENT_INFODOC_DATE_CREATION] = maintenant
        document_cert[Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION] = maintenant

        document_cert[ConstantesPki.LIBELLE_CERTIFICAT_PEM] = enveloppe.certificat_pem
        document_cert[ConstantesPki.LIBELLE_FINGERPRINT] = fingerprint
        document_cert[ConstantesPki.LIBELLE_SUBJECT] = enveloppe.formatter_subject()
        document_cert[ConstantesPki.LIBELLE_NOT_VALID_BEFORE] = enveloppe.not_valid_before
        document_cert[ConstantesPki.LIBELLE_NOT_VALID_AFTER] = enveloppe.not_valid_after
        document_cert[ConstantesPki.LIBELLE_SUBJECT_KEY] = enveloppe.subject_key_identifier
        document_cert[ConstantesPki.LIBELLE_AUTHORITY_KEY] = enveloppe.authority_key_identifier
        document_cert[ConstantesPki.LIBELLE_TRANSACTION_FAITE] = False

        if correlation_csr is not None:
            document_cert[ConstantesSecurityPki.LIBELLE_CORRELATION_CSR] = correlation_csr

        if enveloppe.is_rootCA:
            document_cert[Constantes.DOCUMENT_INFODOC_LIBELLE] = ConstantesPki.LIBVAL_CERTIFICAT_ROOT
            document_cert[ConstantesPki.LIBELLE_IDMG] = enveloppe.idmg
            # Le certificat root est trusted implicitement quand il est charge a partir d'un fichier local
            document_cert[ConstantesPki.LIBELLE_CHAINE_COMPLETE] = True
        elif enveloppe.is_CA:
            document_cert[Constantes.DOCUMENT_INFODOC_LIBELLE] = ConstantesPki.LIBVAL_CERTIFICAT_MILLEGRILLE
            document_cert[ConstantesPki.LIBELLE_IDMG] = enveloppe.subject_organization_name


        filtre = {
            ConstantesPki.LIBELLE_FINGERPRINT: fingerprint
        }

        collection = self._contexte.document_dao.get_collection(ConstantesPki.COLLECTION_DOCUMENTS_NOM)
        result = collection.update_one(filtre, {'$setOnInsert': document_cert}, upsert=True)
        if result.matched_count == 0:
            # Le document vient d'etre insere, on va aussi transmettre une nouvelle transaction pour l'ajouter
            # de manier permanente
            transaction = {
                ConstantesPki.LIBELLE_CERTIFICAT_PEM: enveloppe.certificat_pem,
                ConstantesPki.LIBELLE_FINGERPRINT: fingerprint,
                ConstantesPki.LIBELLE_SUBJECT: enveloppe.formatter_subject(),
            }
            self._contexte.generateur_transactions.soumettre_transaction(
                transaction,
                domaine=ConstantesPki.TRANSACTION_DOMAINE_NOUVEAU_CERTIFICAT
            )

        # # Demarrer validation des certificats
        # # declencher workflow pour trouver les certificats dans MongoDB qui ne sont pas encore valides
        # processus = "%s:%s" % (
        #     ConstantesPki.DOMAINE_NOM,
        #     ProcessusVerifierChaineCertificatsNonValides.__name__
        # )
        # self._mg_processus_demarreur.demarrer_processus(processus, dict())

    def charger_certificat(self, fingerprint=None, subject=None):
        filtre = dict()
        if fingerprint is not None:
            filtre[ConstantesPki.LIBELLE_FINGERPRINT] = fingerprint
        if subject is not None:
            filtre[ConstantesPki.LIBELLE_SUBJECT_KEY] = subject

        # Lire les certificats et les charger dans des enveloppes
        collection = self._contexte.document_dao.get_collection(ConstantesPki.COLLECTION_DOCUMENTS_NOM)
        curseur = collection.find(filtre)
        liste_certificats = list()
        for certificat in curseur:
            # Charger l'enveloppe
            enveloppe = EnveloppeCertificat(certificat_pem=certificat[ConstantesPki.LIBELLE_CERTIFICAT_PEM])
            liste_certificats.append(enveloppe)

        return liste_certificats

    def identifier_certificats_non_valide(self, authority_key=None):
        """
        Fait une liste des fingerprints de certificats qui ne sont pas encore valides.
        :param authority_key: Optionnel, va charger tous les certificats pas encore valides associes a cette autorite.
        :return: Liste de fingerprints
        """
        filtre = {
            ConstantesPki.LIBELLE_CHAINE_COMPLETE: False
        }

        if authority_key is not None:
            filtre[ConstantesPki.LIBELLE_AUTHORITY_KEY] = authority_key

        collection = self._contexte.document_dao.get_collection(ConstantesPki.COLLECTION_DOCUMENTS_NOM)
        curseur = collection.find(filtre)
        fingerprints = list()
        for certificat in curseur:
            fingerprint = certificat[ConstantesPki.LIBELLE_FINGERPRINT]
            fingerprints.append(fingerprint)

        return fingerprints

    def marquer_certificats_valides(self, fingerprints):

        filtre = {
            ConstantesPki.LIBELLE_FINGERPRINT: {'$in': fingerprints}
        }

        operation = {
            '$set': {
                ConstantesPki.LIBELLE_CHAINE_COMPLETE: True
            }
        }

        collection = self._contexte.document_dao.get_collection(ConstantesPki.COLLECTION_DOCUMENTS_NOM)
        collection.update(filtre, operation, multi=True)


class ProcessusAjouterCertificat(MGProcessusTransaction):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction(ConstantesPki.COLLECTION_TRANSACTIONS_NOM)
        fingerprint = transaction['fingerprint']
        self._logger.debug("Chargement certificat fingerprint: %s" % fingerprint)

        # Verifier si on a deja les certificats
        collection = self.document_dao.get_collection(ConstantesPki.COLLECTION_DOCUMENTS_NOM)
        certificat_existant = collection.find_one({'fingerprint': fingerprint})

        if certificat_existant is None:
            # Si on n'a pas le certificat, on le conserve et on lance la verification de chaine
            enveloppe_certificat = EnveloppeCertificat(certificat_pem=bytes(transaction['certificat_pem'], 'utf-8'))

            # Sauvegarder certificat #
            document_certificat = ConstantesPki.DOCUMENT_CERTIFICAT_NOEUD.copy()
            document_certificat[ConstantesPki.LIBELLE_CERTIFICAT_PEM] = transaction['certificat_pem']
            document_certificat[ConstantesPki.LIBELLE_FINGERPRINT] = enveloppe_certificat.fingerprint_ascii
            document_certificat[ConstantesPki.LIBELLE_IDMG] = enveloppe_certificat.idmg

            collection.insert_one(document_certificat)

            self.set_etape_suivante(ProcessusAjouterCertificat.verifier_chaine.__name__)

        else:
            filtre = {'fingerprint': fingerprint}
            operations = {'$set': {ConstantesPki.LIBELLE_TRANSACTION_FAITE: True}}
            collection.update_one(filtre, operations)

            if certificat_existant.get(ConstantesPki.LIBELLE_CHAINE_COMPLETE):
                self.set_etape_suivante()  # Termine
            else:
                self.set_etape_suivante(ProcessusAjouterCertificat.verifier_chaine.__name__)

        return {'fingerprint': fingerprint}

    def verifier_chaine(self):
        # Demarrer processus verification
        verificateur = VerificateurCertificats(self._controleur.contexte)
        fingerprint = self.parametres['fingerprint']

        # Charger le certificat et verifier si on peut valider la chaine
        valide = False
        try:
            enveloppe = verificateur.charger_certificat(fingerprint=fingerprint)
            if enveloppe is not None:
                verificateur.verifier_chaine(enveloppe)
                valide = True

                commande_publier_certificat = {
                    ConstantesPki.LIBELLE_CERTIFICAT_PEM: enveloppe.certificat_pem,
                }
                self.generateur_transactions.transmettre_commande(commande_publier_certificat, 'commande.publicateur.publierCertificat')

        except Exception as e:
            self._logger.warn("Certificat invalide: %s" % fingerprint)
            self._logger.debug("Certificat pas encore valide %s: %s" % (fingerprint, str(e)))

        if valide:
            helper = PKIDocumentHelper(self._controleur.contexte, self._controleur.demarreur_processus)
            helper.marquer_certificats_valides([fingerprint])

        # Transmettre commande au publicateur pour inserer le certificat dans le repertoire certs


        self.set_etape_suivante()  # Termine

        return {'valide': valide}

    def get_collection_transaction_nom(self):
        return ConstantesPki.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesPki.COLLECTION_PROCESSUS_NOM


class ProcessusAjouterCertificatWeb(MGProcessusTransaction):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction(ConstantesPki.COLLECTION_TRANSACTIONS_NOM)
        fingerprint = transaction['fingerprint']
        self._logger.debug("Chargement certificat web, nouveau fingerprint %s" % fingerprint)

        certificat_web = transaction[ConstantesPki.LIBELLE_CERTIFICAT_PEM]
        enveloppe_cert = EnveloppeCertificat(certificat_pem=certificat_web)
        not_valid_before = enveloppe_cert.not_valid_before
        not_valid_after = enveloppe_cert.not_valid_after

        ops = {
            '$set': {
                ConstantesPki.LIBELLE_CERTIFICAT_PEM: transaction[ConstantesPki.LIBELLE_CERTIFICAT_PEM],
                ConstantesPki.LIBELLE_FINGERPRINT: fingerprint,
                ConstantesPki.LIBELLE_CHAINES: transaction[ConstantesPki.LIBELLE_CHAINES],
                ConstantesPki.LIBELLE_SUBJECT: transaction[ConstantesPki.LIBELLE_SUBJECT],
                ConstantesPki.LIBELLE_NOT_VALID_BEFORE: not_valid_before,
                ConstantesPki.LIBELLE_NOT_VALID_AFTER: not_valid_after,
                ConstantesPki.LIBELLE_CLE_CRYPTEE: transaction[ConstantesPki.LIBELLE_CLE_CRYPTEE],
            },
            '$setOnInsert': {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPki.LIBVAL_PKI_WEB,
                Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
            },
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }

        # Sauvegarder document
        filtre = {Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPki.LIBVAL_PKI_WEB}
        collection = self.document_dao.get_collection(ConstantesPki.COLLECTION_DOCUMENTS_NOM)
        collection.update_one(filtre, ops, upsert=True)

        uuid = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
        token_resumer = '%s:%s:%s' % (ConstantesPki.TRANSACTION_CLES_RECUES, ConstantesPki.LIBVAL_PKI_WEB, uuid)
        self.set_etape_suivante(
            ProcessusAjouterCertificatWeb.transmettre_commande_majweb.__name__,
            token_attente=[token_resumer]
        )

        return {
            'fingerprint': fingerprint,
            ConstantesPki.LIBELLE_NOT_VALID_BEFORE: not_valid_before,
            ConstantesPki.LIBELLE_NOT_VALID_AFTER: not_valid_after,
        }

    def transmettre_commande_majweb(self):
        """
        Transmettre une commande pour mettre a jour les certificats web
        :return:
        """

        commande = {
            'fingerprint': self.parametres['fingerprint'],
            ConstantesPki.LIBELLE_NOT_VALID_AFTER: int(self.parametres[ConstantesPki.LIBELLE_NOT_VALID_AFTER].timestamp())
        }
        self.generateur_transactions.transmettre_commande(commande, 'commande.monitor.maj.cerificatsWeb')

        self.set_etape_suivante()  # Termine


class ProcessusVerifierChaineCertificatsNonValides(MGProcessus):

    PARAM_A_VERIFIER = 'fingerprints_a_verifier'
    PARAM_VALIDE = 'fingerprints_valides'
    PARAM_INVALIDE = 'fingerprints_invalides'

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)
        self._helper = PKIDocumentHelper(self._controleur.contexte, self._controleur.demarreur_processus)

    def initiale(self):
        liste_fingerprints = self._helper.identifier_certificats_non_valide()

        resultat = {}
        if len(liste_fingerprints) > 0:
            resultat[ProcessusVerifierChaineCertificatsNonValides.PARAM_A_VERIFIER] = liste_fingerprints
            self.set_etape_suivante(ProcessusVerifierChaineCertificatsNonValides.verifier_chaines.__name__)
        else:
            self.set_etape_suivante()

        return resultat

    def verifier_chaines(self):

        parametres = self.parametres
        fingerprints = parametres.get(ProcessusVerifierChaineCertificatsNonValides.PARAM_A_VERIFIER)

        verificateur = VerificateurCertificats(self._controleur.contexte)

        liste_valide = list()
        liste_invalide = list()
        for fingerprint in fingerprints:
            # Charger le certificat et verifier si on peut valider la chaine
            try:
                enveloppe = verificateur.charger_certificat(fingerprint=fingerprint)
                if enveloppe is not None:
                    verificateur.verifier_chaine(enveloppe)
                    liste_valide.append(fingerprint)
            except Exception as e:
                self._logger.warn("Certificat invalide: %s" % fingerprint)
                self._logger.debug("Certificat pas encore valide %s: %s" % (fingerprint, str(e)))

            if fingerprint not in liste_valide:
                liste_invalide.append(fingerprint)

        resultat = {
            ProcessusVerifierChaineCertificatsNonValides.PARAM_VALIDE: liste_valide,
            ProcessusVerifierChaineCertificatsNonValides.PARAM_INVALIDE: liste_invalide
        }

        if len(liste_valide) > 0:
            self.set_etape_suivante(ProcessusVerifierChaineCertificatsNonValides.marquer_certificats_valides.__name__)
        elif len(liste_invalide) > 0:
            self.set_etape_suivante(ProcessusVerifierChaineCertificatsNonValides.chercher_certificats_invalides.__name__)
        else:
            self.set_etape_suivante()

        return resultat

    def marquer_certificats_valides(self):
        parametres = self.parametres

        fingerprints = parametres.get(ProcessusVerifierChaineCertificatsNonValides.PARAM_VALIDE)
        self._helper.marquer_certificats_valides(fingerprints)

        if len(parametres[ProcessusVerifierChaineCertificatsNonValides.PARAM_INVALIDE]) > 0:
            self.set_etape_suivante(ProcessusVerifierChaineCertificatsNonValides.chercher_certificats_invalides.__name__)
        else:
            self.set_etape_suivante()

    def chercher_certificats_invalides(self):
        self.set_etape_suivante()

    def get_collection_transaction_nom(self):
        return ConstantesPki.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesPki.COLLECTION_PROCESSUS_NOM


class TraitementRequeteCertificat(TraitementMessageDomaine):

    def __init__(self, gestionnaire_domaine, pki_document_helper):
        super().__init__(gestionnaire_domaine)
        self.__pki_document_helper = pki_document_helper
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        # Pas de verification du contenu - le certificat est sa propre validation via CAs
        # self.gestionnaire.verificateur_transaction.verifier(message_dict)

        if method.routing_key.startswith(ConstantesPki.REQUETE_CERTIFICAT_EMIS):
            self.recevoir_certificat(message_dict)
        elif method.routing_key.startswith(ConstantesPki.REQUETE_CERTIFICAT_DEMANDE):
            self.transmettre_certificat(properties, message_dict)
        elif method.routing_key.startswith(ConstantesPki.REQUETE_LISTE_CA):
            self.transmettre_liste_ca(properties, message_dict)
        elif method.routing_key.startswith(ConstantesPki.TRANSACTION_CONFIRMER_CERTIFICAT):
            self.confirmer_certificat(properties, message_dict)

        else:
            raise Exception("Type evenement inconnu: %s" % method.routing_key)

    def recevoir_certificat(self, message_dict):
        enveloppe = EnveloppeCertificat(certificat_pem=message_dict[ConstantesPki.LIBELLE_CERTIFICAT_PEM])
        correlation_csr = message_dict.get(ConstantesSecurityPki.LIBELLE_CORRELATION_CSR)
        # Enregistrer le certificat - le helper va verifier si c'est un nouveau certificat ou si on l'a deja
        self.__pki_document_helper.inserer_certificat(enveloppe, correlation_csr=correlation_csr)

    def transmettre_certificat(self, properties, message_dict):
        pass

    def confirmer_certificat(self, properties, message_dict):
        """
        Confirme la validute d'un certificat.
        """
        reponse = dict()
        if message_dict.get('fingerprint'):
            fingerprint = message_dict['fingerprint']
            self.__logger.debug("Requete verification certificat par fingerprint: %s" % fingerprint)
            # Charge un certificat connu
            enveloppe_cert = self.configuration.verificateur_certificats.charger_certificat(fingerprint=fingerprint)
            if enveloppe_cert is not None:
                reponse['valide'] = True

                # Retourner quelques elements utiles pour des composants javascript, comme la cle publique

            else:
                reponse['valide'] = False
        else:
            reponse['valide'] = False

        self.gestionnaire.generateur_transactions.transmettre_reponse(
            reponse, properties.reply_to, properties.correlation_id)


    def transmettre_liste_ca(self, properties, message_dict):
        ca_file = self.configuration.mq_cafile

        with open(ca_file, 'r') as f:
            contenu = f.read()

        reponse = {
            ConstantesSecurityPki.LIBELLE_CHAINE_PEM: contenu
        }

        self.gestionnaire.generateur_transactions.transmettre_reponse(
            reponse, properties.reply_to, properties.correlation_id)


class TraitementRequetePki(TraitementRequetesNoeuds):

    def __init__(self, gestionnaire_domaine, pki_document_helper):
        super().__init__(gestionnaire_domaine)
        self.__pki_document_helper = pki_document_helper
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        # Pas de verification du contenu - le certificat est sa propre validation via CAs
        # self.gestionnaire.verificateur_transaction.verifier(message_dict)

        domaine_routing_key = method.routing_key.replace('requete.', '')

        if domaine_routing_key.startswith(ConstantesPki.TRANSACTION_CONFIRMER_CERTIFICAT):
            self.confirmer_certificat(properties, message_dict)

        else:
            super().traiter_message(ch, method, properties, body)

    def confirmer_certificat(self, properties, message_dict):
        """
        Confirme la validute d'un certificat.
        """
        reponse = dict()
        if message_dict.get('fingerprint'):
            fingerprint = message_dict['fingerprint']
            self.__logger.debug("Requete verification certificat par fingerprint: %s" % fingerprint)
            # Charge un certificat connu
            enveloppe_cert = self.gestionnaire.verificateur_certificats.charger_certificat(fingerprint=fingerprint)
            if enveloppe_cert is not None:
                reponse['valide'] = enveloppe_cert.est_verifie

                # Retourner quelques elements utiles pour des composants javascript, comme la cle publique
                cle_publique = enveloppe_cert.public_key
                reponse['certificat'] = enveloppe_cert.certificat_pem
                reponse['roles'] = enveloppe_cert.get_roles

            else:
                reponse['valide'] = False
        else:
            reponse['valide'] = False

        self.gestionnaire.generateur_transactions.transmettre_reponse(
            reponse, properties.reply_to, properties.correlation_id)


class ProcessusClesRecues(MGProcessusTransaction):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def traitement_regenerer(self, id_transaction, parametres_processus):
        pass  # Rien a faire pour cette transaction

    def initiale(self):
        """
        Emet un evenement pour indiquer que les cles sont recues par le MaitreDesCles.
        """
        transaction = self.charger_transaction()
        identificateurs_documents = transaction['identificateurs_document']
        mg_libelle = identificateurs_documents[Constantes.DOCUMENT_INFODOC_LIBELLE]
        uuid = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]

        token_resumer = '%s:%s:%s' % (ConstantesPki.TRANSACTION_CLES_RECUES, mg_libelle, uuid)
        self.resumer_processus([token_resumer])

        self.set_etape_suivante()  # Termine
        return {ConstantesPki.LIBELLE_MGLIBELLE: mg_libelle}

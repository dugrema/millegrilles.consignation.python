# Domaine Public Key Infrastructure (PKI)

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesPki
from millegrilles.Erreurs import ErreurModeRegeneration
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementMessageDomaineRequete, TraitementRequetesProtegees, MGPProcesseurTraitementEvenements
from millegrilles.dao.MessageDAO import TraitementMessageDomaine
from millegrilles.MGProcessus import MGPProcesseur, MGProcessus, MGProcessusTransaction
from millegrilles.SecuritePKI import ConstantesSecurityPki, EnveloppeCertificat, VerificateurCertificats
from millegrilles.util.X509Certificate import PemHelpers, ConstantesGenerateurCertificat

import logging
import datetime


class TraitementRequetesPubliques(TraitementMessageDomaineRequete):

    def traiter_requete(self, ch, method, properties, body, message_dict):
        routing_key = method.routing_key

        if routing_key.startswith(ConstantesPki.REQUETE_CERTIFICAT_DEMANDE):
            fingerprint = routing_key.split('.')[-1]
            reponse = self.gestionnaire.get_certificat(fingerprint)
        else:
            raise Exception("Requete publique non supportee " + routing_key)

        if reponse is not None:
            self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)


class TraitementRequetesProtegeesPki(TraitementRequetesProtegees):

    def __init__(self, gestionnaire_domaine):
        super().__init__(gestionnaire_domaine)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def traiter_requete(self, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        domaine_routing_key = routing_key.replace('requete.%s.' % ConstantesPki.DOMAINE_NOM, '')

        if properties.reply_to and properties.correlation_id:
            reponse = None
            if domaine_routing_key == ConstantesPki.REQUETE_CONFIRMER_CERTIFICAT:
                reponse = self.gestionnaire.confirmer_certificat(properties, message_dict)
            elif domaine_routing_key.startswith('requete.certificat.'):
                fingerprint = message_dict.get('fingerprint') or domaine_routing_key.split('.')[-1]
                reponse = self.gestionnaire.get_certificat(fingerprint, properties, demander_si_inconnu=False)
            elif domaine_routing_key == ConstantesPki.REQUETE_CERTIFICAT_BACKUP:
                reponse = self.gestionnaire.get_certificats_backup()
            elif domaine_routing_key == ConstantesPki.REQUETE_LISTE_CERT_COMPTES_NOEUDS:
                reponse = {'liste': self.gestionnaire.get_liste_certificats_noeuds()}
            elif domaine_routing_key == ConstantesPki.REQUETE_LISTE_CERTS_CA:
                reponse = self.gestionnaire.get_liste_certificats_ca()
            else:
                super().traiter_requete(ch, method, properties, body, message_dict)

            if reponse is not None:
                self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)
        else:
            self.__logger.warning("Reception requete sans reply_to/correlation_id:\n%s", str(message_dict))


class TraitementEvenementsPki(MGPProcesseurTraitementEvenements):

    def traiter_message(self, ch, method, properties, body):
        routing_key = method.routing_key

        if routing_key == ConstantesPki.REQUETE_CERTIFICAT_EMIS:
            message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
            self.gestionnaire.recevoir_certificat(message_dict)
        else:
            super().traiter_message(ch, method, properties, body)


class GestionnairePki(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

        self._pki_document_helper = None
        self.__traitement_certificats = None

        handler_requetes_protegees = TraitementRequetesProtegeesPki(self)
        handler_requetes_publiques = TraitementRequetesPubliques(self)

        self.__handler_requetes_noeuds = {
            Constantes.SECURITE_SECURE: handler_requetes_protegees,
            Constantes.SECURITE_PROTEGE: handler_requetes_protegees,
            Constantes.SECURITE_PRIVE: handler_requetes_publiques,
            Constantes.SECURITE_PUBLIC: handler_requetes_publiques,
        }

    def configurer(self):
        super().configurer()
        self._pki_document_helper = PKIDocumentHelper(self._contexte, self.demarreur_processus)
        self.__traitement_certificats = TraitementRequeteCertificat(self, self._pki_document_helper)

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
        self.initialiser_document(ConstantesPki.LIBVAL_CONFIG_CERTDOCKER, ConstantesPki.DOCUMENT_CONFIG_CERTDOCKER)

    def initialiser_mgprocesseur_evenements(self):
        """
        Factory pour traitement evenements du domaine
        :return:
        """
        return MGPProcesseurTraitementEvenements(
            self._contexte, self._stop_event, gestionnaire_domaine=self)

    def traiter_cedule(self, evenement):
        super().traiter_cedule(evenement)

        indicateurs = evenement['indicateurs']
        self._logger.debug("Cedule webPoll: %s" % str(indicateurs))

        # Faire la liste des cedules a declencher
        if 'heure' in indicateurs:
            # declencher workflow pour trouver les certificats dans MongoDB qui ne sont pas encore valides
            processus = "%s:%s" % (
                self.__module__.__name__,
                ProcessusVerifierChaineCertificatsNonValides.__name__
            )
            self.demarrer_processus(processus, dict())

    def get_queue_configuration(self):
        configuration = super().get_queue_configuration()

        configuration_pki = [
            {
                'nom': '.'.join([self.get_nom_queue(), 'evenements']),
                'routing': [
                    ConstantesPki.REQUETE_CERTIFICAT_EMIS,
                ],
                'ttl': 300000,
                'exchange': Constantes.SECURITE_PROTEGE,
            },
            {
                'nom': '.'.join([self.get_nom_queue(), 'evenements']),
                'routing': [
                    ConstantesPki.REQUETE_CERTIFICAT_EMIS,
                ],
                'ttl': 300000,
                'exchange': Constantes.SECURITE_PRIVE,
            },
            {
                'nom': '.'.join([self.get_nom_queue(), 'evenements']),
                'routing': [
                    ConstantesPki.REQUETE_CERTIFICAT_EMIS,
                ],
                'ttl': 300000,
                'exchange': Constantes.SECURITE_PUBLIC,
            },
            {
                'nom': 'Pki.requete.1.public',
                'routing': [
                    'requete.certificat.*',
                ],
                'ttl': 20000,
                'exchange': Constantes.SECURITE_PUBLIC,
            },
            {
                'nom': 'Pki.requete.2.prive',
                'routing': [
                    'requete.certificat.*',
                ],
                'ttl': 20000,
                'exchange': Constantes.SECURITE_PRIVE,
            },
            {
                'nom': 'Pki.requete.3.protege',
                'routing': [
                    'requete.certificat.*',
                ],
                'ttl': 20000,
                'exchange': Constantes.SECURITE_PROTEGE,
            },
        ]

        configuration.extend(configuration_pki)

        return configuration

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

        pki_certfile = self.configuration.pki_certfile
        with open(pki_certfile, 'r') as f:
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
        elif domaine_transaction == ConstantesPki.TRANSACTION_RENOUVELLER_CERT_DOCKER:
            processus = "millegrilles_domaines_Pki:ProcessusRenouvellerCertificats"
        else:
            processus = super().identifier_processus(domaine_transaction)
        return processus

    # def creer_regenerateur_documents(self):
    #     return RegenerateurDeDocumentsSansEffet(self)

    def get_handler_requetes(self):
        return self.__handler_requetes_noeuds

    def get_certs_correlation_csr(self, correlation_csr: list):
        """
        :return: Retourne les certificats associes aux correlation
        """
        collection_pki = self.document_dao.get_collection(self.get_nom_collection())
        curseur = collection_pki.find({
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesSecurityPki.LIBVAL_CERTIFICAT_NOEUD,
            ConstantesSecurityPki.LIBELLE_CORRELATION_CSR: {'$in': correlation_csr}
        })

        certs = list()
        for cert in curseur:
            cert_reponse = {
                ConstantesPki.LIBELLE_CERTIFICAT_PEM: cert[ConstantesPki.LIBELLE_CERTIFICAT_PEM],
                ConstantesSecurityPki.LIBELLE_CORRELATION_CSR: cert[ConstantesSecurityPki.LIBELLE_CORRELATION_CSR],
            }
            certs.append(cert_reponse)

        return certs

    def get_certificat(self, fingerprint, properties=None, demander_si_inconnu=True):
        collection_pki = self.document_dao.get_collection(self.get_nom_collection())
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPki.LIBVAL_CERTIFICAT_NOEUD,
            ConstantesPki.LIBELLE_FINGERPRINT: fingerprint,
        }
        certificat = collection_pki.find_one(filtre)

        certificat_filtre = dict()
        try:
            for key, value in certificat.items():
                if not key.startswith('_'):
                    certificat_filtre[key] = value
        except AttributeError:
            if demander_si_inconnu:
                self._logger.warning('Certificat %s inconnu, on fait une requete sur MQ' % fingerprint)
                # Le certificat n'est pas connu, on fait une requete
                self.demander_certificat_via_mq(fingerprint)
                certificat_filtre = None  # Aucune reponse avant retour
            else:
                self._logger.warning('Certificat %s inconnu' % fingerprint)

        return certificat_filtre

    def demander_certificat_via_mq(self, fingerprint):
        routing = ConstantesSecurityPki.EVENEMENT_REQUETE + '.' + fingerprint
        # Utiliser emettre commande pour eviter d'ajouter un prefixe au routage
        self.generateur_transactions.emettre_commande_noeuds(
            dict(),
            routing,
        )

    def get_certificats_backup(self):
        collection_pki = self.document_dao.get_collection(self.get_nom_collection())
        filtre = {
            ConstantesPki.LIBELLE_FINGERPRINT: ConstantesPki.LIBVAL_LISTE_CERTIFICATS_BACKUP,
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPki.LIBVAL_LISTE_CERTIFICATS_BACKUP,
        }
        liste_certificats = collection_pki.find_one(filtre)

        return liste_certificats

    def get_liste_certificats_noeuds(self):
        """
        :return: Liste de certificats qui donnent acces a MQ pour les noeuds de la millegrille (e.g. service monitor)
        """
        collection_pki = self.document_dao.get_collection(self.get_nom_collection())
        date_courante = datetime.datetime.utcnow()

        roles = [
            ConstantesGenerateurCertificat.ROLE_MONITOR_DEPENDANT,
            ConstantesGenerateurCertificat.ROLE_MONITOR_DEPENDANT,
        ]

        filtre = {
            'sujet.organizationName': self._contexte.idmg,
            'sujet.organizationalUnitName': {'$in': roles},
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPki.LIBVAL_CERTIFICAT_NOEUD,
            'not_valid_after': {'$gt': date_courante},
            'not_valid_before': {'$lt': date_courante},
        }
        curseur = collection_pki.find(filtre)

        liste_certificats = list()
        for cert in curseur:
            cert_filtre = dict()
            for key, value in cert.items():
                if not key.startswith('_'):
                    cert_filtre[key] = value
            liste_certificats.append(cert_filtre)

        return liste_certificats

    def get_liste_certificats_ca(self):
        collection_pki = self.document_dao.get_collection(self.get_nom_collection())
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': [
                ConstantesPki.LIBVAL_CERTIFICAT_ROOT, ConstantesPki.LIBVAL_CERTIFICAT_MILLEGRILLE
            ]},
        }
        curseur = collection_pki.find(filtre)

        documents = dict()
        for doc in curseur:
            type_certificat = doc[Constantes.DOCUMENT_INFODOC_LIBELLE]
            document_cert = {'type_certificat': type_certificat}
            for key, value in doc.items():
                if not key.startswith('_'):
                    document_cert[key] = value
            documents[doc['fingerprint']] = document_cert

        return documents

    def recevoir_certificat(self, message_dict):
        enveloppe = EnveloppeCertificat(certificat_pem=message_dict[ConstantesPki.LIBELLE_CERTIFICAT_PEM])
        correlation_csr = message_dict.get(ConstantesSecurityPki.LIBELLE_CORRELATION_CSR)
        # Enregistrer le certificat - le helper va verifier si c'est un nouveau certificat ou si on l'a deja
        self._pki_document_helper.inserer_certificat(enveloppe, correlation_csr=correlation_csr)

    def confirmer_certificat(self, properties, message_dict):
        """
        Confirme la validute d'un certificat.
        """
        reponse = dict()
        if message_dict.get('fingerprint'):
            fingerprint = message_dict['fingerprint']
            self._logger.debug("Requete verification certificat par fingerprint: %s" % fingerprint)
            # Charge un certificat connu
            enveloppe_cert = self.verificateur_certificats.charger_certificat(fingerprint=fingerprint)
            if enveloppe_cert is not None:
                reponse['valide'] = True
                reponse['roles'] = enveloppe_cert.get_roles
            else:
                reponse['valide'] = False
        else:
            reponse['valide'] = False

        self.generateur_transactions.transmettre_reponse(
            reponse, properties.reply_to, properties.correlation_id)

    def transmettre_liste_ca(self, properties, message_dict):
        ca_file = self.configuration.mq_cafile

        with open(ca_file, 'r') as f:
            contenu = f.read()

        reponse = {
            ConstantesSecurityPki.LIBELLE_CHAINE_PEM: contenu
        }

        self.generateur_transactions.transmettre_reponse(
            reponse, properties.reply_to, properties.correlation_id)

    def transmettre_certificats_correlation_csr(self, properties, message_dict):
        liste_correlation = message_dict[ConstantesSecurityPki.LIBELLE_CORRELATION_CSR]
        certs = self.get_certs_correlation_csr(liste_correlation)

        reponse = {
            ConstantesSecurityPki.LIBELLE_CORRELATION_CSR: certs
        }

        self.generateur_transactions.transmettre_reponse(
            reponse, properties.reply_to, properties.correlation_id)

    def sauvegarder_configuration_altdomaines(self, transaction):
        collection_pki = self.document_dao.get_collection(self.get_nom_collection())

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPki.LIBVAL_CONFIG_CERTDOCKER,
        }
        set_ops = dict()
        for module, altdomain in transaction[ConstantesPki.CHAMP_ALT_DOMAINS].items():
            set_ops['%s.%s' % (ConstantesPki.CHAMP_ALT_DOMAINS, module)] = altdomain

        collection_pki.update_one(filtre, {'$set': set_ops})


class PKIDocumentHelper:

    def __init__(self, contexte, mg_processus_demarreur):
        self._contexte = contexte
        # self._mg_processus_demarreur = MGPProcessusDemarreur(self._contexte)
        self._mg_processus_demarreur = mg_processus_demarreur

    def inserer_certificat(self, enveloppe, trusted=False, correlation_csr: str = None, transaction_faite=False):
        document_cert = ConstantesPki.DOCUMENT_CERTIFICAT_NOEUD.copy()
        del document_cert[ConstantesPki.LIBELLE_FINGERPRINT]
        fingerprint = enveloppe.fingerprint_ascii

        maintenant = datetime.datetime.now(tz=datetime.timezone.utc)
        document_cert[Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION] = maintenant

        document_cert[ConstantesPki.LIBELLE_CERTIFICAT_PEM] = enveloppe.certificat_pem
        document_cert[ConstantesPki.LIBELLE_SUBJECT] = enveloppe.formatter_subject()
        document_cert[ConstantesPki.LIBELLE_NOT_VALID_BEFORE] = enveloppe.not_valid_before
        document_cert[ConstantesPki.LIBELLE_NOT_VALID_AFTER] = enveloppe.not_valid_after
        document_cert[ConstantesPki.LIBELLE_SUBJECT_KEY] = enveloppe.subject_key_identifier
        document_cert[ConstantesPki.LIBELLE_AUTHORITY_KEY] = enveloppe.authority_key_identifier

        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: maintenant,
            ConstantesPki.LIBELLE_FINGERPRINT: fingerprint,
            ConstantesPki.LIBELLE_TRANSACTION_FAITE: transaction_faite,
        }

        if correlation_csr is not None:
            document_cert[ConstantesSecurityPki.LIBELLE_CORRELATION_CSR] = correlation_csr

        if enveloppe.is_rootCA:
            document_cert[Constantes.DOCUMENT_INFODOC_LIBELLE] = ConstantesPki.LIBVAL_CERTIFICAT_ROOT
            document_cert[ConstantesPki.LIBELLE_IDMG] = enveloppe.idmg
            # Le certificat root est trusted implicitement quand il est charge a partir d'un fichier local
            document_cert[ConstantesPki.LIBELLE_CHAINE_COMPLETE] = True
        else:
            document_cert[ConstantesPki.LIBELLE_IDMG] = enveloppe.subject_organization_name
            if enveloppe.is_CA:
                document_cert[Constantes.DOCUMENT_INFODOC_LIBELLE] = ConstantesPki.LIBVAL_CERTIFICAT_MILLEGRILLE
                # document_cert[ConstantesPki.LIBELLE_IDMG] = enveloppe.subject_organization_name
            else:
                roles = enveloppe.get_roles
                if ConstantesGenerateurCertificat.ROLE_BACKUP in roles:
                    document_cert[Constantes.DOCUMENT_INFODOC_LIBELLE] = ConstantesPki.LIBVAL_CERTIFICAT_BACKUP
                    self.maj_liste_certificats_backup(fingerprint, document_cert)

        filtre = {
            ConstantesPki.LIBELLE_FINGERPRINT: fingerprint
        }

        collection = self._contexte.document_dao.get_collection(ConstantesPki.COLLECTION_DOCUMENTS_NOM)
        result = collection.update_one(filtre, {'$set': document_cert, '$setOnInsert': set_on_insert}, upsert=True)
        if result.matched_count == 0:
            # Le document vient d'etre insere, on va aussi transmettre une nouvelle transaction pour l'ajouter
            # de maniere permanente
            transaction = {
                ConstantesPki.LIBELLE_CERTIFICAT_PEM: enveloppe.certificat_pem,
                ConstantesPki.LIBELLE_FINGERPRINT: fingerprint,
                ConstantesPki.LIBELLE_SUBJECT: enveloppe.formatter_subject(),
            }
            try:
                self._contexte.generateur_transactions.soumettre_transaction(
                    transaction,
                    ConstantesPki.TRANSACTION_DOMAINE_NOUVEAU_CERTIFICAT
                )
            except ErreurModeRegeneration:
                # Mode de regeneration de document, rien a faire
                pass

        # # Demarrer validation des certificats
        # # declencher workflow pour trouver les certificats dans MongoDB qui ne sont pas encore valides
        # processus = "%s:%s" % (
        #     ConstantesPki.DOMAINE_NOM,
        #     ProcessusVerifierChaineCertificatsNonValides.__name__
        # )
        # self._mg_processus_demarreur.demarrer_processus(processus, dict())

    def maj_liste_certificats_backup(self, fingerprint, info_certificat):
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPki.LIBVAL_LISTE_CERTIFICATS_BACKUP,
        }
        set_ops = {
            'certificats.%s' % fingerprint: info_certificat[ConstantesSecurityPki.LIBELLE_CERTIFICAT_PEM]
        }
        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
            ConstantesSecurityPki.LIBELLE_FINGERPRINT: ConstantesPki.LIBVAL_LISTE_CERTIFICATS_BACKUP,
        }
        collection = self._contexte.document_dao.get_collection(ConstantesPki.COLLECTION_DOCUMENTS_NOM)
        collection.update_one(filtre, {'$set': set_ops, '$setOnInsert': set_on_insert}, upsert=True)

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

    def initiale(self):
        transaction = self.charger_transaction(ConstantesPki.COLLECTION_TRANSACTIONS_NOM)
        fingerprint = transaction['fingerprint']
        self.__logger.debug("Chargement certificat fingerprint: %s" % fingerprint)

        # Verifier si on a deja les certificats
        collection = self.document_dao.get_collection(ConstantesPki.COLLECTION_DOCUMENTS_NOM)
        certificat_existant = collection.find_one({'fingerprint': fingerprint})

        if certificat_existant is None:
            # Si on n'a pas le certificat, on le conserve et on lance la verification de chaine
            enveloppe_certificat = EnveloppeCertificat(certificat_pem=bytes(transaction['certificat_pem'], 'utf-8'))
            helper = PKIDocumentHelper(self.controleur.contexte, None)
            helper.inserer_certificat(enveloppe_certificat, transaction_faite=True)

            # Sauvegarder certificat #
            # document_certificat = ConstantesPki.DOCUMENT_CERTIFICAT_NOEUD.copy()
            # document_certificat[ConstantesPki.LIBELLE_CERTIFICAT_PEM] = transaction['certificat_pem']
            # document_certificat[ConstantesPki.LIBELLE_FINGERPRINT] = enveloppe_certificat.fingerprint_ascii
            #
            # if enveloppe_certificat.is_rootCA:
            #     idmg_certificat = enveloppe_certificat.idmg
            # else:
            #     idmg_certificat = enveloppe_certificat.subject_organization_name
            # document_certificat[ConstantesPki.LIBELLE_IDMG] = idmg_certificat

            # collection.insert_one(document_certificat)

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
            self.__logger.warn("Certificat invalide: %s" % fingerprint)
            self.__logger.debug("Certificat pas encore valide %s: %s" % (fingerprint, str(e)))

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
        self.__logger.debug("Chargement certificat web, nouveau fingerprint %s" % fingerprint)

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
                self.__logger.warn("Certificat invalide: %s" % fingerprint)
                self.__logger.debug("Certificat pas encore valide %s: %s" % (fingerprint, str(e)))

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
        correlation_id = properties.correlation_id
        # Pas de verification du contenu - le certificat est sa propre validation via CAs
        # self.gestionnaire.verificateur_transaction.verifier(message_dict)

        routing_key = method.routing_key

        if routing_key.startswith(ConstantesPki.REQUETE_CERTIFICAT_EMIS):
            self.recevoir_certificat(message_dict)
        elif routing_key.startswith(ConstantesPki.REQUETE_LISTE_CA):
            self.transmettre_liste_ca(properties, message_dict)
        elif routing_key.startswith(ConstantesPki.REQUETE_CONFIRMER_CERTIFICAT):
            self.confirmer_certificat(properties, message_dict)
        elif routing_key == 'requete.' + ConstantesSecurityPki.REQUETE_CORRELATION_CSR:
            self.transmettre_certificats_correlation_csr(properties, message_dict)
        elif correlation_id.startswith('certificat'):
            self.recevoir_certificat(message_dict)
        else:
            raise Exception("Type evenement inconnu: %s" % method.routing_key)

    def recevoir_certificat(self, message_dict):
        enveloppe = EnveloppeCertificat(certificat_pem=message_dict[ConstantesPki.LIBELLE_CERTIFICAT_PEM])
        correlation_csr = message_dict.get(ConstantesSecurityPki.LIBELLE_CORRELATION_CSR)
        # Enregistrer le certificat - le helper va verifier si c'est un nouveau certificat ou si on l'a deja
        self.__pki_document_helper.inserer_certificat(enveloppe, correlation_csr=correlation_csr)

    def confirmer_certificat(self, properties, message_dict):
        """
        Confirme la validite d'un certificat.
        """
        reponse = dict()
        if message_dict.get('fingerprint'):
            fingerprint = message_dict['fingerprint']
            self.__logger.debug("Requete verification certificat par fingerprint: %s" % fingerprint)
            # Charge un certificat connu
            enveloppe_cert = self.configuration.verificateur_certificats.charger_certificat(fingerprint=fingerprint)
            if enveloppe_cert is not None:
                reponse['valide'] = True
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

    def transmettre_certificats_correlation_csr(self, properties, message_dict):
        liste_correlation = message_dict[ConstantesSecurityPki.LIBELLE_CORRELATION_CSR]
        certs = self.gestionnaire.get_certs_correlation_csr(liste_correlation)

        reponse = {
            ConstantesSecurityPki.LIBELLE_CORRELATION_CSR: certs
        }

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


class ProcessusRenouvellerCertificats(MGProcessusTransaction):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        """
        Sauvegarde les URL de domaines. Emet une commande au monitor pour demander la creation et le deploiement
        de nouveaux certificats pour les modules concernes.
        """
        transaction = self.charger_transaction()
        alt_domains = transaction[ConstantesPki.CHAMP_ALT_DOMAINS]
        roles = transaction[ConstantesPki.CHAMP_ROLES]

        # Sauvegarder les nouveaux alt domains pour les modules
        self._controleur.gestionnaire.sauvegarder_configuration_altdomaines(transaction)

        # Transmettre commande au monitor

        self.set_etape_suivante(ProcessusRenouvellerCertificats.monitor_complete.__name__)

        commande_monitor = {
            ConstantesPki.CHAMP_ALT_DOMAINS: alt_domains,
            ConstantesPki.CHAMP_ROLES: roles,
        }
        self.ajouter_commande_a_transmettre('commande.monitor.maj.certificatsParRole', commande_monitor)

    def monitor_complete(self):
        self.set_etape_suivante()  # Termine

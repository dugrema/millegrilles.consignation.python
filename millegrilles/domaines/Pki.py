# Domaine Public Key Infrastructure (PKI)

from cryptography import x509
from certvalidator.errors import PathValidationError

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesPki
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementMessageDomaineRequete, \
    TraitementRequetesProtegees, MGPProcesseurTraitementEvenements, TraitementCommandesProtegees
from millegrilles.dao.MessageDAO import TraitementMessageDomaine
from millegrilles.MGProcessus import MGPProcesseur, MGProcessusTransaction
from millegrilles.SecuritePKI import ConstantesSecurityPki, EnveloppeCertificat, AutorisationConditionnelleDomaine, CertificatExpire
from millegrilles.util.X509Certificate import ConstantesGenerateurCertificat
from millegrilles.util.BackupModule import HandlerBackupDomaine

import logging
import datetime
import pytz


class TraitementRequetesPubliques(TraitementMessageDomaineRequete):

    def traiter_message(self, ch, method, properties, body):
        routing_key = method.routing_key

        # Verifier si la requete est pour un certificat
        reponse = None
        if routing_key and routing_key.startswith('requete.certificat.'):
            fingerprint = routing_key.split('.')[-1]
            certificat = self.gestionnaire.get_certificat(fingerprint, demander_si_inconnu=False)
            try:
                chaine = [certificat[ConstantesSecurityPki.LIBELLE_CERTIFICATS_PEM][fp] for fp in certificat[ConstantesSecurityPki.LIBELLE_CHAINE]]
                generateur_transactions = self.gestionnaire.generateur_transactions
                reponse = generateur_transactions.emettre_certificat(chaine)
            except KeyError:
                pass  # Certificat inconnu
        else:
            super().traiter_message(ch, method, properties, body)
            return

        if reponse is not None and properties.correlation_id is not None:
            self.transmettre_reponse(dict(), reponse, properties.reply_to, properties.correlation_id)

    def traiter_requete(self, ch, method, properties, body, message_dict, enveloppe_certificat):
        routing_key = method.routing_key
        action = routing_key.split('.')[-1]

        if routing_key.startswith(ConstantesPki.REQUETE_CERTIFICAT_DEMANDE):
            # fingerprint = routing_key.split('.')[-1]
            # reponse = self.gestionnaire.get_certificat(fingerprint)
            raise NotImplementedError("Deprecated")
        elif action == ConstantesPki.REQUETE_CERTIFICAT:
            fingerprint = message_dict['fingerprint']
            reponse = self.gestionnaire.get_certificat(fingerprint)
        else:
            raise Exception("Requete publique non supportee " + routing_key)

        if reponse is not None:
            self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)


class TraitementRequetesPrivees(TraitementMessageDomaineRequete):

    def traiter_requete(self, ch, method, properties, body, message_dict, enveloppe_certificat):
        # Verifier quel processus demarrer. On match la valeur dans la routing key.
        routing_key = method.routing_key
        action = routing_key.split('.')[-1]

        if routing_key and routing_key.startswith('requete.certificat.'):
            fingerprint = routing_key.split('.')[-1]
            certificat = self.gestionnaire.get_certificat(fingerprint, demander_si_inconnu=False)
            try:
                chaine = [certificat[ConstantesSecurityPki.LIBELLE_CERTIFICATS_PEM][fp] for fp in certificat[ConstantesSecurityPki.LIBELLE_CHAINE]]
                generateur_transactions = self.gestionnaire.generateur_transactions
                reponse = generateur_transactions.emettre_certificat(chaine)
            except KeyError:
                pass  # Certificat inconnu
                reponse = None
        elif action == ConstantesPki.REQUETE_CERTIFICAT_PAR_PK:
            reponse = self.gestionnaire.get_certificat_par_pk(message_dict)
        elif action == ConstantesPki.REQUETE_LISTE_CERTS_CA:
            reponse = self.gestionnaire.get_liste_certificats_ca()
        else:
            return super().traiter_requete(ch, method, properties, body, message_dict, enveloppe_certificat)
            # Type de transaction inconnue, on lance une exception
            # raise TransactionTypeInconnuError("Type de transaction inconnue: message: %s" % message_dict, routing_key)

        # Genere message reponse
        if reponse:
            correlation_id = properties.correlation_id
            reply_to = properties.reply_to
            self.transmettre_reponse(message_dict, reponse, replying_to=reply_to, correlation_id=correlation_id)

        return reponse


class TraitementRequetesProtegeesPki(TraitementRequetesProtegees):

    def __init__(self, gestionnaire_domaine):
        super().__init__(gestionnaire_domaine)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def traiter_message(self, ch, method, properties, body):
        routing_key = method.routing_key
        correlation_id = properties.correlation_id
        reply_to = properties.reply_to

        # Verifier si la requete est pour un certificat
        reponse = None
        if routing_key and routing_key.startswith('requete.certificat.'):
            fingerprint = routing_key.split('.')[-1]
            certificat = self.gestionnaire.get_certificat(fingerprint, demander_si_inconnu=False)
            try:
                reponse = self.gestionnaire.generateur_transactions.emettre_certificat(
                    certificat[ConstantesSecurityPki.LIBELLE_CHAINE_PEM])
            except KeyError:
                self.__logger.exception("Erreur preparation certificat %s" % fingerprint)
                pass  # Certificat inconnu
        else:
            super().traiter_message(ch, method, properties, body)
            return

        if reponse is not None:
            self.gestionnaire.generateur_transactions.transmettre_reponse(reponse, reply_to, correlation_id)

    def traiter_requete(self, ch, method, properties, body, message_dict, enveloppe_certificat):
        routing_key = method.routing_key
        domaine_routing_key = routing_key.replace('requete.%s.' % ConstantesPki.DOMAINE_NOM, '')
        domaine_action = routing_key.split('.').pop()

        if properties.reply_to and properties.correlation_id:
            reponse = None
            if domaine_routing_key == ConstantesPki.REQUETE_CONFIRMER_CERTIFICAT:
                reponse = self.gestionnaire.confirmer_certificat(properties, message_dict)
            elif domaine_routing_key.startswith('certificat.'):
                fingerprint = message_dict.get('fingerprint') or domaine_routing_key.split('.')[-1]
                reponse = self.gestionnaire.get_certificat(fingerprint, properties, demander_si_inconnu=False)
            elif domaine_action == ConstantesPki.REQUETE_CERTIFICAT:
                fingerprint = message_dict.get('fingerprint')
                reponse = self.gestionnaire.get_certificat(fingerprint, demander_si_inconnu=False)
            elif domaine_routing_key == ConstantesPki.REQUETE_CERTIFICAT_BACKUP:
                reponse = self.gestionnaire.get_certificats_backup()
            elif domaine_routing_key == ConstantesPki.REQUETE_LISTE_CERTS_CA:
                reponse = self.gestionnaire.get_liste_certificats_ca()
            elif domaine_action == ConstantesPki.REQUETE_CERTIFICAT_PAR_PK:
                reponse = self.gestionnaire.get_certificat_par_pk(message_dict)
            else:
                super().traiter_requete(ch, method, properties, body, message_dict)

            if reponse is not None:
                self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)
        else:
            self.__logger.warning("Reception requete sans reply_to/correlation_id:\n%s", str(message_dict))


class TraitementEvenementsPki(TraitementMessageDomaine):

    def traiter_message(self, ch, method, properties, body):
        routing_key = method.routing_key
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)

        if routing_key == ConstantesPki.EVENEMENT_CERTIFICAT_EMIS:
            self.gestionnaire.recevoir_certificat(message_dict)


class TraitementCommandesProtegeesPki(TraitementCommandesProtegees):

    def traiter_commande(self, enveloppe_certificat, ch, method, properties, body, message_dict) -> dict:
        action = method.routing_key.split('.')[-1]

        if action == ConstantesPki.COMMANDE_SAUVEGADER_CERTIFICAT:
            return self.gestionnaire.recevoir_certificat(message_dict)
        else:
            return super().traiter_commande(enveloppe_certificat, ch, method, properties, body, message_dict)


class GestionnairePki(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

        # self._pki_document_helper = None
        self.__traitement_certificats = None

        handler_requetes_protegees = TraitementRequetesProtegeesPki(self)
        handler_requetes_privees = TraitementRequetesPrivees(self)
        handler_requetes_publiques = TraitementRequetesPubliques(self)
        self.__handler_evenements_certificats = TraitementEvenementsPki(self)
        self.__handler_backup = HandlerBackupPKI(self._contexte)

        self.__handler_requetes_noeuds = {
            Constantes.SECURITE_SECURE: handler_requetes_protegees,
            Constantes.SECURITE_PROTEGE: handler_requetes_protegees,
            Constantes.SECURITE_PRIVE: handler_requetes_privees,
            Constantes.SECURITE_PUBLIC: handler_requetes_publiques,
        }

        handler_commandes_protegees = TraitementCommandesProtegeesPki(self)
        self.__hanlder_commandes = {
            Constantes.SECURITE_SECURE: handler_commandes_protegees,
            Constantes.SECURITE_PROTEGE: handler_commandes_protegees,
        }

    def configurer(self):
        super().configurer()
        # self._pki_document_helper = PKIDocumentHelper(self._contexte, self.demarreur_processus)
        self.__traitement_certificats = TraitementRequeteCertificat(self)

        # self.initialiser_mgca()  # S'assurer que les certs locaux sont prets avant les premieres transactions

        # Index collection domaine
        collection_domaine = self.get_collection()
        # Index par fingerprint de certificat
        collection_domaine.create_index(
            [
                (ConstantesSecurityPki.LIBELLE_FINGERPRINT, 1)
            ],
            name='fingerprint',
            unique=False,
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

        # Index pour trouver un certificat par cle publique (creation compte usager hors bande)
        collection_domaine.create_index(
            [
                (ConstantesSecurityPki.LIBELLE_FINGERPRINT_CLE_PUBLIQUE, 1),
            ],
            name='fingerprint_pk',
        )

    def demarrer(self):
        super().demarrer()
        self.initialiser_document(ConstantesPki.LIBVAL_CONFIGURATION, ConstantesPki.DOCUMENT_DEFAUT)
        self.initialiser_document(ConstantesPki.LIBVAL_CONFIG_CERTDOCKER, ConstantesPki.DOCUMENT_CONFIG_CERTDOCKER)

    # def on_channel_open(self, channel):
    #     super().on_channel_open(channel)
    #
    #     # Ajouter basicconsume pour Q certificats
    #     self.inscrire_basicconsume(self.nom_queue_certificats, self.__handler_evenements_certificats.callbackAvecAck)

    def initialiser_mgprocesseur_evenements(self):
        """
        Factory pour traitement evenements du domaine
        :return:
        """
        return MGPProcesseurTraitementEvenements(
            self._contexte, self._stop_event, gestionnaire_domaine=self)

    @property
    def nom_queue_certificats(self):
        return '.'.join([self.get_nom_queue(), 'certificats'])

    def get_queue_configuration(self):
        configuration = super().get_queue_configuration()

        configuration_pki = [
            {
                'nom': self.nom_queue_certificats,
                'routing': [
                    ConstantesPki.EVENEMENT_CERTIFICAT_EMIS,
                ],
                'ttl': 300000,
                'exchange': Constantes.SECURITE_SECURE,
                'callback': self.__handler_evenements_certificats.callbackAvecAck,
            },
            {
                'nom': self.nom_queue_certificats,
                'routing': [
                    ConstantesPki.EVENEMENT_CERTIFICAT_EMIS,
                ],
                'ttl': 300000,
                'exchange': Constantes.SECURITE_PROTEGE,
                'callback': self.__handler_evenements_certificats.callbackAvecAck,
            },
            {
                'nom': self.nom_queue_certificats,
                'routing': [
                    ConstantesPki.EVENEMENT_CERTIFICAT_EMIS,
                ],
                'ttl': 300000,
                'exchange': Constantes.SECURITE_PRIVE,
                'callback': self.__handler_evenements_certificats.callbackAvecAck,
            },
            {
                'nom': self.nom_queue_certificats,
                'routing': [
                    ConstantesPki.EVENEMENT_CERTIFICAT_EMIS,
                ],
                'ttl': 300000,
                'exchange': Constantes.SECURITE_PUBLIC,
                # 'callback': self.__handler_evenements_certificats.callbackAvecAck,
            },
            {
                'nom': 'Pki.requete.1.public',
                'routing': [
                    'requete.certificat.*',
                ],
                'ttl': 20000,
                'exchange': Constantes.SECURITE_PUBLIC,
                # 'callback': self.__handler_requetes_noeuds[Constantes.SECURITE_PUBLIC].callbackAvecAck,
            },
            {
                'nom': 'Pki.requete.2.prive',
                'routing': [
                    'requete.certificat.*',
                ],
                'ttl': 20000,
                'exchange': Constantes.SECURITE_PRIVE,
                # 'callback': self.__handler_requetes_noeuds[Constantes.SECURITE_PRIVE].callbackAvecAck,
            },
            {
                'nom': 'Pki.requete.3.protege',
                'routing': [
                    'requete.certificat.*',
                ],
                'ttl': 20000,
                'exchange': Constantes.SECURITE_PROTEGE,
                # 'callback': self.__handler_requetes_noeuds[Constantes.SECURITE_PROTEGE].callbackAvecAck,
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

    def get_handler_commandes(self) -> dict:
        return self.__hanlder_commandes

    @property
    def handler_backup(self):
        return self.__handler_backup

    def initialiser_mgca(self):
        """ Initialise les root CA et noeud middleware (ou local) """
        raise NotImplemented("Deprecated")
        #
        # verificateur = self._contexte.verificateur_certificats
        #
        # with open(self.configuration.pki_cafile, 'r') as f:
        #     contenu = f.read()
        #     pems = PemHelpers.split_certificats(contenu)
        #     self._logger.debug("Certificats ROOT configures: %s" % pems)
        #
        # for cert in pems:
        #     enveloppe = EnveloppeCertificat(certificat_pem=cert.encode('utf-8'))
        #     self._logger.debug("OUN pour cert = %s" % enveloppe.subject_organizational_unit_name)
        #     self._pki_document_helper.inserer_certificat(enveloppe, trusted=True)
        #     verificateur.charger_certificat(enveloppe=enveloppe)
        #
        # pki_certfile = self.configuration.pki_certfile
        # with open(pki_certfile, 'r') as f:
        #     contenu_pem = f.read()
        # pems = PemHelpers.split_certificats(contenu_pem)
        # pems.reverse()  # Commencer par les certs intermediaires
        # for cert_pem in pems:
        #     enveloppe = EnveloppeCertificat(certificat_pem=cert_pem.encode('utf-8'))
        #     verificateur.charger_certificat(enveloppe=enveloppe)
        #     self._logger.debug("Certificats noeud local: %s" % contenu)
        #
        #     # Verifier la chaine immediatement, permet d'ajouter le cert avec Trusted=True
        #     self._pki_document_helper.inserer_certificat(enveloppe, trusted=True)
        #
        # # Demarrer validation des certificats
        # # declencher workflow pour trouver les certificats dans MongoDB qui ne sont pas encore valides
        # # processus = "%s:%s" % (
        # #     ConstantesPki.DOMAINE_NOM,
        # #     ProcessusVerifierChaineCertificatsNonValides.__name__
        # # )
        # # self.demarrer_processus(processus, dict())

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
            # Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPki.LIBVAL_CERTIFICAT_NOEUD,
            ConstantesSecurityPki.LIBELLE_FINGERPRINT: fingerprint,
        }
        certificat = collection_pki.find_one(filtre)

        certificat_filtre = dict()
        try:
            for key, value in certificat.items():
                if not key.startswith('_'):
                    certificat_filtre[key] = value

            certs = certificat[ConstantesSecurityPki.LIBELLE_CERTIFICATS_PEM]
            chaine_fp = certificat[ConstantesSecurityPki.LIBELLE_CHAINE]

            chaine_pem = [certs[c] for c in chaine_fp]
            certificat_filtre[ConstantesSecurityPki.LIBELLE_CHAINE_PEM] = chaine_pem
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

    def get_certificat_par_pk(self, message: dict):
        fingerprint = message[ConstantesSecurityPki.LIBELLE_FINGERPRINT_CLE_PUBLIQUE]
        collection_pki = self.document_dao.get_collection(self.get_nom_collection())
        filtre = {
            ConstantesSecurityPki.LIBELLE_FINGERPRINT_CLE_PUBLIQUE: fingerprint,
        }
        certificat = collection_pki.find_one(filtre)

        if certificat is not None:
            pems = certificat['certificats_pem']
            chaine = [pems[c] for c in certificat['chaine']]

            return {'certificat': chaine}

        return {'resultat': False}

    def recevoir_certificat(self, message_dict):
        # Verifier si le certificat existe deja
        fingerprint = message_dict[ConstantesSecurityPki.LIBELLE_FINGERPRINT]
        document_existant = self.verifier_presence_certificat(fingerprint)

        ajoute = False
        if document_existant is None:
            self._logger.debug('Ajout du certificat %s' % fingerprint)
            chaine_pem = message_dict[ConstantesSecurityPki.LIBELLE_CHAINE_PEM]
            correlation_csr = message_dict.get(ConstantesSecurityPki.LIBELLE_CORRELATION_CSR)
            self.inserer_certificat_pem(chaine_pem, correlation_csr=correlation_csr)

            ajoute = True

        return {'ok': True, 'ajoute': ajoute}

    def verifier_presence_certificat(self, fingerprint: str):
        filtre = {ConstantesSecurityPki.LIBELLE_FINGERPRINT: fingerprint}
        collection = self._contexte.document_dao.get_collection(ConstantesPki.COLLECTION_DOCUMENTS_NOM)
        document_existant = collection.find_one(filtre, projection={'_id': True})
        return document_existant

    def inserer_certificat_pem(self, chaine_pem: list, correlation_csr: str = None, dirty=True):
        # def inserer_certificat(self, enveloppe, trusted=False, correlation_csr: str = None, transaction_faite=False):
        chaine_pem = [pem.strip() for pem in chaine_pem]
        enveloppe = EnveloppeCertificat(certificat_pem='\n'.join(chaine_pem))
        fingerprint = enveloppe.fingerprint
        fingerprint_cle_publique = enveloppe.fingerprint_cle_publique

        # Valider la chaine de certificats - lance exception si invalide
        try:
            # Charger le certificat en ignorant la date d'expiration - valide la chaine sur la date d'expiration
            # Les certificats expires restent necessaires pour valider la signature des transactions et documents
            # self._contexte.verificateur_certificats.valider_x509_enveloppe(enveloppe)
            cert_millegrille_pem = chaine_pem[-1]
            enveloppe_millegrille = EnveloppeCertificat(certificat_pem=cert_millegrille_pem)
            idmg_validation = enveloppe_millegrille.idmg
            date_reference = enveloppe.not_valid_after

            self._contexte.validateur_pki.valider(chaine_pem, date_reference=date_reference, idmg=idmg_validation)
        except PathValidationError as pve:
            if 'expired' not in str(pve):
                # La chaine est invalide pour raison autre que l'expiration du certificat
                raise pve

        idmg = enveloppe.subject_organization_name
        chaine_fingerprints = [fingerprint]
        certs_pem_dict = {fingerprint: chaine_pem[0]}

        document_cert = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPki.LIBVAL_CERTIFICAT_NOEUD,
            ConstantesPki.LIBELLE_IDMG: idmg,
            ConstantesSecurityPki.LIBELLE_FINGERPRINT: enveloppe.fingerprint,
            ConstantesSecurityPki.LIBELLE_FINGERPRINT_CLE_PUBLIQUE: fingerprint_cle_publique,
            ConstantesPki.LIBELLE_SUBJECT: enveloppe.formatter_subject(),
            ConstantesPki.LIBELLE_NOT_VALID_BEFORE: enveloppe.not_valid_before,
            ConstantesPki.LIBELLE_NOT_VALID_AFTER: enveloppe.not_valid_after,
            ConstantesPki.LIBELLE_SUBJECT_KEY: enveloppe.subject_key_identifier,
            ConstantesPki.LIBELLE_AUTHORITY_KEY: enveloppe.authority_key_identifier,
            ConstantesSecurityPki.LIBELLE_CHAINE: chaine_fingerprints,
            ConstantesSecurityPki.LIBELLE_CERTIFICATS_PEM: certs_pem_dict,
            'dirty': dirty,
        }

        # Ajouter valeurs d'extension MilleGrilles - optionnel
        try:
            document_cert[ConstantesPki.LIBELLE_ROLES]: enveloppe.get_roles
        except x509.extensions.ExtensionNotFound:
            pass
        try:
            document_cert[ConstantesPki.LIBELLE_EXCHANGES]: enveloppe.get_exchanges
        except x509.extensions.ExtensionNotFound:
            pass
        try:
            document_cert[ConstantesPki.LIBELLE_DOMAINES]: enveloppe.get_domaines
        except x509.extensions.ExtensionNotFound:
            pass

        # document_cert[ConstantesPki.LIBELLE_CERTIFICAT_PEM] = enveloppe.certificat_pem
        # ConstantesSecurityPki.LIBELLE_CERTIFICATS_PEM:
        enveloppe_ca = None
        for pem in chaine_pem[1:]:
            enveloppe_ca = EnveloppeCertificat(certificat_pem=pem)
            fingerprint_ca = enveloppe_ca.fingerprint
            chaine_fingerprints.append(fingerprint_ca)
            if enveloppe_ca.is_CA is not True:
                raise Exception("Chaine de certificat invalide, cert suivants dans liste pas CA : " + fingerprint_ca)
            elif enveloppe.subject_organization_name != idmg:
                raise Exception("Certificat dans la chain ne correspond pas au idmg : " + fingerprint_ca)
            certs_pem_dict[fingerprint_ca] = pem

        if enveloppe_ca is None:
            raise Exception("Chaine incomplete")

        if idmg != enveloppe_ca.idmg:  # Recalculer le idmg
            raise Exception("Certificat racine fourni ne correspond pas au idmg")

        maintenant = datetime.datetime.now(tz=datetime.timezone.utc)
        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: maintenant,
        }

        if correlation_csr is not None:
            document_cert[ConstantesSecurityPki.LIBELLE_CORRELATION_CSR] = correlation_csr

        filtre = {
            ConstantesSecurityPki.LIBELLE_FINGERPRINT: fingerprint
        }

        ops = {
            '$set': document_cert,
            '$setOnInsert': set_on_insert,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }

        collection = self._contexte.document_dao.get_collection(ConstantesPki.COLLECTION_DOCUMENTS_NOM)
        result = collection.update_one(filtre, ops, upsert=True)

        if dirty:
            # Transmettre la transaction pour conserver le certificat de maniere permanente
            document_cert[ConstantesPki.LIBELLE_NOT_VALID_BEFORE] = document_cert[
                ConstantesPki.LIBELLE_NOT_VALID_BEFORE].timestamp()
            document_cert[ConstantesPki.LIBELLE_NOT_VALID_AFTER] = document_cert[
                ConstantesPki.LIBELLE_NOT_VALID_AFTER].timestamp()
            del document_cert['dirty']
            self.generateur_transactions.soumettre_transaction(
                document_cert,
                ConstantesPki.TRANSACTION_DOMAINE_NOUVEAU_CERTIFICAT,
                ajouter_certificats=True
            )

        if result.matched_count != 1 and result.upserted_id is None:
            raise Exception("Erreur insertion nouveau certificat")

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


class HandlerBackupPKI(HandlerBackupDomaine):

    def __init__(self, contexte):
        super().__init__(contexte,
                         ConstantesPki.DOMAINE_NOM,
                         ConstantesPki.COLLECTION_TRANSACTIONS_NOM,
                         ConstantesPki.COLLECTION_DOCUMENTS_NOM)

    def _doit_chiffrer(self):
        """
        Les transactions de cles sont deja chiffrees (asymetrique). On ne rechiffre pas une deuxieme fois.
        :return:
        """
        return False


class ProcessusAjouterCertificat(MGProcessusTransaction):

    def __init__(self, controleur: MGPProcesseur, evenement, transaction_mapper=None):
        super().__init__(controleur, evenement, transaction_mapper)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        transaction = self.charger_transaction(ConstantesPki.COLLECTION_TRANSACTIONS_NOM)
        fingerprint = transaction[ConstantesSecurityPki.LIBELLE_FINGERPRINT]

        # Verifier si on a deja les certificats
        self.__logger.debug("Chargement certificat fingerprint: %s" % fingerprint)
        doc_id = self.controleur.gestionnaire.verifier_presence_certificat(fingerprint)

        if doc_id is None:
            # Ordonner PEMs selon la chaine
            pems = [transaction[ConstantesSecurityPki.LIBELLE_CERTIFICATS_PEM][fp] for fp in transaction[ConstantesSecurityPki.LIBELLE_CHAINE]]

            # Reset dirty flag, on est en train de traiter la transaction
            self.controleur.gestionnaire.inserer_certificat_pem(pems, dirty=False)

        self.set_etape_suivante()  # Termine
        return {ConstantesSecurityPki.LIBELLE_FINGERPRINT: fingerprint}

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


class TraitementRequeteCertificat(TraitementMessageDomaine):

    def __init__(self, gestionnaire_domaine):
        super().__init__(gestionnaire_domaine)
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        correlation_id = properties.correlation_id
        # Pas de verification du contenu - le certificat est sa propre validation via CAs
        # self.gestionnaire.verificateur_transaction.verifier(message_dict)

        routing_key = method.routing_key

        if routing_key.startswith(ConstantesPki.EVENEMENT_CERTIFICAT_EMIS):
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
        # self.__pki_document_helper.inserer_certificat(enveloppe, correlation_csr=correlation_csr)
        self.gestionnaire.inserer_certificat()

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

# Domaine de gestion et d'administration de MilleGrilles
from millegrilles import Constantes
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementRequetesNoeuds
from millegrilles.dao.MessageDAO import TraitementMessageDomaine
from millegrilles.MGProcessus import  MGProcessusTransaction

import logging
import datetime


class ConstantesParametres:

    DOMAINE_NOM = 'millegrilles.domaines.Parametres'
    COLLECTION_NOM = DOMAINE_NOM

    COLLECTION_TRANSACTIONS_NOM = COLLECTION_NOM
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_NOM
    QUEUE_NOM = DOMAINE_NOM
    QUEUE_ROUTING_CHANGEMENTS = 'noeuds.source.millegrilles_domaines_Parametres.documents'

    TRANSACTION_MODIFIER_EMAIL_SMTP = '%s.modifierEmailSmtp' % DOMAINE_NOM
    TRANSACTION_CLES_RECUES = '%s.clesRecues' % DOMAINE_NOM
    TRANSACTION_ETAT_ROUTEUR = '%s.public.routeur.etatRouteur' % DOMAINE_NOM
    TRANSACTION_EXPOSER_PORTS_ROUTEUR = '%s.public.routeur.exposerPorts' % DOMAINE_NOM
    TRANSACTION_RETIRER_PORTS_ROUTEUR = '%s.public.routeur.retirerPorts' % DOMAINE_NOM
    TRANSACTION_CONFIRMATION_ROUTEUR = '%s.public.routeur.confirmerAction' % DOMAINE_NOM
    TRANSACTION_SAUVER_CONFIG_PUBLIC = '%s.public.sauvegarder' % DOMAINE_NOM
    TRANSACTION_DEPLOYER_ACCES_PUBLIC = '%s.public.deployer' % DOMAINE_NOM
    TRANSACTION_RETIRER_ACCES_PUBLIC = '%s.public.retirer' % DOMAINE_NOM
    TRANSACTION_RENOUVELLER_CERTIFICAT_PUBLIC = '%s.public.renouvellerCertificat' % DOMAINE_NOM
    TRANSACTION_MAJ_CERTIFICAT_PUBLIC = '%s.public.majCertificat' % DOMAINE_NOM

    TRANSACTION_CHAMP_MGLIBELLE = 'mg-libelle'
    TRANSACTION_CHAMP_UUID = 'uuid'

    # Courriel
    DOCUMENT_CHAMP_COURRIEL_ORIGINE = 'origine'
    DOCUMENT_CHAMP_COURRIEL_DESTINATIONS = 'destinations'
    DOCUMENT_CHAMP_HOST = 'host'
    DOCUMENT_CHAMP_PORT = 'port'
    DOCUMENT_CHAMP_USER = 'user'
    DOCUMENT_CHAMP_PASSWORD = 'password'
    DOCUMENT_CHAMP_NOM_MILLEGRILLE = 'nom_millegrille'
    DOCUMENT_CHAMP_URL_BASE = 'adresse_url_base'
    DOCUMENT_CHAMP_ACTIF = 'actif'

    LIBVAL_CONFIGURATION = 'configuration'
    LIBVAL_EMAIL_SMTP = 'email.stmp'
    LIBVAL_VERSIONS_IMAGES_DOCKER = 'versions.images.docker'
    LIBVAL_CERTS_WEB = 'certs.web'
    LIBVAL_CERTS_SSL = 'certs.ssl'
    LIBVAL_ID_MILLEGRILLE = 'millegrille.id'

    # Configuration Publique
    LIBVAL_CONFIGURATION_PUBLIQUE = 'publique.configuration'
    DOCUMENT_PUBLIQUE_ACTIF = 'actif'
    DOCUMENT_PUBLIQUE_UPNP_SUPPORTE = 'upnp_supporte'
    DOCUMENT_PUBLIQUE_NOEUD_DOCKER = 'noeud_docker_hostname'
    DOCUMENT_PUBLIQUE_NOEUD_DOCKER_ID = 'noeud_docker_id'
    DOCUMENT_PUBLIQUE_URL_WEB = 'url_web'
    DOCUMENT_PUBLIQUE_URL_MQ = 'url_mq'
    DOCUMENT_PUBLIQUE_PORT_HTTP = 'port_http'
    DOCUMENT_PUBLIQUE_PORT_HTTPS = 'port_https'
    DOCUMENT_PUBLIQUE_PORT_MQ = 'port_mq'
    DOCUMENT_PUBLIQUE_PORT_EXTERIEUR = 'port_ext'
    DOCUMENT_PUBLIQUE_PORT_INTERNE = 'port_int'
    DOCUMENT_PUBLIQUE_IPV4_EXTERNE = 'ipv4_externe'
    DOCUMENT_PUBLIQUE_IPV4_INTERNE = 'ipv4_interne'
    DOCUMENT_PUBLIQUE_PROTOCOL = 'protocol'
    DOCUMENT_PUBLIQUE_PORT_MAPPING_NOM = 'port_mapping_nom'
    DOCUMENT_PUBLIQUE_MAPPINGS_IPV4 = 'mappings_ipv4'
    DOCUMENT_PUBLIQUE_MAPPINGS_IPV4_DEMANDES = 'mappings_ipv4_demandes'
    DOCUMENT_PUBLIQUE_ROUTEUR_STATUS = 'status_info'
    DOCUMENT_PUBLIQUE_ACTIVITE = 'activite'

    DOCUMENT_PUBLIQUE_ACTIVITE_DATE = 'date'
    DOCUMENT_PUBLIQUE_ACTIVITE_DESCRIPTION = 'description'

    DOCUMENT_PUBLIQUE_ACTIVITE_TAILLEMAX = 50

    DOCUMENT_DEFAUT = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_CONFIGURATION
    }

    DOCUMENT_ID_MILLEGRILLE = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_ID_MILLEGRILLE,
        DOCUMENT_CHAMP_NOM_MILLEGRILLE: 'Sansnom',
        DOCUMENT_CHAMP_URL_BASE: 'sansnom.millegrilles.com',
    }

    DOCUMENT_EMAIL_SMTP = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_EMAIL_SMTP,
        DOCUMENT_CHAMP_ACTIF: False,
        DOCUMENT_CHAMP_COURRIEL_ORIGINE: None,
        DOCUMENT_CHAMP_COURRIEL_DESTINATIONS: None,
        DOCUMENT_CHAMP_HOST: None,
        DOCUMENT_CHAMP_PORT: None,
        DOCUMENT_CHAMP_USER: None,
        Constantes.DOCUMENT_SECTION_CRYPTE: None,  # DOCUMENT_CHAMP_PASSWORD
    }

    DOCUMENT_CONFIGURATION_PUBLIQUE = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_CONFIGURATION_PUBLIQUE,
        DOCUMENT_PUBLIQUE_ACTIF: False,
        DOCUMENT_PUBLIQUE_NOEUD_DOCKER: None,
        DOCUMENT_PUBLIQUE_UPNP_SUPPORTE: False,
        DOCUMENT_PUBLIQUE_URL_WEB: None,
        DOCUMENT_PUBLIQUE_URL_MQ: None,
        DOCUMENT_PUBLIQUE_IPV4_EXTERNE: None,
        DOCUMENT_PUBLIQUE_ROUTEUR_STATUS: None,
        DOCUMENT_PUBLIQUE_PORT_HTTP: 80,
        DOCUMENT_PUBLIQUE_PORT_HTTPS: 443,
        DOCUMENT_PUBLIQUE_PORT_MQ: 5673,

        # Cle: port exterieur, Valeur: DOCUMENT_CONFIGURATION_PUBLIQUE_MAPPINGS
        DOCUMENT_PUBLIQUE_MAPPINGS_IPV4: dict(),
        DOCUMENT_PUBLIQUE_MAPPINGS_IPV4_DEMANDES: dict(),
        DOCUMENT_PUBLIQUE_ACTIVITE: list(),
    }

    DOCUMENT_CONFIGURATION_PUBLIQUE_MAPPINGS = {
        DOCUMENT_PUBLIQUE_PORT_EXTERIEUR: None,
        DOCUMENT_PUBLIQUE_IPV4_INTERNE: None,
        DOCUMENT_PUBLIQUE_PORT_INTERNE: None,
        DOCUMENT_PUBLIQUE_PORT_MAPPING_NOM: None,
    }

    DOCUMENT_CONFIGURATION_PUBLIQUE_ACTIVITE = {
        DOCUMENT_PUBLIQUE_ACTIVITE_DATE: datetime.datetime.utcnow(),
        DOCUMENT_PUBLIQUE_ACTIVITE_DESCRIPTION: '',
    }


class GestionnaireParametres(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)

        # Queue message handlers
        self.__handler_transaction = TraitementTransactionPersistee(self)
        self.__handler_cedule = TraitementMessageCedule(self)
        self.__handler_requetes_noeuds = TraitementRequetesNoeuds(self)

        self._logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

    def configurer(self):
        super().configurer()

    def demarrer(self):
        super().demarrer()
        self.initialiser_document(ConstantesParametres.LIBVAL_CONFIGURATION, ConstantesParametres.DOCUMENT_DEFAUT)
        self.initialiser_document(ConstantesParametres.LIBVAL_EMAIL_SMTP, ConstantesParametres.DOCUMENT_EMAIL_SMTP)
        self.initialiser_document(
            ConstantesParametres.LIBVAL_CONFIGURATION_PUBLIQUE, ConstantesParametres.DOCUMENT_CONFIGURATION_PUBLIQUE)

        document_config_id = ConstantesParametres.DOCUMENT_ID_MILLEGRILLE.copy()
        nom_millegrille = self.configuration.nom_millegrille
        document_config_id['nom_millegrille'] = nom_millegrille
        document_config_id['adresse_url_base'] = 'mg-%s.local' % nom_millegrille
        self.initialiser_document(ConstantesParametres.LIBVAL_ID_MILLEGRILLE, document_config_id)

        self.demarrer_watcher_collection(
            ConstantesParametres.COLLECTION_DOCUMENTS_NOM, ConstantesParametres.QUEUE_ROUTING_CHANGEMENTS)


    def modifier_document_email_smtp(self, transaction):
        document_email_smtp = {
            Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: datetime.datetime.utcnow()
        }
        self.map_transaction_vers_document(transaction, document_email_smtp)  # Copier champs transaction vers doc

        operations = {
            '$set': document_email_smtp,
        }

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesParametres.LIBVAL_EMAIL_SMTP
        }

        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        resultat = collection_domaine.update_one(filtre, operations)

        return document_email_smtp

    def get_nom_queue(self):
        return ConstantesParametres.QUEUE_NOM

    def get_nom_collection(self):
        return ConstantesParametres.COLLECTION_DOCUMENTS_NOM

    def get_collection_transaction_nom(self):
        return ConstantesParametres.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesParametres.COLLECTION_PROCESSUS_NOM

    def get_nom_domaine(self):
        return ConstantesParametres.DOMAINE_NOM

    def get_handler_transaction(self):
        return self.__handler_transaction

    def get_handler_cedule(self):
        return self.__handler_cedule

    def get_handler_requetes_noeuds(self):
        return self.__handler_requetes_noeuds

    def identifier_processus(self, domaine_transaction):
        if domaine_transaction == ConstantesParametres.TRANSACTION_MODIFIER_EMAIL_SMTP:
            processus = "millegrilles_domaines_Parametres:ProcessusTransactionModifierEmailSmtp"
        elif domaine_transaction == ConstantesParametres.TRANSACTION_CLES_RECUES:
            processus = "millegrilles_domaines_Parametres:ProcessusTransactionClesRecues"
        elif domaine_transaction == ConstantesParametres.TRANSACTION_ETAT_ROUTEUR:
            processus = "millegrilles_domaines_Parametres:ProcessusEtatRouteur"
        elif domaine_transaction == ConstantesParametres.TRANSACTION_EXPOSER_PORTS_ROUTEUR:
            processus = "millegrilles_domaines_Parametres:ProcessusExposerPortsRouteur"
        elif domaine_transaction == ConstantesParametres.TRANSACTION_RETIRER_PORTS_ROUTEUR:
            processus = "millegrilles_domaines_Parametres:ProcessusRetirerPortsRouteur"
        elif domaine_transaction == ConstantesParametres.TRANSACTION_CONFIRMATION_ROUTEUR:
            processus = "millegrilles_domaines_Parametres:ProcessusConfirmationRouteur"
        elif domaine_transaction == ConstantesParametres.TRANSACTION_SAUVER_CONFIG_PUBLIC:
            processus = "millegrilles_domaines_Parametres:ProcessusSauverConfigPublique"
        elif domaine_transaction == ConstantesParametres.TRANSACTION_DEPLOYER_ACCES_PUBLIC:
            processus = "millegrilles_domaines_Parametres:ProcessusDeployerAccesPublic"
        elif domaine_transaction == ConstantesParametres.TRANSACTION_RETIRER_ACCES_PUBLIC:
            processus = "millegrilles_domaines_Parametres:ProcessusRetirerAccesPublic"
        elif domaine_transaction == ConstantesParametres.TRANSACTION_RENOUVELLER_CERTIFICAT_PUBLIC:
            processus = "millegrilles_domaines_Parametres:ProcessusRenouvellerCertificatPublic"
        elif domaine_transaction == ConstantesParametres.TRANSACTION_MAJ_CERTIFICAT_PUBLIC:
            processus = "millegrilles_domaines_Parametres:ProcessusMajCertificatPublic"
        else:
            processus = super().identifier_processus(domaine_transaction)

        return processus

    def traiter_cedule(self, evenement):
        pass


class TraitementMessageCedule(TraitementMessageDomaine):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire)

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)
        routing_key = method.routing_key


class TraitementTransactionPersistee(TraitementMessageDomaine):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire)

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)

        # Verifier quel processus demarrer.
        routing_key = method.routing_key
        routing_key_sansprefixe = routing_key.replace(
            'destinataire.domaine.',
            ''
        )

        processus = self.gestionnaire.identifier_processus(routing_key_sansprefixe)
        self._gestionnaire.demarrer_processus(processus, message_dict)


# ******************* Processus *******************
class ProcessusParametres(MGProcessusTransaction):

    def get_collection_transaction_nom(self):
        return ConstantesParametres.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesParametres.COLLECTION_PROCESSUS_NOM


class ProcessusSauverConfigPublique(ProcessusParametres):

    def initiale(self):
        self._sauvegarder_configuration()
        self.set_etape_suivante()  # Termine

    def _sauvegarder_configuration(self):
        transaction = self.transaction

        activite = ConstantesParametres.DOCUMENT_CONFIGURATION_PUBLIQUE_ACTIVITE.copy()
        activite[ConstantesParametres.DOCUMENT_PUBLIQUE_ACTIVITE_DATE] = datetime.datetime.utcnow()
        activite[ConstantesParametres.DOCUMENT_PUBLIQUE_ACTIVITE_DESCRIPTION] = self._description(transaction)

        transaction_detail = dict()
        champs_detail = [
            ConstantesParametres.DOCUMENT_PUBLIQUE_URL_WEB,
            ConstantesParametres.DOCUMENT_PUBLIQUE_PORT_HTTP,
            ConstantesParametres.DOCUMENT_PUBLIQUE_PORT_HTTPS,
            ConstantesParametres.DOCUMENT_PUBLIQUE_URL_MQ,
            ConstantesParametres.DOCUMENT_PUBLIQUE_PORT_MQ
        ]
        for champ in champs_detail:
            transaction_detail[champ] = transaction.get(champ)

        collection = self.document_dao.get_collection(ConstantesParametres.COLLECTION_DOCUMENTS_NOM)

        ops = {
            '$set': transaction_detail,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
            '$push': {
                ConstantesParametres.DOCUMENT_PUBLIQUE_ACTIVITE: {
                    '$each': [activite],
                    '$sort': {ConstantesParametres.DOCUMENT_PUBLIQUE_ACTIVITE_DATE: -1},
                    '$slice': ConstantesParametres.DOCUMENT_PUBLIQUE_ACTIVITE_TAILLEMAX,
                }
            }
        }

        resultat = collection.update_one(
            {Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesParametres.LIBVAL_CONFIGURATION_PUBLIQUE},
            ops
        )
        if resultat.modified_count == 0:
            raise Exception(
                "Erreur ajout activite a configuration publique, document %s n'existe pas" %
                ConstantesParametres.LIBVAL_CONFIGURATION_PUBLIQUE
            )

    def _description(self, transaction):
        ports = list()

        port_http = transaction.get(ConstantesParametres.DOCUMENT_PUBLIQUE_PORT_HTTP)
        port_https = transaction.get(ConstantesParametres.DOCUMENT_PUBLIQUE_PORT_HTTPS)
        port_mq = transaction.get(ConstantesParametres.DOCUMENT_PUBLIQUE_PORT_MQ)

        ports.append('%s->%s' % (port_http, port_http))
        ports.append('%s->%s' % (port_https, port_https))
        ports.append('%s->%s' % (port_mq, port_mq))

        desc = 'MAJ mappings: %s' % ', '.join(ports)

        return desc


class ProcessusTransactionModifierEmailSmtp(ProcessusParametres):
    """
    Processus de modification de document Plume
    """

    def initiale(self):
        """
        Certains messages contiennent de l'information cryptee. On doit s'assurer d'avoir recu la cle avant
        de poursuivre la mise a jour.
        :return:
        """
        transaction = self.charger_transaction()
        document_email_smtp = self._controleur.gestionnaire.modifier_document_email_smtp(transaction)

        tokens_attente = None
        if document_email_smtp.get(Constantes.DOCUMENT_SECTION_CRYPTE) is not None:
            # On doit attendre la confirmation de reception des cles
            uuid = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][
                Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
            tokens_attente = self._get_tokens_attente(uuid)

        self.set_etape_suivante(
            etape_suivante=ProcessusTransactionModifierEmailSmtp.sauvegarder_changements.__name__,
            token_attente=tokens_attente
        )

    def sauvegarder_changements(self):
        """ Mettre a jour le document """
        transaction = self.charger_transaction()
        document_email_smtp = self._controleur.gestionnaire.modifier_document_email_smtp(transaction)

        self.set_etape_suivante()  # Termine
        return {
            Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: document_email_smtp[Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION],
        }

    def _get_tokens_attente(self, uuid):
        tokens = [
            '%s:%s:%s' % (ConstantesParametres.TRANSACTION_CLES_RECUES, ConstantesParametres.LIBVAL_EMAIL_SMTP, uuid)
        ]

        return tokens


class ProcessusTransactionClesRecues(ProcessusParametres):

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

        token_resumer = '%s:%s:%s' % (ConstantesParametres.TRANSACTION_CLES_RECUES, mg_libelle, uuid)
        self.resumer_processus([token_resumer])

        self.set_etape_suivante()  # Termine
        return {ConstantesParametres.TRANSACTION_CHAMP_MGLIBELLE: mg_libelle}


class ProcessusEtatRouteur(ProcessusParametres):

    def initiale(self):
        transaction = self.transaction

        activite = ConstantesParametres.DOCUMENT_CONFIGURATION_PUBLIQUE_ACTIVITE.copy()
        activite[ConstantesParametres.DOCUMENT_PUBLIQUE_ACTIVITE_DATE] = datetime.datetime.utcnow()
        activite[ConstantesParametres.DOCUMENT_PUBLIQUE_ACTIVITE_DESCRIPTION] = self._description(transaction)

        collection = self.document_dao.get_collection(ConstantesParametres.COLLECTION_DOCUMENTS_NOM)

        document_status = transaction.get(ConstantesParametres.DOCUMENT_PUBLIQUE_ROUTEUR_STATUS)
        upnp_supporte = document_status is not None

        ops = {
            '$set': {
                ConstantesParametres.DOCUMENT_PUBLIQUE_UPNP_SUPPORTE: upnp_supporte,
                ConstantesParametres.DOCUMENT_PUBLIQUE_IPV4_EXTERNE: transaction.get(
                    ConstantesParametres.DOCUMENT_PUBLIQUE_IPV4_EXTERNE),
                ConstantesParametres.DOCUMENT_PUBLIQUE_MAPPINGS_IPV4: transaction.get(
                    ConstantesParametres.DOCUMENT_PUBLIQUE_MAPPINGS_IPV4),
                ConstantesParametres.DOCUMENT_PUBLIQUE_ROUTEUR_STATUS: transaction.get(
                    ConstantesParametres.DOCUMENT_PUBLIQUE_ROUTEUR_STATUS),

            },
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
            '$push': {
                ConstantesParametres.DOCUMENT_PUBLIQUE_ACTIVITE: {
                    '$each': [activite],
                    '$sort': {ConstantesParametres.DOCUMENT_PUBLIQUE_ACTIVITE_DATE: -1},
                    '$slice': ConstantesParametres.DOCUMENT_PUBLIQUE_ACTIVITE_TAILLEMAX,
                }
            }
        }

        resultat = collection.update_one(
            {Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesParametres.LIBVAL_CONFIGURATION_PUBLIQUE},
            ops
        )
        if resultat.modified_count == 0:
            raise Exception(
                "Erreur ajout activite a configuration publique, document %s n'existe pas" %
                ConstantesParametres.LIBVAL_CONFIGURATION_PUBLIQUE
            )

        self.set_etape_suivante()  # Termine

    def _description(self, transaction):
        desc = 'IP ext: %s, etat %s' % (
            transaction.get(ConstantesParametres.DOCUMENT_PUBLIQUE_IPV4_EXTERNE),
            str(transaction.get(ConstantesParametres.DOCUMENT_PUBLIQUE_ROUTEUR_STATUS))
        )
        return desc


# class ProcessusExposerPortsRouteur(ProcessusSauverConfigPublique):
#     """
#     La transaction est la meme que celle pour la mise a jour de la configuraiton, avec action necessaire.
#     """
#
#     def initiale(self):
#         self._sauvegarder_configuration()
#         self.set_etape_suivante(ProcessusExposerPortsRouteur.exposer_ports.__name__)
#
#     def exposer_ports(self):
#         """
#         Transmet une demande d'exposition des ports au Monitor de la MilleGrille
#         :return:
#         """
#
#         self.set_etape_suivante()  # Termine
#
#     def _description(self, transaction):
#         ports = list()
#
#         port_http = transaction.get(ConstantesParametres.DOCUMENT_PUBLIQUE_PORT_HTTP)
#         port_https = transaction.get(ConstantesParametres.DOCUMENT_PUBLIQUE_PORT_HTTPS)
#         port_mq = transaction.get(ConstantesParametres.DOCUMENT_PUBLIQUE_PORT_MQ)
#
#         ports.append('%s->%s' % (port_http, port_http))
#         ports.append('%s->%s' % (port_https, port_https))
#         ports.append('%s->%s' % (port_mq, port_mq))
#
#         desc = 'Ajout mappings externes: %s' % ', '.join(ports)
#
#         return desc


# class ProcessusRetirerPortRouteur(ProcessusParametres):
#     pass


class ProcessusConfirmationRouteur(ProcessusParametres):
    pass


class ProcessusDeployerAccesPublic(ProcessusParametres):
    """
    Utilise le monitor pour deployer le node label netzone.public=true et ajouter mappings au routeur.
    """

    def initiale(self):
        transaction = self.transaction
        collection = self.document_dao.get_collection(ConstantesParametres.COLLECTION_DOCUMENTS_NOM)

        activite = ConstantesParametres.DOCUMENT_CONFIGURATION_PUBLIQUE_ACTIVITE.copy()
        activite[ConstantesParametres.DOCUMENT_PUBLIQUE_ACTIVITE_DATE] = datetime.datetime.utcnow()
        activite[ConstantesParametres.DOCUMENT_PUBLIQUE_ACTIVITE_DESCRIPTION] = self._description(transaction)

        # Fixer les mappings demandes
        configuration_publique = collection.find_one(
            {Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesParametres.LIBVAL_CONFIGURATION_PUBLIQUE})
        noeud_docker = transaction[ConstantesParametres.DOCUMENT_PUBLIQUE_NOEUD_DOCKER]
        noeud_docker_id = transaction[ConstantesParametres.DOCUMENT_PUBLIQUE_NOEUD_DOCKER_ID]
        ipv4_interne = transaction[ConstantesParametres.DOCUMENT_PUBLIQUE_IPV4_INTERNE]

        champs_mapping = [
            ConstantesParametres.DOCUMENT_PUBLIQUE_PORT_HTTP,
            ConstantesParametres.DOCUMENT_PUBLIQUE_PORT_HTTPS,
            ConstantesParametres.DOCUMENT_PUBLIQUE_PORT_MQ,
        ]
        mappings_demandes = dict()
        for champ in champs_mapping:
            mapping_http = ConstantesParametres.DOCUMENT_CONFIGURATION_PUBLIQUE_MAPPINGS.copy()
            port = configuration_publique[champ]
            mapping_http[ConstantesParametres.DOCUMENT_PUBLIQUE_PORT_INTERNE] = port
            mapping_http[ConstantesParametres.DOCUMENT_PUBLIQUE_PORT_EXTERIEUR] = port
            mapping_http[ConstantesParametres.DOCUMENT_PUBLIQUE_IPV4_INTERNE] = ipv4_interne
            mapping_http[ConstantesParametres.DOCUMENT_PUBLIQUE_PORT_MAPPING_NOM] = \
                'mg_%s_%s' % (self._controleur.configuration.nom_millegrille, champ)

            mappings_demandes[str(port)] = mapping_http

        ops = {
            '$set': {
                ConstantesParametres.DOCUMENT_PUBLIQUE_NOEUD_DOCKER: noeud_docker,
                ConstantesParametres.DOCUMENT_PUBLIQUE_NOEUD_DOCKER_ID: noeud_docker_id,
                ConstantesParametres.DOCUMENT_PUBLIQUE_IPV4_INTERNE: ipv4_interne,
                ConstantesParametres.DOCUMENT_PUBLIQUE_MAPPINGS_IPV4_DEMANDES: mappings_demandes,
            },
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
            '$push': {
                ConstantesParametres.DOCUMENT_PUBLIQUE_ACTIVITE: {
                    '$each': [activite],
                    '$sort': {ConstantesParametres.DOCUMENT_PUBLIQUE_ACTIVITE_DATE: -1},
                    '$slice': ConstantesParametres.DOCUMENT_PUBLIQUE_ACTIVITE_TAILLEMAX,
                }
            }
        }
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesParametres.LIBVAL_CONFIGURATION_PUBLIQUE
        }

        updated = collection.update_one(filtre, ops)
        if updated.modified_count == 0:
            raise Exception(
                "Erreur ajout activite a configuration publique, document %s n'existe pas" %
                ConstantesParametres.LIBVAL_CONFIGURATION_PUBLIQUE
            )

        self.set_etape_suivante(ProcessusDeployerAccesPublic.transmettre_commandes.__name__)

    def transmettre_commandes(self):
        collection = self.document_dao.get_collection(ConstantesParametres.COLLECTION_DOCUMENTS_NOM)
        configuration_publique = collection.find_one(
            {Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesParametres.LIBVAL_CONFIGURATION_PUBLIQUE})

        # Creer commande pour deployer public avec docker
        champs_docker_mappings = [
            ConstantesParametres.DOCUMENT_PUBLIQUE_NOEUD_DOCKER,
            ConstantesParametres.DOCUMENT_PUBLIQUE_NOEUD_DOCKER_ID,
        ]
        commande_docker_mappings = dict()
        for mapping in champs_docker_mappings:
            commande_docker_mappings[mapping] = configuration_publique[mapping]

        self.generateur_transactions.transmettre_commande(commande_docker_mappings, 'commande.monitor.publierNoeudDocker')

        # Creer commande pour ajouter mappings sur le routeur
        mappings_demandes = configuration_publique[ConstantesParametres.DOCUMENT_PUBLIQUE_MAPPINGS_IPV4_DEMANDES]
        commande = {
            ConstantesParametres.DOCUMENT_PUBLIQUE_MAPPINGS_IPV4_DEMANDES: mappings_demandes
        }

        self.generateur_transactions.transmettre_commande(commande, 'commande.monitor.exposerPorts')

        self.set_etape_suivante()

        return {
            'mappings': commande,
            'docker': commande_docker_mappings,
        }

    def _description(self, transaction):
        desc = 'Publier sur noeud %s' % transaction[ConstantesParametres.DOCUMENT_PUBLIQUE_NOEUD_DOCKER]
        return desc


class ProcessusRetirerAccesPublic(ProcessusParametres):
    pass


class ProcessusRenouvellerCertificatPublic(ProcessusParametres):
    pass


class ProcessusMajCertificatPublic(ProcessusParametres):
    pass

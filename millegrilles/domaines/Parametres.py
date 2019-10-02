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
    TRANSACTION_EXPOSER_PORT_ROUTEUR = '%s.public.routeur.exposerPort' % DOMAINE_NOM
    TRANSACTION_RETIRER_PORT_ROUTEUR = '%s.public.routeur.retirerPort' % DOMAINE_NOM
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
    DOCUMENT_PUBLIQUE_ACTIVITE_DETAIL = 'detail'

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
        DOCUMENT_PUBLIQUE_ACTIVITE_DETAIL: dict(),
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
        elif domaine_transaction == ConstantesParametres.TRANSACTION_EXPOSER_PORT_ROUTEUR:
            processus = "millegrilles_domaines_Parametres:ProcessusExposerPortRouteur"
        elif domaine_transaction == ConstantesParametres.TRANSACTION_RETIRER_PORT_ROUTEUR:
            processus = "millegrilles_domaines_Parametres:ProcessusRetirerPortRouteur"
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
        activite[ConstantesParametres.DOCUMENT_PUBLIQUE_ACTIVITE_DESCRIPTION] = self.__description(transaction)
        activite[ConstantesParametres.DOCUMENT_PUBLIQUE_ACTIVITE_DETAIL] = {
            ConstantesParametres.DOCUMENT_PUBLIQUE_IPV4_EXTERNE: transaction.get(ConstantesParametres.DOCUMENT_PUBLIQUE_IPV4_EXTERNE),
            ConstantesParametres.DOCUMENT_PUBLIQUE_ROUTEUR_STATUS: transaction.get(ConstantesParametres.DOCUMENT_PUBLIQUE_ROUTEUR_STATUS),
            ConstantesParametres.DOCUMENT_PUBLIQUE_MAPPINGS_IPV4: transaction.get(ConstantesParametres.DOCUMENT_PUBLIQUE_MAPPINGS_IPV4),
        }

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
                    '$slice': 100,
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


    def __description(self, transaction):
        desc = 'IP ext: %s, etat %s' % (
            transaction.get(ConstantesParametres.DOCUMENT_PUBLIQUE_IPV4_EXTERNE),
            str(transaction.get(ConstantesParametres.DOCUMENT_PUBLIQUE_ROUTEUR_STATUS))
        )
        return desc



class ProcessusExposerPortRouteur(ProcessusParametres):
    pass


class ProcessusRetirerPortRouteur(ProcessusParametres):
    pass


class ProcessusConfirmationRouteur(ProcessusParametres):
    pass


class ProcessusSauverConfigPublique(ProcessusParametres):

    def initiale(self):
        transaction = self.transaction

        activite = ConstantesParametres.DOCUMENT_CONFIGURATION_PUBLIQUE_ACTIVITE.copy()
        activite[ConstantesParametres.DOCUMENT_PUBLIQUE_ACTIVITE_DATE] = datetime.datetime.utcnow()
        activite[ConstantesParametres.DOCUMENT_PUBLIQUE_ACTIVITE_DESCRIPTION] = self.__description(transaction)

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

        activite.update(transaction_detail)

        collection = self.document_dao.get_collection(ConstantesParametres.COLLECTION_DOCUMENTS_NOM)

        ops = {
            '$set': transaction_detail,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
            '$push': {
                ConstantesParametres.DOCUMENT_PUBLIQUE_ACTIVITE: {
                    '$each': [activite],
                    '$sort': {ConstantesParametres.DOCUMENT_PUBLIQUE_ACTIVITE_DATE: -1},
                    '$slice': 100,
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

    def __description(self, transaction):
        desc = 'Mise a jour configuration'
        return desc

class ProcessusDeployerAccesPublic(ProcessusParametres):
    pass


class ProcessusRetirerAccesPublic(ProcessusParametres):
    pass


class ProcessusRenouvellerCertificatPublic(ProcessusParametres):
    pass


class ProcessusMajCertificatPublic(ProcessusParametres):
    pass

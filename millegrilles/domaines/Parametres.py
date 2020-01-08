# Domaine de gestion et d'administration de MilleGrilles
from millegrilles import Constantes
from millegrilles.Constantes import ConstantesParametres
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementMessageDomaineRequete, ExchangeRouter
from millegrilles.dao.MessageDAO import TraitementMessageDomaine
from millegrilles.MGProcessus import  MGProcessusTransaction

import logging
import datetime


class TraitementRequetesPubliquesParametres(TraitementMessageDomaineRequete):

    def traiter_requete(self, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        if routing_key == 'requete.' + ConstantesParametres.REQUETE_NOEUD_PUBLIC:
            noeud_publique = self.gestionnaire.get_noeud_publique(message_dict)
            self.transmettre_reponse(message_dict, noeud_publique, properties.reply_to, properties.correlation_id)
        else:
            raise Exception("Requete publique non supportee " + routing_key)


class ParametresExchangeRouter(ExchangeRouter):

    def determiner_exchanges(self, document):
        """
        :return: Liste des echanges sur lesquels le document doit etre soumis
        """
        exchanges = set()
        mg_libelle = document.get(Constantes.DOCUMENT_INFODOC_LIBELLE)
        if mg_libelle in [ConstantesParametres.LIBVAL_CONFIGURATION_NOEUDPUBLIC]:
            exchanges.add(self._exchange_public)
            exchanges.add(self._exchange_prive)
            exchanges.add(self._exchange_protege)
        else:
            exchanges.add(self._exchange_protege)

        return list(exchanges)

class GestionnaireParametres(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)

        # Queue message handlers
        self.__handler_transaction = TraitementTransactionPersistee(self)
        self.__handler_cedule = TraitementMessageCedule(self)
        self.__handler_requetes_noeuds = {
            Constantes.SECURITE_PUBLIC: TraitementRequetesPubliquesParametres(self),
            Constantes.SECURITE_PROTEGE: TraitementMessageDomaineRequete(self)
        }

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
        idmg = self.configuration.idmg
        document_config_id['idmg'] = idmg
        document_config_id['adresse_url_base'] = '%s.local' % idmg
        self.initialiser_document(ConstantesParametres.LIBVAL_ID_MILLEGRILLE, document_config_id)

        self.demarrer_watcher_collection(
            ConstantesParametres.COLLECTION_DOCUMENTS_NOM,
            ConstantesParametres.QUEUE_ROUTING_CHANGEMENTS,
            ParametresExchangeRouter(self._contexte)
        )

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

    def get_handler_requetes(self) -> dict:
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
        elif domaine_transaction == ConstantesParametres.TRANSACTION_PRIVATISER_NOEUD:
            processus = "millegrilles_domaines_Parametres:ProcessusPrivatiserNoeud"
        elif domaine_transaction == ConstantesParametres.TRANSACTION_FERMER_MILLEGRILLE:
            processus = "millegrilles_domaines_Parametres:FermerMilleGrilles"
        elif domaine_transaction == ConstantesParametres.TRANSACTION_MAJ_NOEUD_PUBLIC:
            processus = "millegrilles_domaines_Parametres:ProcessusConfigurerNoeudPublic"
        elif domaine_transaction == ConstantesParametres.TRANSACTION_SUPPRIMER_NOEUD_PUBLIC:
            processus = "millegrilles_domaines_Parametres:ProcessusSupprimerNoeudPublic"

        else:
            processus = super().identifier_processus(domaine_transaction)

        return processus

    def traiter_cedule(self, evenement):
        pass

    def maj_configuration_noeud_public(self, url, transaction):
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesParametres.LIBVAL_CONFIGURATION_NOEUDPUBLIC,
            ConstantesParametres.DOCUMENT_PUBLIQUE_URL_WEB: url,
        }
        set_on_insert = {Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow()}
        set_on_insert.update(filtre)

        operations = {
            '$set': {
                ConstantesParametres.DOCUMENT_PUBLIQUE_MENU: transaction[ConstantesParametres.DOCUMENT_PUBLIQUE_MENU]
            },
            '$setOnInsert': set_on_insert,
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True
            }
        }

        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        resultat = collection_domaine.update_one(filtre, operations, upsert=True)

        if resultat.upserted_id is None and resultat.modified_count != 1:
            raise Exception("Erreur creation/mise a jour configuration noeud public " + url)

    def get_noeud_publique(self, requete):
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesParametres.LIBVAL_CONFIGURATION_NOEUDPUBLIC,
            ConstantesParametres.DOCUMENT_PUBLIQUE_URL_WEB: requete[ConstantesParametres.DOCUMENT_PUBLIQUE_URL_WEB],
        }

        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        noeud_public = collection_domaine.find_one(filtre)

        return noeud_public


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
            ConstantesParametres.DOCUMENT_PUBLIQUE_URL_COUPDOEIL,
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


class ProcessusConfirmationRouteur(ProcessusParametres):

    def initiale(self):
        self.set_etape_suivante()  # Pour l'instant on ne fait rien avec cette transaction


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
        url_web = configuration_publique[ConstantesParametres.DOCUMENT_PUBLIQUE_URL_WEB]
        url_coupdoeil = configuration_publique[ConstantesParametres.DOCUMENT_PUBLIQUE_URL_COUPDOEIL]

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
                'mg_%s_%s' % (self._controleur.configuration.idmg, champ)

            mappings_demandes[str(port)] = mapping_http

        ops = {
            '$set': {
                ConstantesParametres.DOCUMENT_PUBLIQUE_NOEUD_DOCKER: noeud_docker,
                ConstantesParametres.DOCUMENT_PUBLIQUE_NOEUD_DOCKER_ID: noeud_docker_id,
                ConstantesParametres.DOCUMENT_PUBLIQUE_IPV4_INTERNE: ipv4_interne,
                ConstantesParametres.DOCUMENT_PUBLIQUE_MAPPINGS_IPV4_DEMANDES: mappings_demandes,
                ConstantesParametres.DOCUMENT_PUBLIQUE_ACTIF: True,
                ConstantesParametres.DOCUMENT_PUBLIQUE_URL_WEB: url_web,
                ConstantesParametres.DOCUMENT_PUBLIQUE_URL_COUPDOEIL: url_coupdoeil,
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
        url_web = configuration_publique[ConstantesParametres.DOCUMENT_PUBLIQUE_URL_WEB]
        url_coupdoeil = configuration_publique[ConstantesParametres.DOCUMENT_PUBLIQUE_URL_COUPDOEIL]
        commande = {
            ConstantesParametres.DOCUMENT_PUBLIQUE_MAPPINGS_IPV4_DEMANDES: mappings_demandes,
            ConstantesParametres.DOCUMENT_PUBLIQUE_URL_WEB: url_web,
            ConstantesParametres.DOCUMENT_PUBLIQUE_URL_COUPDOEIL: url_coupdoeil,
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


class ProcessusPrivatiserNoeud(ProcessusParametres):
    """
    Utilise le monitor pour privatiser le node label netzone.public=true et returer les mappings du routeur.
    """

    def initiale(self):
        transaction = self.transaction
        collection = self.document_dao.get_collection(ConstantesParametres.COLLECTION_DOCUMENTS_NOM)

        activite = ConstantesParametres.DOCUMENT_CONFIGURATION_PUBLIQUE_ACTIVITE.copy()
        activite[ConstantesParametres.DOCUMENT_PUBLIQUE_ACTIVITE_DATE] = datetime.datetime.utcnow()
        activite[ConstantesParametres.DOCUMENT_PUBLIQUE_ACTIVITE_DESCRIPTION] = self._description(transaction)

        # Enlever toutes les valeurs
        ops = {
            '$set': {
                ConstantesParametres.DOCUMENT_PUBLIQUE_NOEUD_DOCKER: None,
                ConstantesParametres.DOCUMENT_PUBLIQUE_NOEUD_DOCKER_ID: None,
                ConstantesParametres.DOCUMENT_PUBLIQUE_IPV4_INTERNE: None,
                ConstantesParametres.DOCUMENT_PUBLIQUE_MAPPINGS_IPV4_DEMANDES: None,
                ConstantesParametres.DOCUMENT_PUBLIQUE_ACTIF: False,
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
        transaction = self.transaction

        # Creer commande pour deployer public avec docker
        champs_docker_mappings = [
            ConstantesParametres.DOCUMENT_PUBLIQUE_NOEUD_DOCKER,
            ConstantesParametres.DOCUMENT_PUBLIQUE_NOEUD_DOCKER_ID,
        ]
        commande_docker_mappings = dict()
        for mapping in champs_docker_mappings:
            commande_docker_mappings[mapping] = transaction[mapping]

        self.generateur_transactions.transmettre_commande(commande_docker_mappings, 'commande.monitor.privatiserNoeudDocker')

        # Creer commande pour ajouter mappings sur le routeur
        self.generateur_transactions.transmettre_commande({'tous': True}, 'commande.monitor.retirerPorts')

        self.set_etape_suivante()

        return {
            'docker': commande_docker_mappings,
        }

    def _description(self, transaction):
        desc = 'Privatiser le noeud %s' % transaction[ConstantesParametres.DOCUMENT_PUBLIQUE_NOEUD_DOCKER]
        return desc


class FermerMilleGrilles(ProcessusParametres):
    """
    Transmet la commande de shutdown au moniteur.
    """

    def initiale(self):
        commande = {}
        domaine = 'commande.monitor.fermerMilleGrilles'
        self.generateur_transactions.transmettre_commande(commande, domaine)

        self.set_etape_suivante()


class ProcessusRetirerAccesPublic(ProcessusParametres):
    pass


class ProcessusRenouvellerCertificatPublic(ProcessusParametres):
    pass


class ProcessusMajCertificatPublic(ProcessusParametres):
    pass


class ProcessusConfigurerNoeudPublic(ProcessusParametres):
    """
    Sert a creer ou modifier un noeud public par URL.
    """

    def initiale(self):
        transaction = self.transaction
        url = transaction[ConstantesParametres.DOCUMENT_PUBLIQUE_URL_WEB]
        self.controleur.gestionnaire.maj_configuration_noeud_public(url, transaction)

        self.set_etape_suivante()  # Termine


class ProcessusSupprimerNoeudPublic(ProcessusParametres):
    """
    Sert a creer ou modifier un noeud public par URL.
    """

    def initiale(self):
        transaction = self.transaction
        url = transaction[ConstantesParametres.DOCUMENT_PUBLIQUE_URL_WEB]
        self.controleur.gestionnaire.maj_supprimer_noeud_public(url, transaction)

        self.set_etape_suivante()  # Termine
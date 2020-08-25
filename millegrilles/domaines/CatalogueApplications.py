# Domaine de topologie des noeuds et domaines
import logging
import json
import datetime

from typing import Optional

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesCatalogueApplications
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementRequetesProtegees
from millegrilles.Domaines import TraitementCommandesProtegees
from millegrilles.MGProcessus import MGProcessusTransaction
from millegrilles.dao.MessageDAO import TraitementMessageDomaine

CONFIGURATION_INITIALE_DOMAINE_SENSEURSPASSIFS = {
    "nom": "SenseursPassifs",
    "module": "millegrilles.domaines.SenseursPassifs",
    "classe": "GestionnaireSenseursPassifs"
}

CONFIGURATION_INITIALE_APPLICATION_BLYNK = {
    "nom": "blynk",
    "registries": [
        "docker.maceroc.com",
        "dugremat"
    ],
    "images": {
        "blynk": {
            "image": "mg_blynk",
            "version": "0.41.10_2"
        },
        "blynk_client": {
            "registries": [""],
            "image": "alpine",
            "version": "latest"
        }
    },
    "dependances": [
        {
            "image": "blynk",
            "config": {
                "name": "blynk",
                "constraints": [
                    "node.labels.millegrilles.app.blynk == true"
                ],
                "env": [
                    "SERVER_SSL_KEY=/run/secrets/webkey.pem",
                    "SERVER_SSL_CERT=/run/secrets/webcert.pem"
                ],
                "configs": [
                    {
                        "name": "pki.web.cert;pki.nginx.cert",
                        "filename": "/run/secrets/webcert.pem"
                    }
                ],
                "secrets": [
                    {
                        "name": "pki.web.key;pki.nginx.key",
                        "filename": "webkey.pem"
                    }
                ],
                "mounts": [
                    "blynk_data:/blynk/data:rw"
                ],
                "endpoint_spec": {
                    "mode": "vip",
                    "ports": [{
                        "published_port": 9443,
                        "target_port": 9443,
                        "protocol": "tcp",
                        "publish_mode": "host"
                    }]
                },
                "networks": [{
                    "target": "mg_${IDMG}_net"
                }],
                "labels": {
                    "millegrille": "${IDMG}"
                },
                "resources": {
                    "cpu_limit": 1000000000,
                    "mem_limit": 100000000
                },
                "mode": {
                    "mode": "replicated",
                    "replicas": 1
                }
            }
        },
        {
            "image": "blynk_client",
            "command": "/bin/sleep 10000",
            "etape_seulement": True,
            "backup": {
                "base_path": "/tmp/backup"
            },
            "config": {
                "name": "blynk_client",
                "constraints": [
                    "node.labels.millegrilles.app.blynk == true"
                ],
                "mounts": [
                    "blynk_data:/tmp/backup/data:rw"
                ],
                "labels": {
                    "millegrille": "${IDMG}"
                },
                "resources": {
                    "cpu_limit": 1000000000,
                    "mem_limit": 50000000
                },
                "mode": {
                    "mode": "replicated",
                    "replicas": 1
                }
            }
        }
    ]
}


class TraitementRequetesProtegeesCatalogueApplications(TraitementRequetesProtegees):

    def traiter_requete(self, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        if routing_key == 'requete.' + ConstantesCatalogueApplications.REQUETE_LISTE_DOMAINES:
            reponse = {'liste': self.gestionnaire.get_liste_domaines()}
        elif routing_key == 'requete.' + ConstantesCatalogueApplications.REQUETE_LISTE_APPLICATIONS:
            reponse = {'liste': self.gestionnaire.get_liste_applications()}
        elif routing_key == 'requete.' + ConstantesCatalogueApplications.REQUETE_INFO_DOMAINE:
            reponse = self.gestionnaire.get_domaine(message_dict)
        elif routing_key == 'requete.' + ConstantesCatalogueApplications.REQUETE_INFO_APPLICATION:
            reponse = self.gestionnaire.get_application(message_dict)
        else:
            super().traiter_requete(ch, method, properties, body, message_dict)
            return

        self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)


class TraitementCommandeCatalogueApplications(TraitementCommandesProtegees):

    def traiter_commande(self, enveloppe_certificat, ch, method, properties, body, message_dict):
        # routing_key = method.routing_key
        #
        # resultat = None
        # if Falserouting_key == 'commande.' + SenseursPassifsConstantes.COMMANDE_RAPPORT_HEBDOMADAIRE:
        #     CommandeGenererRapportHebdomadaire(self.gestionnaire, message_dict).generer()
        # elif routing_key == 'commande.' + SenseursPassifsConstantes.COMMANDE_RAPPORT_ANNUEL:
        #     CommandeGenererRapportAnnuel(self.gestionnaire, message_dict).generer()
        # elif routing_key == 'commande.' + SenseursPassifsConstantes.COMMANDE_DECLENCHER_RAPPORTS:
        #     resultat = CommandeDeclencherRapports(self.gestionnaire, message_dict).declencher()
        # else:
        #     resultat = super().traiter_commande(enveloppe_certificat, ch, method, properties, body, message_dict)

        resultat = super().traiter_commande(enveloppe_certificat, ch, method, properties, body, message_dict)

        return resultat


class TraitementEvenementsProteges(TraitementMessageDomaine):

    def __init__(self, gestionnaire_domaine):
        super().__init__(gestionnaire_domaine)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def traiter_message(self, ch, method, properties, body):
        lecture = json.loads(body.decode('utf-8'))


class GestionnaireCatalogueApplications(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self.__traitement_lecture = None
        self.__traitement_requetes = None
        self._traitement_backlog_lectures = None

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.__handler_requetes_noeuds = {
            Constantes.SECURITE_PROTEGE: TraitementRequetesProtegeesCatalogueApplications(self)
        }

        self._traitement_evenements = TraitementEvenementsProteges(self)

        self.__handler_commandes = super().get_handler_commandes()
        self.__handler_commandes[Constantes.SECURITE_PROTEGE] = TraitementCommandeCatalogueApplications(self)

    def configurer(self):
        super().configurer()

        # # Ajouter les index dans la collection de transactions
        # collection_transactions = self.document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM)
        # collection_transactions.create_index(
        #     [
        #         (SenseursPassifsConstantes.TRANSACTION_DATE_LECTURE, 2),
        #         ('%s.%s' %
        #          (Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION, Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE),
        #          1),
        #         (Constantes.DOCUMENT_INFODOC_LIBELLE, 1)
        #     ],
        #     name='date-domaine-mglibelle'
        # )

    def get_queue_configuration(self):
        configuration = super().get_queue_configuration()

        # configuration.append({
        #     'nom': '%s.%s' % (self.get_nom_queue(), 'evenements_lectures'),
        #     'routing': [
        #         'evenement.%s.#.lecture' % self.get_nom_domaine(),
        #     ],
        #     'exchange': self.configuration.exchange_protege,
        #     'ttl': 60000,
        #     'callback': self._traitement_evenements_lecture.callbackAvecAck
        # })

        return configuration

    def demarrer(self):
        super().demarrer()

        # Verifier si les documents existent, inserer via transaction au besoin
        self._inserer_catalogues_initiaux()

    def arreter(self):
        super().arreter()

    def get_handler_requetes(self) -> dict:
        return self.__handler_requetes_noeuds

    def get_handler_commandes(self) -> dict:
        return self.__handler_commandes

    def get_nom_queue(self):
        return ConstantesCatalogueApplications.QUEUE_NOM

    def get_collection_transaction_nom(self):
        return ConstantesCatalogueApplications.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesCatalogueApplications.COLLECTION_PROCESSUS_NOM

    def get_nom_domaine(self):
        return ConstantesCatalogueApplications.DOMAINE_NOM

    def traiter_cedule(self, evenement):
        """
        Traite les evenements sur cedule.
        :param evenement:
        :return:
        """
        super().traiter_cedule(evenement)

        # indicateurs = evenement['indicateurs']
        #
        # # Verifier si les indicateurs sont pour notre timezone
        # if 'heure' in indicateurs:
        #     try:
        #         self.traiter_cedule_heure(evenement)
        #     except Exception as he:
        #         self.__logger.exception("Erreur traitement cedule horaire: %s" % str(he))
        #
        #     # Verifier si on a l'indicateur jour pour notre TZ (pas interesse par minuit UTC)
        #     if 'Canada/Eastern' in indicateurs:
        #         if 'jour' in indicateurs:
        #             try:
        #                 self.traiter_cedule_quotidienne(evenement)
        #             except Exception as de:
        #                 self.__logger.exception("Erreur traitement cedule quotidienne: %s" % str(de))

    def get_nom_collection(self):
        return ConstantesCatalogueApplications.COLLECTION_DOCUMENTS_NOM

    def identifier_processus(self, domaine_transaction):
        if domaine_transaction == ConstantesCatalogueApplications.TRANSACTION_MAJ_DOMAINE:
            processus = "millegrilles_domaines_CatalogueApplications:ProcessusTransactionMajDomaine"
        elif domaine_transaction == ConstantesCatalogueApplications.TRANSACTION_CATALOGUE_DOMAINES:
            processus = "millegrilles_domaines_CatalogueApplications:ProcessusTransactionMajDomaines"
        elif domaine_transaction == ConstantesCatalogueApplications.TRANSACTION_MAJ_APPLICATION:
            processus = "millegrilles_domaines_CatalogueApplications:ProcessusTransactionMajApplication"
        else:
            # Type de transaction inconnue, on lance une exception
            processus = super().identifier_processus(domaine_transaction)

        return processus

    def _inserer_catalogues_initiaux(self):
        collection = self.document_dao.get_collection(ConstantesCatalogueApplications.COLLECTION_DOCUMENTS_NOM)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': [
                ConstantesCatalogueApplications.LIBVAL_DOMAINE, ConstantesCatalogueApplications.LIBVAL_APPLICATION]},
        }
        curseur_docs = collection.find(filtre)

        domaines = {
            'SenseursPassifs': CONFIGURATION_INITIALE_DOMAINE_SENSEURSPASSIFS,
        }
        applications = {
            'blynk': CONFIGURATION_INITIALE_APPLICATION_BLYNK,
        }

        for doc in curseur_docs:
            libval = doc[Constantes.DOCUMENT_INFODOC_LIBELLE]
            if libval == ConstantesCatalogueApplications.LIBVAL_APPLICATION:
                nom_application = doc['nom']
                if applications.get(nom_application):
                    # Enlever de la liste, deja configure
                    del applications[nom_application]
            elif libval == ConstantesCatalogueApplications.LIBVAL_DOMAINE:
                nom_domaine = doc['nom']
                if domaines.get(nom_domaine):
                    # Enlever de la liste, deja configure
                    del domaines[nom_domaine]

        # Creer transactions pour applications et domaines restants
        for domaine in domaines.values():
            domaine_action = ConstantesCatalogueApplications.TRANSACTION_MAJ_DOMAINE
            self.generateur_transactions.soumettre_transaction(domaine, domaine_action)

        for app in applications.values():
            domaine_action = ConstantesCatalogueApplications.TRANSACTION_MAJ_APPLICATION
            self.generateur_transactions.soumettre_transaction(app, domaine_action)

    def traiter_transaction_maj_domaine(self, transaction):
        collection = self.document_dao.get_collection(ConstantesCatalogueApplications.COLLECTION_DOCUMENTS_NOM)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesCatalogueApplications.LIBVAL_DOMAINE,
            'nom': transaction['nom'],
        }
        on_insert = {
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
        }
        on_insert.update(filtre)

        set_ops = dict()
        for key, value in transaction.items():
            if key not in ['nom']:
                set_ops[key] = value

        ops = {
            '$set': set_ops,
            '$setOnInsert': on_insert,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }

        collection.update(filtre, ops, upsert=True)

    def traiter_transaction_maj_application(self, transaction):
        collection = self.document_dao.get_collection(ConstantesCatalogueApplications.COLLECTION_DOCUMENTS_NOM)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesCatalogueApplications.LIBVAL_APPLICATION,
            'nom': transaction['nom'],
        }
        on_insert = {
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
        }
        on_insert.update(filtre)

        set_ops = dict()
        for key, value in transaction.items():
            if key not in ['nom']:
                set_ops[key] = value

        ops = {
            '$set': set_ops,
            '$setOnInsert': on_insert,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }

        collection.update(filtre, ops, upsert=True)

    def get_liste_domaines(self):
        """
        Faire une liste des domaines connus
        :return:
        """
        collection = self.document_dao.get_collection(ConstantesCatalogueApplications.COLLECTION_DOCUMENTS_NOM)
        filtre = {Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesCatalogueApplications.LIBVAL_DOMAINE}
        projection = {'nom': 1}

        domaines = list()
        for domaine in collection.find(filtre, projection):
            info = {
                'nom': domaine['nom']
            }
            domaines.append(info)

        return domaines

    def get_liste_applications(self):
        collection = self.document_dao.get_collection(ConstantesCatalogueApplications.COLLECTION_DOCUMENTS_NOM)
        filtre = {Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesCatalogueApplications.LIBVAL_APPLICATION}
        projection = {'nom': 1}

        applications = list()
        for domaine in collection.find(filtre, projection):
            info = {
                'nom': domaine['nom']
            }
            applications.append(info)

        return applications

    def get_domaine(self, params: dict):
        collection = self.document_dao.get_collection(ConstantesCatalogueApplications.COLLECTION_DOCUMENTS_NOM)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesCatalogueApplications.LIBVAL_DOMAINE,
            'nom': params['nom']
        }
        domaine = collection.find_one(filtre)

        domaine_resultat = dict()
        if domaine:
            for key, value in domaine.items():
                if key not in ['_id']:
                    domaine_resultat[key] = value

        return domaine_resultat

    def get_application(self, params: dict):
        collection = self.document_dao.get_collection(ConstantesCatalogueApplications.COLLECTION_DOCUMENTS_NOM)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesCatalogueApplications.LIBVAL_APPLICATION,
            'nom': params['nom']
        }
        application = collection.find_one(filtre)

        application_resultat = dict()
        if application:
            for key, value in application.items():
                if key not in ['_id']:
                    application_resultat[key] = value

        return application_resultat


class ProcessusCatalogueApplications(MGProcessusTransaction):

    def get_collection_transaction_nom(self):
        return ConstantesCatalogueApplications.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesCatalogueApplications.COLLECTION_PROCESSUS_NOM


class ProcessusTransactionMajDomaine(ProcessusCatalogueApplications):
    """
    Processus pour enregistrer une transaction
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        transaction = self.transaction_filtree
        self.__logger.debug("Document processus: %s" % self._document_processus)
        self.__logger.debug("Document transaction: %s" % transaction)

        self.controleur.gestionnaire.traiter_transaction_maj_domaine(transaction)

        self.set_etape_suivante()  # Terminer


class ProcessusTransactionMajDomaines(ProcessusCatalogueApplications):
    """
    Processus pour enregistrer une transaction
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        transaction = self.transaction_filtree
        self.__logger.debug("Document processus: %s" % self._document_processus)
        self.__logger.debug("Document transaction: %s" % transaction)

        for nom_domaine, configuration in transaction['domaines'].items():
            info_domaine = {
                'nom': nom_domaine,
                'module': configuration['module'],
                'classe': configuration['classe'],
            }
            self.controleur.gestionnaire.traiter_transaction_maj_domaine(info_domaine)

        self.set_etape_suivante()  # Terminer


class ProcessusTransactionMajApplication(ProcessusCatalogueApplications):
    """
    Processus pour enregistrer une transaction
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        transaction = self.transaction_filtree
        self.__logger.debug("Document processus: %s" % self._document_processus)
        self.__logger.debug("Document transaction: %s" % transaction)

        self.controleur.gestionnaire.traiter_transaction_maj_application(transaction)

        self.set_etape_suivante()  # Terminer
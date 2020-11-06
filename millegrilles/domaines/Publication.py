from pymongo.errors import DuplicateKeyError

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesPublication
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementRequetesProtegees, TraitementMessageDomaineRequete, HandlerBackupDomaine, \
    RegenerateurDeDocuments, GroupeurTransactionsARegenerer
from millegrilles.MGProcessus import MGProcessusTransaction, MGPProcesseur

import os
import logging
import uuid
import datetime
import json


class TraitementRequetesPubliquesPublication(TraitementMessageDomaineRequete):

    def traiter_requete(self, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        reponse = None
        if routing_key == 'requete.' + ConstantesPublication.REQUETE_CONFIGURATION_NOEUDS:
            raise NotImplementedError()
        else:
            raise Exception("Requete publique non supportee " + routing_key)

        if reponse:
            self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)


class GestionnairePublication(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.__handler_requetes_noeuds = {
            Constantes.SECURITE_PUBLIC: TraitementRequetesPubliquesPublication(self),
            Constantes.SECURITE_PROTEGE: TraitementRequetesPubliquesPublication(self)
        }

    def configurer(self):
        super().configurer()
        self.creer_index()  # Creer index dans MongoDB

    def demarrer(self):
        super().demarrer()
        self.initialiser_document(Constantes.LIBVAL_CONFIGURATION, ConstantesPublication.DOCUMENT_DEFAUT)

    def creer_index(self):
        collection_noeuds = self.document_dao.get_collection(ConstantesPublication.COLLECTION_NOEUDS_NOM)
        collection_posts = self.document_dao.get_collection(ConstantesPublication.COLLECTION_POSTS_NOM)

        # Index _mg-libelle
        collection_noeuds.create_index([(Constantes.DOCUMENT_INFODOC_LIBELLE, 1)], name='mglibelle')
        collection_posts.create_index([(Constantes.DOCUMENT_INFODOC_LIBELLE, 1)], name='mglibelle')

    def traiter_cedule(self, evenement):
        super().traiter_cedule(evenement)

        # minutes = evenement['timestamp']['UTC'][4]
        #
        # if minutes % 15 == 3:
        #     self.resoumettre_conversions_manquantes()

    def get_handler_requetes(self) -> dict:
        return self.__handler_requetes_noeuds

    def get_nom_collection(self):
        return ConstantesPublication.COLLECTION_NOEUDS_NOM

    def get_nom_queue(self):
        return ConstantesPublication.QUEUE_NOM

    def get_collection_transaction_nom(self):
        return ConstantesPublication.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesPublication.COLLECTION_PROCESSUS_NOM

    def get_nom_domaine(self):
        return ConstantesPublication.DOMAINE_NOM

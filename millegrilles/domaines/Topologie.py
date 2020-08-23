# Domaine de topologie des noeuds et domaines
import logging
import json
import datetime

from typing import Optional

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesTopologie
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementMessageDomaineRequete, TraitementRequetesProtegees
from millegrilles.Domaines import ExchangeRouter, TraitementCommandesProtegees
from millegrilles.MGProcessus import MGProcessusTransaction
from millegrilles.dao.MessageDAO import TraitementMessageDomaine


class TraitementRequetesProtegeesTopologie(TraitementRequetesProtegees):

    def traiter_requete(self, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        # if routing_key == 'requete.' + SenseursPassifsConstantes.REQUETE_VITRINE_DASHBOARD:
        #     reponse = self.gestionnaire.get_vitrine_dashboard()
        #     self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)
        # else:
        #     super().traiter_requete(ch, method, properties, body, message_dict)


class TraitementCommandeTopologie(TraitementCommandesProtegees):

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


# Gestionnaire pour le domaine millegrilles.domaines.SenseursPassifs.
class GestionnaireTopologie(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self.__traitement_lecture = None
        self.__traitement_requetes = None
        self._traitement_backlog_lectures = None

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.__handler_requetes_noeuds = {
            Constantes.SECURITE_PROTEGE: TraitementRequetesProtegeesTopologie(self)
        }

        self._traitement_evenements = TraitementEvenementsProteges(self)

        self.__handler_commandes = super().get_handler_commandes()
        self.__handler_commandes[Constantes.SECURITE_PROTEGE] = TraitementCommandeTopologie(self)

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
        # Documents initiaux
        # self.initialiser_document(
        #     SenseursPassifsConstantes.LIBVAL_CONFIGURATION,
        #     SenseursPassifsConstantes.DOCUMENT_DEFAUT_CONFIGURATION
        # )

    def arreter(self):
        super().arreter()

    def get_handler_requetes(self) -> dict:
        return self.__handler_requetes_noeuds

    def get_handler_commandes(self) -> dict:
        return self.__handler_commandes

    def get_nom_queue(self):
        return ConstantesTopologie.QUEUE_NOM

    def get_collection_transaction_nom(self):
        return ConstantesTopologie.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesTopologie.COLLECTION_PROCESSUS_NOM

    def get_nom_domaine(self):
        return ConstantesTopologie.DOMAINE_NOM

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
        return ConstantesTopologie.COLLECTION_DOCUMENTS_NOM

    def identifier_processus(self, domaine_transaction):
        # if domaine_transaction == SenseursPassifsConstantes.TRANSACTION_DOMAINE_LECTURE:
        #     processus = "millegrilles_domaines_SenseursPassifs:ProcessusTransactionSenseursPassifsLecture"
        # elif domaine_transaction == SenseursPassifsConstantes.TRANSACTION_MAJ_SENSEUR:
        #     processus = "millegrilles_domaines_SenseursPassifs:ProcessusMajSenseur"
        # elif domaine_transaction == SenseursPassifsConstantes.TRANSACTION_MAJ_NOEUD:
        #     processus = "millegrilles_domaines_SenseursPassifs:ProcessusMajNoeud"
        # elif domaine_transaction == SenseursPassifsConstantes.TRANSACTION_DOMAINE_SUPPRESSION_SENSEUR:
        #     processus = "millegrilles_domaines_SenseursPassifs:ProcessusSupprimerSenseur"
        # else:
        #     # Type de transaction inconnue, on lance une exception
        processus = super().identifier_processus(domaine_transaction)

        return processus


class ProcessusTopologie(MGProcessusTransaction):

    def get_collection_transaction_nom(self):
        return ConstantesTopologie.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesTopologie.COLLECTION_PROCESSUS_NOM


class ProcessusTransactionAjouterNoeud(ProcessusTopologie):
    """
    Processus pour enregistrer une transaction d'un senseur passif
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        """
        Enregistrer l'information de la transaction dans le document du senseur
        :return:
        """
        transaction = self.charger_transaction()
        self.__logger.debug("Document processus: %s" % self._document_processus)
        self.__logger.debug("Document transaction: %s" % transaction)

        self.set_etape_suivante()  # Terminer


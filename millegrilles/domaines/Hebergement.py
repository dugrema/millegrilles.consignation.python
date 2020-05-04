# Domaine d'hebergemenet de MilleGrilles par un hote
import logging
import datetime

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesHebergement
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementMessageDomaineRequete, \
    TraitementCommandesProtegees
from millegrilles.MGProcessus import MGProcessus, MGProcessusTransaction
from millegrilles.Domaines import ExchangeRouter
from millegrilles.util import X509Certificate


class TraitementRequetesProtegees(TraitementMessageDomaineRequete):

    def traiter_requete(self, ch, method, properties, body, message_dict):
        routing_key = method.routing_key

        reponse = None
        if routing_key == 'requete.%s' % ConstantesHebergement.REQUETE_MILLEGRILLES_ACTIVES:
            reponse = self.gestionnaire.get_millegrilles_actives()
        elif routing_key == 'requete.%s' % ConstantesHebergement.REQUETE_MILLEGRILLES_HEBERGEES:
            reponse = self.gestionnaire.get_millegrilles_hebergees()
        else:
            super().traiter_requete(ch, method, properties, body, message_dict)

        if reponse:
            self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)


class TraitementCommandesHebergementProtegees(TraitementCommandesProtegees):

    def traiter_commande(self, enveloppe_certificat, ch, method, properties, body, message_dict) -> dict:
        routing_key = method.routing_key

        resultat: dict
        if routing_key == 'commande.%s' % ConstantesHebergement.COMMANDE_CREER_MILLEGRILLE_HEBERGEE:
            resultat = self._gestionnaire.creer_trousseau_millegrille(message_dict, properties)
        else:
            resultat = super().traiter_commande(enveloppe_certificat, ch, method, properties, body, message_dict)

        return resultat


class HebergementExchangeRouter(ExchangeRouter):

    def determiner_exchanges(self, document):
        """
        :return: Liste des echanges sur lesquels le document doit etre soumis
        """
        exchanges = set()
        exchanges.add(self._exchange_protege)
        # mg_libelle = document.get(Constantes.DOCUMENT_INFODOC_LIBELLE)
        # if mg_libelle in [SenseursPassifsConstantes.LIBVAL_VITRINE_DASHBOARD, SenseursPassifsConstantes.LIBELLE_DOCUMENT_SENSEUR]:
        #     exchanges.add(self._exchange_public)
        #     exchanges.add(self._exchange_prive)
        #     exchanges.add(self._exchange_protege)
        # else:
        #     exchanges.add(self._exchange_protege)

        return list(exchanges)


class GestionnaireHebergement(GestionnaireDomaineStandard):
    """
    Gestionnaire du domaine de l'hebergement de MilleGrilles
    """

    def __init__(self, contexte):
        super().__init__(contexte)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.__handler_requetes_noeuds = {
            Constantes.SECURITE_PROTEGE: TraitementRequetesProtegees(self),
        }
        self.__handlers_commandes = {
            Constantes.SECURITE_PROTEGE: TraitementCommandesHebergementProtegees(self),
        }

    def demarrer(self):
        super().demarrer()
        # self.initialiser_document(ConstantesPki.LIBVAL_CONFIGURATION, ConstantesPki.DOCUMENT_DEFAUT)

        self.demarrer_watcher_collection(
            ConstantesHebergement.COLLECTION_DOCUMENTS_NOM, ConstantesHebergement.ROUTING_CHANGEMENTS,
            HebergementExchangeRouter(self._contexte))

    def get_nom_queue(self):
        return ConstantesHebergement.QUEUE_NOM

    def get_nom_queue_certificats(self):
        return ConstantesHebergement.QUEUE_NOM

    def get_nom_collection(self):
        return ConstantesHebergement.COLLECTION_DOCUMENTS_NOM

    def get_collection_transaction_nom(self):
        return ConstantesHebergement.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesHebergement.COLLECTION_PROCESSUS_NOM

    def get_nom_domaine(self):
        return ConstantesHebergement.DOMAINE_NOM

    def get_handler_requetes(self) -> dict:
        return self.__handler_requetes_noeuds

    def get_handler_commandes(self) -> dict:
        return self.__handlers_commandes

    def identifier_processus(self, domaine_transaction):

        if domaine_transaction == ConstantesHebergement.TRANSACTION_NOUVEAU_IDMG:
            processus = "millegrilles_domaines_Hebergement:ProcessusNouveauIdmg"
        elif domaine_transaction == ConstantesHebergement.TRANSACTION_ACTIVER_MILLEGRILLE_HEBERGEE:
            processus = "millegrilles_domaines_Hebergement:ProcessusActiverHebergement"
        elif domaine_transaction == ConstantesHebergement.TRANSACTION_DESACTIVER_MILLEGRILLE_HEBERGEE:
            processus = "millegrilles_domaines_Hebergement:ProcessusDesactiverHebergement"
        elif domaine_transaction == ConstantesHebergement.TRANSACTION_SUPPRIMER_MILLEGRILLE_HEBERGEE:
            processus = "millegrilles_domaines_Hebergement:ProcessusSupprimerHebergement"

        else:
            processus = super().identifier_processus(domaine_transaction)

        return processus

    # --- Operations du domaine ---

    def creer_trousseau_millegrille(self, commande, properties):
        """
        Lance les commandes / transactions requises pour creer une nouvelle MilleGrille hebergee
        :param commande:
        :return:
        """
        domaine = 'commande.%s.%s' % (
            Constantes.ConstantesMaitreDesCles.DOMAINE_NOM,
            Constantes.ConstantesMaitreDesCles.COMMANDE_CREER_CLES_MILLEGRILLE_HEBERGEE
        )
        self.generateur_transactions.transmettre_commande(
            commande, domaine, exchange=self.configuration.exchange_middleware)

        self.generateur_transactions.transmettre_reponse({'resultats': {'ok': True}}, properties.reply_to, properties.correlation_id)

    def maj_hebergement(self, parametres: dict):
        idmg = parametres['idmg']

        activite = parametres.get(ConstantesHebergement.CHAMP_HEBERGEMENT_ETAT) or ConstantesHebergement.VALEUR_HEBERGEMENT_ACTIF

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesHebergement.LIBVAL_MILLEGRILLE_HEBERGEE,
            'idmg': idmg,
        }

        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
        }
        set_on_insert.update(filtre)

        set_ops = {
            ConstantesHebergement.CHAMP_HEBERGEMENT_ETAT: activite,
        }

        ops = {
            '$set': set_ops,
            '$setOnInsert': set_on_insert,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }

        collection = self.document_dao.get_collection(ConstantesHebergement.COLLECTION_DOCUMENTS_NOM)
        collection.update_one(filtre, ops, upsert=True)

    def supprimer_hebergement(self, idmg):
        filtre = {
            'idmg': idmg,
        }
        collection = self.document_dao.get_collection(ConstantesHebergement.COLLECTION_DOCUMENTS_NOM)
        collection.delete_one(filtre)

    def get_millegrilles_actives(self):

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesHebergement.LIBVAL_MILLEGRILLE_HEBERGEE,
            ConstantesHebergement.CHAMP_HEBERGEMENT_ETAT: ConstantesHebergement.VALEUR_HEBERGEMENT_ACTIF,
        }

        collection = self.document_dao.get_collection(ConstantesHebergement.COLLECTION_DOCUMENTS_NOM)
        curseur = collection.find(filtre)

        liste = list()
        for doc in curseur:
            liste.append({
                'idmg': doc['idmg']
            })

        return liste

    def get_millegrilles_hebergees(self):

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesHebergement.LIBVAL_MILLEGRILLE_HEBERGEE,
        }

        collection = self.document_dao.get_collection(ConstantesHebergement.COLLECTION_DOCUMENTS_NOM)
        curseur = collection.find(filtre)

        liste = [self.filtrer_doc(doc) for doc in curseur]  # Extraire liste du curseur

        return liste

    def filtrer_doc(self, doc: dict):
        resultat = dict()
        for key, value in doc.items():
            if not key.startswith('_'):
                resultat[key] = value
        return resultat


class ProcessusNouveauIdmg(MGProcessusTransaction):

    def __init__(self, controleur, evenement, transaction_mapper=None):
        super().__init__(controleur, evenement, transaction_mapper)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        transaction = self.charger_transaction()
        idmg = transaction['idmg']

        parametres = {
            ConstantesHebergement.CHAMP_HEBERGEMENT_ETAT: ConstantesHebergement.VALEUR_HEBERGEMENT_ACTIF,
            Constantes.CONFIG_IDMG: idmg,
        }

        # Creer document d'hebergement de la MilleGrille
        self.controleur.gestionnaire.maj_hebergement(parametres)

        # Transmettre commande pour activer l'hebergement de la MilleGrille
        commande = {'idmg': idmg}
        commande_domaine = 'commande.' + Constantes.ConstantesServiceMonitor.COMMANDE_ACTIVER_HEBERGEMENT
        self.ajouter_commande_a_transmettre(commande_domaine, commande)

        self.set_etape_suivante()  # Termine


class ProcessusActiverHebergement(MGProcessusTransaction):

    def __init__(self, controleur, evenement, transaction_mapper=None):
        super().__init__(controleur, evenement, transaction_mapper)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        transaction = self.charger_transaction()
        idmg = transaction['idmg']

        parametres = {
            ConstantesHebergement.CHAMP_HEBERGEMENT_ETAT: ConstantesHebergement.VALEUR_HEBERGEMENT_ACTIF,
            Constantes.CONFIG_IDMG: idmg,
        }

        # Creer document d'hebergement de la MilleGrille
        self.controleur.gestionnaire.maj_hebergement(parametres)

        # Transmettre commande pour activer l'hebergement de la MilleGrille
        commande = {'idmg': idmg}
        commande_domaine = 'commande.' + Constantes.ConstantesServiceMonitor.COMMANDE_ACTIVER_HEBERGEMENT
        self.ajouter_commande_a_transmettre(commande_domaine, commande)

        self.set_etape_suivante()  # Termine


class ProcessusDesactiverHebergement(MGProcessusTransaction):

    def __init__(self, controleur, evenement, transaction_mapper=None):
        super().__init__(controleur, evenement, transaction_mapper)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        transaction = self.charger_transaction()
        idmg = transaction['idmg']

        parametres = {
            ConstantesHebergement.CHAMP_HEBERGEMENT_ETAT: ConstantesHebergement.VALEUR_HEBERGEMENT_INACTIF,
            Constantes.CONFIG_IDMG: idmg,
        }

        # Creer document d'hebergement de la MilleGrille
        self.controleur.gestionnaire.maj_hebergement(parametres)

        # Transmettre commande pour activer l'hebergement de la MilleGrille
        commande = {'idmg': idmg}
        commande_domaine = 'commande.' + Constantes.ConstantesServiceMonitor.COMMANDE_DESACTIVER_HEBERGEMENT
        self.ajouter_commande_a_transmettre(commande_domaine, commande)

        self.set_etape_suivante()  # Termine


class ProcessusSupprimerHebergement(MGProcessusTransaction):

    def __init__(self, controleur, evenement, transaction_mapper=None):
        super().__init__(controleur, evenement, transaction_mapper)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        transaction = self.charger_transaction()
        idmg = transaction['idmg']

        # Creer document d'hebergement de la MilleGrille
        self.controleur.gestionnaire.supprimer_hebergement(idmg)

        # Transmettre commande pour desactiver l'hebergement de la MilleGrille
        commande = {'idmg': idmg}
        commande_domaine = 'commande.' + Constantes.ConstantesServiceMonitor.COMMANDE_DESACTIVER_HEBERGEMENT
        self.ajouter_commande_a_transmettre(commande_domaine, commande)

        # Supprimer trousseau de la MilleGrille hebergee du MaitreDesCles
        transaction_domaine = 'commande.' + Constantes.ConstantesMaitreDesCles.TRANSACTION_HEBERGEMENT_SUPPRIMER
        self.ajouter_transaction_a_soumettre(transaction_domaine, commande)

        self.set_etape_suivante()  # Termine

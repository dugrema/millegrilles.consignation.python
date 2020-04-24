# Domaine d'hebergemenet de MilleGrilles par un hote
import logging
import datetime

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesHebergement
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementMessageDomaineRequete, \
    TraitementCommandesProtegees
from millegrilles.MGProcessus import MGProcessus, MGProcessusTransaction
from millegrilles.util import X509Certificate


class TraitementRequetesProtegees(TraitementMessageDomaineRequete):

    def traiter_requete(self, ch, method, properties, body, message_dict):
        routing_key = method.routing_key

        reponse = None
        if routing_key == 'requete.%s' % ConstantesHebergement.REQUETE_MILLEGRILLES_ACTIVES:
            reponse = self.gestionnaire.get_millegrilles_actives()
        else:
            super().traiter_requete(ch, method, properties, body, message_dict)

        if reponse:
            self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)


class TraitementCommandesHebergementProtegees(TraitementCommandesProtegees):

    def traiter_commande(self, enveloppe_certificat, ch, method, properties, body, message_dict) -> dict:
        routing_key = method.routing_key

        resultat: dict
        if routing_key == 'commande.%s' % ConstantesHebergement.COMMANDE_CREER_MILLEGRILLE_HEBERGEE:
            resultat = self._gestionnaire.creer_trousseau_millegrille(message_dict)
        else:
            resultat = super().traiter_commande(enveloppe_certificat, ch, method, properties, body, message_dict)

        return resultat


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

        else:
            processus = super().identifier_processus(domaine_transaction)

        return processus

    # --- Operations du domaine ---

    def creer_trousseau_millegrille(self, commande):
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

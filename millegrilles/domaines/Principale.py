# Domaine de l'interface principale de l'usager. Ne peut pas etre deleguee.
import logging
import datetime

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesPrincipale
from millegrilles.Domaines import GestionnaireDomaineStandard, ExchangeRouter
from millegrilles.dao.MessageDAO import TraitementMessageDomaine
from millegrilles.MGProcessus import MGProcessusTransaction, ErreurMAJProcessus
from millegrilles.Domaines import TraitementMessageDomaineRequete, TraitementRequetesProtegees


class TraitementRequetesPubliques(TraitementMessageDomaineRequete):

    def traiter_requete(self, ch, method, properties, body, message_dict, enveloppe_certificat):
        routing_key = method.routing_key
        action = routing_key.split('.')[-1]

        reponse = None
        if action == ConstantesPrincipale.REQUETE_PROFIL_MILLEGRILLE:
            reponse = self.gestionnaire.charger_documents([ConstantesPrincipale.LIBVAL_PROFIL_MILLEGRILLE, ConstantesPrincipale.LIBVAL_DOMAINES])
        elif action == ConstantesPrincipale.REQUETE_PROFIL_USAGER:
            reponse = self.gestionnaire.charger_documents([ConstantesPrincipale.LIBVAL_PROFIL_MILLEGRILLE, ConstantesPrincipale.LIBVAL_PROFIL_USAGER])

        if reponse is not None:
            self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)


class TraitementRequetesProtegeesPrincipale(TraitementRequetesProtegees):

    def traiter_requete(self, ch, method, properties, body, message_dict, enveloppe_certificat):
        routing_key = method.routing_key
        action = routing_key.split('.')[-1]

        reponse = None
        if action == ConstantesPrincipale.REQUETE_AUTHINFO_MILLEGRILLE:
            reponse = self.gestionnaire.charger_documents([ConstantesPrincipale.LIBVAL_CLES])
        elif action == ConstantesPrincipale.REQUETE_PROFIL_MILLEGRILLE:
            reponse = self.gestionnaire.charger_documents([ConstantesPrincipale.LIBVAL_PROFIL_MILLEGRILLE, ConstantesPrincipale.LIBVAL_DOMAINES])
        elif action == ConstantesPrincipale.REQUETE_PROFIL_USAGER:
            reponse = self.gestionnaire.charger_documents([ConstantesPrincipale.LIBVAL_PROFIL_MILLEGRILLE, ConstantesPrincipale.LIBVAL_PROFIL_USAGER])
        else:
            super().traiter_requete(ch, method, properties, body, message_dict)

        if reponse is not None:
            self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)


class PrincipaleExchangeRouter(ExchangeRouter):

    def determiner_exchanges(self, document):
        """
        :return: Liste des echanges sur lesquels le document doit etre soumis
        """
        exchanges = set()
        mg_libelle = document.get(Constantes.DOCUMENT_INFODOC_LIBELLE)

        libvals_relai = [
            ConstantesPrincipale.LIBVAL_PROFIL_MILLEGRILLE,
            ConstantesPrincipale.LIBVAL_PROFIL_USAGER,
        ]

        if mg_libelle in libvals_relai:
            exchanges.add(self._exchange_public)
            exchanges.add(self._exchange_prive)
            exchanges.add(self._exchange_protege)
        # else:
        #     exchanges.add(self._exchange_protege)

        return list(exchanges)


class GestionnairePrincipale(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._traitement_message = None
        self._logger = logging.getLogger("%s.GestionnaireRapports" % __name__)

        self.__handler_requetes = {
            Constantes.SECURITE_PUBLIC: TraitementRequetesPubliques(self),
            Constantes.SECURITE_PROTEGE: TraitementRequetesProtegeesPrincipale(self),
        }

    def configurer(self):
        super().configurer()
        self._traitement_message = TraitementMessagePrincipale(self)

    def demarrer(self):
        super().demarrer()
        self.initialiser_document(ConstantesPrincipale.LIBVAL_CONFIGURATION, ConstantesPrincipale.DOCUMENT_DEFAUT)
        self.initialiser_document(ConstantesPrincipale.LIBVAL_ALERTES, ConstantesPrincipale.DOCUMENT_ALERTES)
        self.initialiser_document(ConstantesPrincipale.LIBVAL_PROFIL_USAGER, ConstantesPrincipale.DOCUMENT_PROFIL_USAGER)
        self.initialiser_document(ConstantesPrincipale.LIBVAL_DOMAINES, ConstantesPrincipale.DOCUMENT_DOMAINES)
        self.initialiser_document(ConstantesPrincipale.LIBVAL_CLES, ConstantesPrincipale.DOCUMENT_CLES)

        profil_millegrille = ConstantesPrincipale.DOCUMENT_PROFIL_MILLEGRILLE
        profil_millegrille[Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG] = self.configuration.idmg
        self.initialiser_document(ConstantesPrincipale.LIBVAL_PROFIL_MILLEGRILLE, ConstantesPrincipale.DOCUMENT_PROFIL_MILLEGRILLE)

        self.demarrer_watcher_collection(
            ConstantesPrincipale.COLLECTION_DOCUMENTS_NOM,
            ConstantesPrincipale.QUEUE_ROUTING_CHANGEMENTS,
            PrincipaleExchangeRouter(self._contexte)
        )

        self.upgrade_menu()

    def traiter_cedule(self, evenement):
        super().traiter_cedule(evenement)

    def traiter_transaction(self, ch, method, properties, body):
        self._traitement_message.callbackAvecAck(ch, method, properties, body)

    def get_nom_collection(self):
        return ConstantesPrincipale.COLLECTION_DOCUMENTS_NOM

    def get_nom_queue(self):
        return ConstantesPrincipale.QUEUE_NOM

    def get_handler_requetes(self):
        return self.__handler_requetes

    def get_nom_queue_requetes_noeuds(self):
        return '%s.noeuds' % self.get_nom_queue()

    def get_nom_queue_requetes_inter(self):
        return '%s.inter' % self.get_nom_queue()

    def get_collection_transaction_nom(self):
        return ConstantesPrincipale.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesPrincipale.COLLECTION_PROCESSUS_NOM

    def get_nom_domaine(self):
        return ConstantesPrincipale.DOMAINE_NOM

    def identifier_processus(self, domaine_transaction):
        if domaine_transaction == ConstantesPrincipale.TRANSACTION_ACTION_FERMERALERTE:
            processus = "millegrilles_domaines_Principale:ProcessusFermerAlerte"
        elif domaine_transaction == ConstantesPrincipale.TRANSACTION_ACTION_CREERALERTE:
            processus = "millegrilles_domaines_Principale:ProcessusCreerAlerte"
        elif domaine_transaction == ConstantesPrincipale.TRANSACTION_ACTION_CREEREMPREINTE:
            processus = "millegrilles_domaines_Principale:ProcessusCreerEmpreinte"
        elif domaine_transaction == ConstantesPrincipale.TRANSACTION_ACTION_AJOUTER_TOKEN:
            processus = "millegrilles_domaines_Principale:ProcessusAjouterToken"
        elif domaine_transaction == ConstantesPrincipale.TRANSACTION_ACTION_MAJ_PROFILUSAGER:
            processus = "millegrilles_domaines_Principale:ProcessusMajProfilUsager"
        elif domaine_transaction == ConstantesPrincipale.TRANSACTION_ACTION_MAJ_PROFILMILLEGRILLE:
            processus = "millegrilles_domaines_Principale:ProcessusMajProfilMilleGrille"
        elif domaine_transaction == ConstantesPrincipale.TRANSACTION_MAJ_MENU:
            processus = "millegrilles_domaines_Principale:ProcessusMajMenu"
        else:
            # Type de transaction inconnue, on lance une exception
            processus = super().identifier_processus(domaine_transaction)

        return processus

    def maj_profil_usager(self, fiche):
        operation = {
            '$set': fiche
        }
        documents = self.document_dao.get_collection(ConstantesPrincipale.COLLECTION_DOCUMENTS_NOM)
        resultat = documents.update_one(
            {Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPrincipale.LIBVAL_PROFIL_USAGER},
            operation
        )

        if resultat.matched_count < 1:
            raise ErreurMAJProcessus("Erreur MAJ processus %s, document inexistant" % self.__class__.__name__)

    def maj_profil_millegrille(self, fiche):
        operation = {
            '$set': fiche
        }
        documents = self.document_dao.get_collection(ConstantesPrincipale.COLLECTION_DOCUMENTS_NOM)
        resultat = documents.update_one(
            {Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPrincipale.LIBVAL_PROFIL_MILLEGRILLE},
            operation
        )

        if resultat.matched_count < 1:
            raise ErreurMAJProcessus("Erreur MAJ processus %s, document inexistant" % self.__class__.__name__)

    def upgrade_menu(self):
        domaines = ConstantesPrincipale.DOCUMENT_DOMAINES

        collection_principale = self.document_dao.get_collection(ConstantesPrincipale.COLLECTION_DOCUMENTS_NOM)
        filtre_menu = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPrincipale.LIBVAL_DOMAINES
        }
        document_domaines = collection_principale.find_one(filtre_menu)

        try:
            domaines_configures = list(document_domaines[ConstantesPrincipale.LIBELLE_DOMAINES].keys())
            domaines_disponibles = list(domaines[ConstantesPrincipale.LIBELLE_DOMAINES].keys())
        except TypeError:
            # Rien a faire
            return

        domaine_manquant = False
        for domaine in domaines_disponibles:
            if domaine not in domaines_configures:
                domaine_manquant = True

        if domaine_manquant:
            # Creer transaction pour remplacer le document
            domaine = ConstantesPrincipale.TRANSACTION_MAJ_MENU
            nouveau_doc = {
                ConstantesPrincipale.LIBELLE_DOMAINES: domaines[ConstantesPrincipale.LIBELLE_DOMAINES],
                ConstantesPrincipale.LIBELLE_MENU: domaines[ConstantesPrincipale.LIBELLE_MENU],
            }
            self.generateur_transactions.soumettre_transaction(nouveau_doc, domaine)

    def maj_menu(self, transaction):
        collection_principale = self.document_dao.get_collection(ConstantesPrincipale.COLLECTION_DOCUMENTS_NOM)
        filtre_menu = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPrincipale.LIBVAL_DOMAINES
        }
        set_ops = {
            ConstantesPrincipale.LIBELLE_DOMAINES: transaction[ConstantesPrincipale.LIBELLE_DOMAINES],
            ConstantesPrincipale.LIBELLE_MENU: transaction[ConstantesPrincipale.LIBELLE_MENU],
        }
        ops = {
            '$set': set_ops,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }

        collection_principale.update_one(filtre_menu, ops)

    def charger_documents(self, liste_libval: list):
        """
        Charge les documents demandes, filtre les cles et les retourne dans une collection indexee par _mg-libelle
        :param liste_libval:
        :return:
        """
        collection = self.get_collection()
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': liste_libval},
        }

        curseur = collection.find(filtre)
        docs = dict()
        for document in curseur:
            info = dict()
            for key, value in document.items():
                if not key.startswith('_'):
                    info[key] = value
            docs[document['_mg-libelle']] = info

        return docs

    @property
    def version_domaine(self):
        return 7


class TraitementMessagePrincipale(TraitementMessageDomaine):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire)

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)
        routing_key = method.routing_key

        if routing_key.split('.')[0:2] == ['processus', 'domaine']:
            # Chaining vers le gestionnaire de processus du domaine
            self._gestionnaire.traitement_evenements.traiter_message(ch, method, properties, body)

        elif evenement == Constantes.EVENEMENT_CEDULEUR:
            # Ceduleur, verifier si action requise
            self._gestionnaire.traiter_cedule(message_dict)
        elif evenement == Constantes.EVENEMENT_TRANSACTION_PERSISTEE:
            # Verifier quel processus demarrer. On match la valeur dans la routing key.
            routing_key = method.routing_key
            processus = self.gestionnaire.identifier_processus(routing_key)
            self._gestionnaire.demarrer_processus(processus, message_dict)

        else:
            # Type d'evenement inconnu, on lance une exception
            raise ValueError("Type d'evenement inconnu: %s" % str(evenement))


class ProcessusPrincipale(MGProcessusTransaction):

    def get_collection_transaction_nom(self):
        return ConstantesPrincipale.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesPrincipale.COLLECTION_PROCESSUS_NOM


class ProcessusFermerAlerte(ProcessusPrincipale):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction(ConstantesPrincipale.COLLECTION_TRANSACTIONS_NOM)

        ts_alerte = transaction['alerte']['ts']

        # Configurer MongoDB, inserer le document de configuration de reference s'il n'existe pas
        collection_domaine = self.document_dao.get_collection(ConstantesPrincipale.COLLECTION_DOCUMENTS_NOM)

        filtre = {Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPrincipale.LIBVAL_ALERTES}
        operation = {'$pull': {'alertes': {'ts': ts_alerte}}}
        resultat = collection_domaine.update(filtre, operation)

        if resultat['nModified'] != 1:
            raise ValueError("L'alerte n'a pas ete trouvee, elle ne peut pas etre fermee.")

        self.set_etape_suivante()  # Marque transaction comme traitee


class ProcessusCreerAlerte(ProcessusPrincipale):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction(ConstantesPrincipale.COLLECTION_TRANSACTIONS_NOM)

        if transaction.get('message') is None:
            raise ValueError("L'alerte doit avoir un element 'message'")

        if transaction.get('ts') is None:
            transaction['ts'] = int(datetime.datetime.utcnow().timestamp() * 1000)

        # Ajouter au document d'alerte
        collection_domaine = self.document_dao.get_collection(ConstantesPrincipale.COLLECTION_DOCUMENTS_NOM)

        filtre = {Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPrincipale.LIBVAL_ALERTES}
        operation = {'$push': {'alertes': transaction}}
        resultat = collection_domaine.update(filtre, operation)

        if resultat['nModified'] != 1:
            raise ValueError("L'alerte n'a pas ete ajoutee.")

        self.set_etape_suivante()  # Marque transaction comme traitee


class ProcessusCreerEmpreinte(ProcessusPrincipale):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction(ConstantesPrincipale.COLLECTION_TRANSACTIONS_NOM)

        if transaction.get('cle') is None:
            self.set_etape_suivante()  # On arrete le traitement
            return {'erreur': 'Cle manquante de la transaction', 'succes': False}

        # Verifier que la MilleGrille n'a pas deja d'empreinte
        documents = self.document_dao.get_collection(ConstantesPrincipale.COLLECTION_DOCUMENTS_NOM)
        profil = documents.find_one({Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPrincipale.LIBVAL_CLES})
        empreinte_absente = profil.get('empreinte_absente')
        if empreinte_absente is True:
            # Validation correcte. On passe a l'etape de sauvegarde
            self.set_etape_suivante('empreinte')
        else:
            self.set_etape_suivante()  # On arrete le traitement
            return {'erreur': 'La MilleGrille a deja une empreinte'}

    def empreinte(self):
        transaction = self.charger_transaction(ConstantesPrincipale.COLLECTION_TRANSACTIONS_NOM)

        operation = {
            '$unset': {'empreinte_absente': True},
            '$push': {'cles': transaction['cle']}
        }
        documents = self.document_dao.get_collection(ConstantesPrincipale.COLLECTION_DOCUMENTS_NOM)
        resultat = documents.update_one({Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPrincipale.LIBVAL_CLES}, operation)

        if resultat.modified_count != 1:
            raise ErreurMAJProcessus("Erreur MAJ processus: %s" % str(resultat))

        self.set_etape_suivante()  # Termine


class ProcessusAjouterToken(ProcessusPrincipale):

    def initiale(self):
        transaction = self.charger_transaction(ConstantesPrincipale.COLLECTION_TRANSACTIONS_NOM)

        if transaction.get('cle') is None:
            self.set_etape_suivante()  # On arrete le traitement
            return {'erreur': 'Cle manquante de la transaction', 'succes': False}

        operation = {
            '$unset': {'empreinte_absente': True},
            '$push': {'cles': transaction['cle']}
        }
        documents = self.document_dao.get_collection(ConstantesPrincipale.COLLECTION_DOCUMENTS_NOM)
        resultat = documents.update_one({Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPrincipale.LIBVAL_CLES}, operation)

        if resultat.modified_count != 1:
            raise ErreurMAJProcessus("Erreur MAJ processus: %s" % str(resultat))

        self.set_etape_suivante()  # Termine


class ProcessusMajFiches(ProcessusPrincipale):

    def _generer_transactions_fiches(self, transaction_fiche):
        """
        Genere 2 transactions pour Annaire - fiche privee et fiche publique
        :param transaction_fiche:
        :return:
        """
        self.generateur_transactions.soumettre_transaction(
            transaction_fiche, Constantes.ConstantesAnnuaire.TRANSACTION_MAJ_FICHEPRIVEE
        )

        self.generateur_transactions.soumettre_transaction(
            transaction_fiche, Constantes.ConstantesAnnuaire.TRANSACTION_MAJ_FICHEPUBLIQUE
        )


class ProcessusMajProfilUsager(ProcessusMajFiches):

    def initiale(self):
        transaction = self.charger_transaction(ConstantesPrincipale.COLLECTION_TRANSACTIONS_NOM)

        # Recuperer toutes les valeurs de la transaction et inserer dans le document
        fiche = ConstantesPrincipale.DOCUMENT_PROFIL_USAGER.copy()
        del fiche[Constantes.DOCUMENT_INFODOC_LIBELLE]

        for cle, valeur in transaction.items():
            if not cle.startswith('_') and cle not in [Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]:
                fiche[cle] = valeur

        # Mettre a jour le profile usager sous Principale
        self.controleur.gestionnaire.maj_profil_usager(fiche)

        # Creer transactions pour mettre a jour les fiches privees et publiques de l'annuaire.
        # Copier le contenu directement
        transaction_fiche = {
            Constantes.ConstantesAnnuaire.LIBELLE_DOC_USAGER: fiche
        }
        self._generer_transactions_fiches(transaction_fiche)

        self.set_etape_suivante()  # Termine


class ProcessusMajProfilMilleGrille(ProcessusMajFiches):

    def initiale(self):
        transaction = self.charger_transaction(ConstantesPrincipale.COLLECTION_TRANSACTIONS_NOM)

        fiche = {
            ConstantesPrincipale.LIBELLE_LANGUE_PRINCIPALE: transaction[ConstantesPrincipale.LIBELLE_LANGUE_PRINCIPALE],
            ConstantesPrincipale.LIBELLE_LANGUES_ADDITIONNELLES: transaction[ConstantesPrincipale.LIBELLE_LANGUES_ADDITIONNELLES],
        }

        # Verifier si on a plusieurs languages - si oui, les noms de MilleGrilles sont ramenes au niveau de base
        champs_multilingues = [
            ConstantesPrincipale.LIBELLE_NOM_MILLEGRILLE
        ]

        for champ in champs_multilingues:
            for key, value in transaction.items():
                if key.startswith(champ):
                    fiche[key] = value

        # Mettre a jour le profile usager sous Principale
        self.controleur.gestionnaire.maj_profil_millegrille(fiche)

        # Creer transactions pour mettre a jour les fiches privees et publiques de l'annuaire.
        # Copier le contenu directement
        self._generer_transactions_fiches(fiche)

        self.set_etape_suivante()  # Termine


class ProcessusMajMenu(ProcessusPrincipale):

    def initiale(self):
        transaction = self.transaction
        self.controleur.gestionnaire.maj_menu(transaction)

        self.set_etape_suivante()  # Termine

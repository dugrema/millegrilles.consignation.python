# Domaine de l'interface principale de l'usager. Ne peut pas etre deleguee.
from millegrilles import Constantes
from millegrilles.Domaines import GestionnaireDomaineStandard
from millegrilles.dao.MessageDAO import TraitementMessageDomaine
from millegrilles.MGProcessus import MGProcessusTransaction, ErreurMAJProcessus

import logging
import datetime


class ConstantesPrincipale:
    """ Constantes pour le domaine de l'interface principale """

    DOMAINE_NOM = 'millegrilles.domaines.Principale'
    COLLECTION_TRANSACTIONS_NOM = DOMAINE_NOM
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_TRANSACTIONS_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_TRANSACTIONS_NOM
    QUEUE_NOM = 'millegrilles.domaines.Principale'

    LIBVAL_CONFIGURATION = 'configuration'
    LIBVAL_PROFIL_USAGER = 'profil.usager'
    LIBVAL_ALERTES = 'alertes'
    LIBVAL_DOMAINES = 'domaines'
    LIBVAL_CLES = 'cles'

    TRANSACTION_ACTION_FERMERALERTE = '%s.fermerAlerte' % DOMAINE_NOM
    TRANSACTION_ACTION_CREERALERTE = '%s.creerAlerte' % DOMAINE_NOM
    TRANSACTION_ACTION_CREEREMPREINTE = '%s.creerEmpreinte' % DOMAINE_NOM
    TRANSACTION_ACTION_AJOUTER_TOKEN = '%s.ajouterToken' % DOMAINE_NOM

    DOCUMENT_ALERTES = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_ALERTES,
        'alertes': [
            {'message': "Interface principale initialisee", 'ts': int(datetime.datetime.utcnow().timestamp()*1000)}
        ]
    }

    DOCUMENT_CLES = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_CLES,
        'cles': [],
        'challenge_authentification': None,
        'empreinte_absente': True,
    }

    DOCUMENT_DOMAINES = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_DOMAINES,
        LIBVAL_DOMAINES: {
            'SenseursPassifs': {
                'rang': 5,
                'description': 'SenseursPassifs'
            },
            'GrosFichiers': {
                'rang': 3,
                'description': 'GrosFichiers'
            },
            'Principale': {
                'rang': 1,
                'description': 'Principale'
            },
            'Plume': {
                'rang': 1,
                'description': 'Plume'
            },
            'Pki': {
                'rang': 1,
                'description': 'Pki'
            },
            'Parametres': {
                'rang': 1,
                'description': 'Parametres'
            },
            'Annuaire': {
                'rang': 1,
                'description': 'Annuaire'
            }
        },
        "menu": [
            'Principale',
            'Annuaire',
            'GrosFichiers',
            'Plume',
            'SenseursPassifs',
            'Pki',
            'Parametres',
        ]
    }

    # Document par defaut pour la configuration de l'interface principale
    DOCUMENT_DEFAUT = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_CONFIGURATION,
    }

    DOCUMENT_PROFIL_USAGER = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_PROFIL_USAGER,
        'courriel': None,
        'courriel_alertes': [],
        'prenom': None,
        'nom': None,
        'uuid_usager': None,
    }


class GestionnairePrincipale(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._traitement_message = None
        self._traitement_requetes = None
        self.traiter_requete_noeud = None
        self._logger = logging.getLogger("%s.GestionnaireRapports" % __name__)

    def configurer(self):
        super().configurer()
        self._traitement_message = TraitementMessagePrincipale(self)

        self._traitement_requetes = TraitementMessageRequete(self)
        self.traiter_requete_noeud = self._traitement_requetes.callbackAvecAck  # Transfert methode

    def demarrer(self):
        super().demarrer()
        self.initialiser_document(ConstantesPrincipale.LIBVAL_CONFIGURATION, ConstantesPrincipale.DOCUMENT_DEFAUT)
        self.initialiser_document(ConstantesPrincipale.LIBVAL_ALERTES, ConstantesPrincipale.DOCUMENT_ALERTES)
        self.initialiser_document(ConstantesPrincipale.LIBVAL_PROFIL_USAGER, ConstantesPrincipale.DOCUMENT_PROFIL_USAGER)
        self.initialiser_document(ConstantesPrincipale.LIBVAL_DOMAINES, ConstantesPrincipale.DOCUMENT_DOMAINES)
        self.initialiser_document(ConstantesPrincipale.LIBVAL_CLES, ConstantesPrincipale.DOCUMENT_CLES)

    def traiter_cedule(self, evenement):
        pass

    def traiter_transaction(self, ch, method, properties, body):
        self._traitement_message.callbackAvecAck(ch, method, properties, body)

    def get_nom_collection(self):
        return ConstantesPrincipale.COLLECTION_DOCUMENTS_NOM

    def get_nom_queue(self):
        return ConstantesPrincipale.QUEUE_NOM

    def get_nom_queue_requetes_noeuds(self):
        return '%s.noeuds' % self.get_nom_queue()

    def get_nom_queue_requetes_inter(self):
        return '%s.inter' % self.get_nom_queue()

    def get_collection_transaction_nom(self):
        return ConstantesPrincipale.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesPrincipale.COLLECTION_PROCESSUS_NOM

    def traiter_requete_noeud(self, ch, method, properties, body):
        pass

    def traiter_requete_inter(self, ch, method, properties, body):
        pass

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
        else:
            # Type de transaction inconnue, on lance une exception
            processus = super().identifier_processus(domaine_transaction)

        return processus


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
            routing_key_sansprefixe = routing_key.replace(
                'destinataire.domaine.millegrilles.domaines.Principale.',
                ''
            )
            processus = self.gestionnaire.identifier_processus(routing_key_sansprefixe)
            self._gestionnaire.demarrer_processus(processus, message_dict)

        else:
            # Type d'evenement inconnu, on lance une exception
            raise ValueError("Type d'evenement inconnu: %s" % str(evenement))


class TraitementMessageRequete(TraitementMessageDomaine):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire)
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def traiter_message(self, ch, method, properties, body):
        routing_key = method.routing_key
        exchange = method.exchange
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        enveloppe_certificat = self.gestionnaire.verificateur_transaction.verifier(message_dict)
        self._logger.debug("Certificat: %s" % str(enveloppe_certificat))
        resultats = list()
        for requete in message_dict['requetes']:
            resultat = self.executer_requete(requete)
            resultats.append(resultat)

        # Genere message reponse
        self.transmettre_reponse(message_dict, resultats, properties.reply_to, properties.correlation_id)

    def executer_requete(self, requete):
        self._logger.debug("Requete: %s" % str(requete))
        collection = self.document_dao.get_collection(ConstantesPrincipale.COLLECTION_DOCUMENTS_NOM)
        filtre = requete.get('filtre')
        projection = requete.get('projection')
        sort_params = requete.get('sort')

        if projection is None:
            curseur = collection.find(filtre)
        else:
            curseur = collection.find(filtre, projection)

        if sort_params is not None:
            curseur.sort(sort_params)

        resultats = list()
        for resultat in curseur:
            resultats.append(resultat)

        self._logger.debug("Resultats: %s" % str(resultats))

        return resultats

    def transmettre_reponse(self, requete, resultats, replying_to, correlation_id=None):
        # enveloppe_val = generateur.soumettre_transaction(requete, 'millegrilles.domaines.Principale.creerAlerte')
        if correlation_id is None:
            correlation_id = requete[Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]

        message_resultat = {
            'resultats': resultats,
        }

        self.gestionnaire.generateur_transactions.transmettre_reponse(message_resultat, replying_to, correlation_id)


class ProcessusFermerAlerte(MGProcessusTransaction):

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

    def get_collection_transaction_nom(self):
        return ConstantesPrincipale.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesPrincipale.COLLECTION_PROCESSUS_NOM


class ProcessusCreerAlerte(MGProcessusTransaction):

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

    def get_collection_transaction_nom(self):
        return ConstantesPrincipale.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesPrincipale.COLLECTION_PROCESSUS_NOM


class ProcessusCreerEmpreinte(MGProcessusTransaction):

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

    def get_collection_transaction_nom(self):
        return ConstantesPrincipale.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesPrincipale.COLLECTION_PROCESSUS_NOM


class ProcessusAjouterToken(MGProcessusTransaction):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

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

    def get_collection_transaction_nom(self):
        return ConstantesPrincipale.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesPrincipale.COLLECTION_PROCESSUS_NOM

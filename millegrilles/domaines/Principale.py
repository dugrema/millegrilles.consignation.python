# Domaine de l'interface principale
from millegrilles import Constantes
from millegrilles.Domaines import GestionnaireDomaine
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.MGProcessus import MGProcessusTransaction

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

    TRANSACTION_ACTION_FERMERALERTE = 'fermerAlerte'
    TRANSACTION_ACTION_CREERALERTE = 'creerAlerte'

    DOCUMENT_ALERTES = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_ALERTES,
        'alertes': [
            {'message': "Interface principale initialisee", 'ts': int(datetime.datetime.utcnow().timestamp()*1000)}
        ]
    }

    # Document par defaut pour la configuration de l'interface principale
    DOCUMENT_DEFAUT = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_CONFIGURATION,
        'nom_millegrille': 'Sansnom',
        'adresse_url_base': 'sansnom.millegrilles.com',
        'domaines': {
            'SenseursPassifs': {
                'rang': 1,
                'description': 'SenseursPassifs'
            },
            'Notifications': {
                'rang': 2,
                'description': 'Notifications'
            },
            'WebPoll': {
                'rang': 3,
                'description': 'WebPoll'
            },
            'Rapports': {
                'rang': 4,
                'description': 'Rapports'
            },
            'Principale': {
                'rang': 5,
                'description': 'Principale'
            }
        }
    }

    DOCUMENT_PROFIL_USAGER = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_PROFIL_USAGER,
        'courriel': None,
        'courriel_alertes': [],
        'prenom': None,
        'nom': None,
        'cles': [],
        'challenge_authentification': None,
        'uuid_usager': None,
        'empreinte_absente': True,
    }


class GestionnairePrincipale(GestionnaireDomaine):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._traitement_message = None

        self._logger = logging.getLogger("%s.GestionnaireRapports" % __name__)

    def configurer(self):
        super().configurer()
        self._traitement_message = TraitementMessagePrincipale(self)

        nom_queue_domaine = self.get_nom_queue()

        # Configurer la Queue pour les rapports sur RabbitMQ
        self.message_dao.channel.queue_declare(
            queue=nom_queue_domaine,
            durable=True)

        self.message_dao.channel.queue_bind(
            exchange=self.configuration.exchange_middleware,
            queue=nom_queue_domaine,
            routing_key='destinataire.domaine.%s.#' % nom_queue_domaine
        )

        self.message_dao.channel.queue_bind(
            exchange=self.configuration.exchange_middleware,
            queue=nom_queue_domaine,
            routing_key='ceduleur.#'
        )

        self.initialiser_document(ConstantesPrincipale.LIBVAL_CONFIGURATION, ConstantesPrincipale.DOCUMENT_DEFAUT)
        self.initialiser_document(ConstantesPrincipale.LIBVAL_ALERTES, ConstantesPrincipale.DOCUMENT_ALERTES)
        self.initialiser_document(ConstantesPrincipale.LIBVAL_PROFIL_USAGER, ConstantesPrincipale.DOCUMENT_PROFIL_USAGER)

    def traiter_cedule(self, evenement):
        pass

    def traiter_transaction(self, ch, method, properties, body):
        self._traitement_message.callbackAvecAck(ch, method, properties, body)

    def get_nom_queue(self):
        return ConstantesPrincipale.QUEUE_NOM

    def get_collection_transaction_nom(self):
        return ConstantesPrincipale.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesPrincipale.COLLECTION_PROCESSUS_NOM

    def traiter_requete_noeud(self, ch, method, properties, body):
        pass

    def traiter_requete_inter(self, ch, method, properties, body):
        pass

    def initialiser_document(self, mg_libelle, doc_defaut):
        # Configurer MongoDB, inserer le document de configuration de reference s'il n'existe pas
        collection_domaine = self.document_dao.get_collection(ConstantesPrincipale.COLLECTION_DOCUMENTS_NOM)

        # Trouver le document de configuration
        document_configuration = collection_domaine.find_one(
            {Constantes.DOCUMENT_INFODOC_LIBELLE: mg_libelle}
        )
        if document_configuration is None:
            self._logger.info("On insere le document %s pour domaine Principale" % mg_libelle)

            # Preparation document de configuration pour le domaine
            configuration_initiale = doc_defaut.copy()
            maintenant = datetime.datetime.utcnow()
            configuration_initiale[Constantes.DOCUMENT_INFODOC_DATE_CREATION] = maintenant
            configuration_initiale[Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION] = maintenant

            collection_domaine.insert(configuration_initiale)
        else:
            self._logger.info("Document de %s pour principale: %s" % (mg_libelle, str(document_configuration)))

    def get_nom_domaine(self):
        return ConstantesPrincipale.DOMAINE_NOM


class TraitementMessagePrincipale(BaseCallback):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire.contexte)
        self._gestionnaire = gestionnaire

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
            if routing_key_sansprefixe == ConstantesPrincipale.TRANSACTION_ACTION_FERMERALERTE:
                processus = "millegrilles_domaines_Principale:ProcessusFermerAlerte"
                self._gestionnaire.demarrer_processus(processus, message_dict)
            elif routing_key_sansprefixe == ConstantesPrincipale.TRANSACTION_ACTION_CREERALERTE:
                processus = "millegrilles_domaines_Principale:ProcessusCreerAlerte"
                self._gestionnaire.demarrer_processus(processus, message_dict)
            else:
                # Type de transaction inconnue, on lance une exception
                raise ValueError("Type de transaction inconnue: routing: %s, message: %s" % (routing_key, evenement))
        else:
            # Type d'evenement inconnu, on lance une exception
            raise ValueError("Type d'evenement inconnu: %s" % str(evenement))


class ProcessusFermerAlerte(MGProcessusTransaction):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction(ConstantesPrincipale.COLLECTION_TRANSACTIONS_NOM)

        ts_alerte = transaction['alerte']['ts']

        # Configurer MongoDB, inserer le document de configuration de reference s'il n'existe pas
        collection_domaine = self.contexte.document_dao.get_collection(ConstantesPrincipale.COLLECTION_DOCUMENTS_NOM)

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
        collection_domaine = self.contexte.document_dao.get_collection(ConstantesPrincipale.COLLECTION_DOCUMENTS_NOM)

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

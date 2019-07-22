# Domaine de l'interface GrosFichiers
from millegrilles import Constantes
from millegrilles.Domaines import GestionnaireDomaine
from millegrilles.dao.DocumentDAO import MongoJSONEncoder
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles.MGProcessus import MGProcessusTransaction

import logging
import datetime


class ConstantesGrosFichiers:
    """ Constantes pour le domaine de GrosFichiers """

    DOMAINE_NOM = 'millegrilles.domaines.GrosFichiers'
    COLLECTION_TRANSACTIONS_NOM = DOMAINE_NOM
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_TRANSACTIONS_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_TRANSACTIONS_NOM
    QUEUE_NOM = 'millegrilles.domaines.GrosFichiers'

    LIBVAL_CONFIGURATION = 'configuration'

    TRANSACTION_NOUVELLEVERSION_METADATA = '%s.nouvelleVersion.metadata' % DOMAINE_NOM
    TRANSACTION_NOUVELLEVERSION_TRANSFERTCOMPLETE = '%s.nouvelleVersion.transfertComplete' % DOMAINE_NOM

    # Document par defaut pour la configuration de l'interface GrosFichiers
    DOCUMENT_DEFAUT = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_CONFIGURATION,
    }


class GestionnaireGrosFichiers(GestionnaireDomaine):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._traitement_middleware = None
        self._traitement_noeud = None
        self._logger = logging.getLogger("%s.GestionnaireRapports" % __name__)

    def configurer(self):
        super().configurer()

        self._traitement_middleware = TraitementMessageMiddleware(self)
        self._traitement_noeud = TraitementMessageNoeud(self)

        # Configurer la Queue pour les rapports sur RabbitMQ
        nom_queue_domaine = self.get_nom_queue()

        queues_config = [
            {
                'nom': self.get_nom_queue(),
                'routing': 'destinataire.domaine.millegrilles.domaines.GrosFichiers.#',
                'exchange': Constantes.DEFAUT_MQ_EXCHANGE_MIDDLEWARE
            },
            {
                'nom': self.get_nom_queue_requetes_noeuds(),
                'routing': 'requete.%s.#' % ConstantesGrosFichiers.DOMAINE_NOM,
                'exchange': Constantes.DEFAUT_MQ_EXCHANGE_NOEUDS
            },
            {
                'nom': self.get_nom_queue_requetes_inter(),
                'routing': 'requete.%s.#' % ConstantesGrosFichiers.DOMAINE_NOM,
                'exchange': Constantes.DEFAUT_MQ_EXCHANGE_INTER
            },
        ]

        channel = self.message_dao.channel
        for queue_config in queues_config:
            channel.queue_declare(
                queue=queue_config['nom'],
                durable=True)

            channel.queue_bind(
                exchange=queue_config['exchange'],
                queue=queue_config['nom'],
                routing_key=queue_config['routing']
            )

            # Si la Q existe deja, la purger. Le traitement du backlog est plus efficient via load du gestionnaire.
            channel.queue_purge(
                queue=queue_config['nom']
            )

        channel.queue_bind(
            exchange=self.configuration.exchange_middleware,
            queue=nom_queue_domaine,
            routing_key='ceduleur.#'
        )

        channel.queue_bind(
            exchange=self.configuration.exchange_middleware,
            queue=nom_queue_domaine,
            routing_key='processus.domaine.%s.#' % ConstantesGrosFichiers.DOMAINE_NOM
        )

        self.initialiser_document(ConstantesGrosFichiers.LIBVAL_CONFIGURATION, ConstantesGrosFichiers.DOCUMENT_DEFAUT)

    def traiter_cedule(self, evenement):
        pass

    def traiter_transaction(self, ch, method, properties, body):
        self._traitement_middleware.callbackAvecAck(ch, method, properties, body)

    def get_nom_queue(self):
        return ConstantesGrosFichiers.QUEUE_NOM

    def get_nom_queue_requetes_noeuds(self):
        return '%s.noeuds' % self.get_nom_queue()

    def get_nom_queue_requetes_inter(self):
        return '%s.inter' % self.get_nom_queue()

    def get_collection_transaction_nom(self):
        return ConstantesGrosFichiers.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesGrosFichiers.COLLECTION_PROCESSUS_NOM

    def traiter_requete_noeud(self, ch, method, properties, body):
        self._traitement_noeud.callbackAvecAck(ch, method, properties, body)

    def traiter_requete_inter(self, ch, method, properties, body):
        pass

    def initialiser_document(self, mg_libelle, doc_defaut):
        # Configurer MongoDB, inserer le document de configuration de reference s'il n'existe pas
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        # Trouver le document de configuration
        document_configuration = collection_domaine.find_one(
            {Constantes.DOCUMENT_INFODOC_LIBELLE: mg_libelle}
        )
        if document_configuration is None:
            self._logger.info("On insere le document %s pour domaine GrosFichiers" % mg_libelle)

            # Preparation document de configuration pour le domaine
            configuration_initiale = doc_defaut.copy()
            maintenant = datetime.datetime.utcnow()
            configuration_initiale[Constantes.DOCUMENT_INFODOC_DATE_CREATION] = maintenant
            configuration_initiale[Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION] = maintenant

            collection_domaine.insert(configuration_initiale)
        else:
            self._logger.info("Document de %s pour GrosFichiers: %s" % (mg_libelle, str(document_configuration)))

    def get_nom_domaine(self):
        return ConstantesGrosFichiers.DOMAINE_NOM


class TraitementMessageMiddleware(BaseCallback):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire.contexte)
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))
        self._gestionnaire = gestionnaire

    def traiter_message(self, ch, method, properties, body):
        routing_key = method.routing_key
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)

        if routing_key.split('.')[0:2] == ['processus', 'domaine']:
            # Chaining vers le gestionnaire de processus du domaine
            self._gestionnaire.traitement_evenements.traiter_message(ch, method, properties, body)

        elif evenement == Constantes.EVENEMENT_TRANSACTION_PERSISTEE:
            # Verifier quel processus demarrer.
            routing_key_sansprefixe = routing_key.replace(
                'destinataire.domaine.',
                ''
            )
            if routing_key_sansprefixe == ConstantesGrosFichiers.TRANSACTION_NOUVELLEVERSION_METADATA:
                processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionNouvelleVersionMetadata"
                self._gestionnaire.demarrer_processus(processus, message_dict)
            elif routing_key_sansprefixe == ConstantesGrosFichiers.TRANSACTION_NOUVELLEVERSION_TRANSFERTCOMPLETE:
                processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionNouvelleVersionTransfertComplete"
                self._gestionnaire.demarrer_processus(processus, message_dict)
            else:
                # Type de transaction inconnue, on lance une exception
                raise ValueError("Type de transaction inconnue: routing: %s, message: %s" % (routing_key, evenement))
        elif evenement == Constantes.EVENEMENT_CEDULEUR:
            self._gestionnaire.traiter_cedule(message_dict)
        else:
            raise ValueError("Type de transaction inconnue: routing: %s, message: %s" % (routing_key, evenement))


class TraitementMessageNoeud(BaseCallback):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire.contexte)
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))
        self._gestionnaire = gestionnaire
        self._generateur = GenerateurTransaction(gestionnaire.contexte, encodeur_json=MongoJSONEncoder)

    def traiter_message(self, ch, method, properties, body):
        routing_key = method.routing_key
        exchange = method.exchange
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)
        enveloppe_certificat = self.contexte.verificateur_transaction.verifier(message_dict)

        self._logger.debug("Certificat: %s" % str(enveloppe_certificat))
        resultats = list()
        for requete in message_dict['requetes']:
            resultat = self.executer_requete(requete)
            resultats.append(resultat)

        # Genere message reponse
        self.transmettre_reponse(message_dict, resultats, properties.reply_to, properties.correlation_id)

    def executer_requete(self, requete):
        self._logger.debug("Requete: %s" % str(requete))
        collection = self.contexte.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
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

        self._generateur.transmettre_reponse(message_resultat, replying_to, correlation_id)


# ******************* Processus *******************
class ProcessusTransactionNouvelleVersionMetadata(MGProcessusTransaction):
    """ Processus de d'ajout de nouveau fichier ou nouvelle version d'un fichier """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        """ Sauvegarder une nouvelle version d'un fichier """
        collection_transactions = self.contexte.document_dao.get_collection(
            ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        # Vierifier si le document de fichier existe deja
        document_fichier = None

        if document_fichier is None:
            self._logger.debug("Fichier est nouveau")
            self.set_etape_suivante(
                ProcessusTransactionNouvelleVersionMetadata.creer_nouveau_fichier.__name__)
        else:
            self._logger.debug("Fichier existe, on ajoute une version")
            self.set_etape_suivante(
                ProcessusTransactionNouvelleVersionMetadata.ajouter_version_fichier.__name__)

        return {'fuuid': 'allo mon fuuid'}

    def creer_nouveau_fichier(self):
        # Ajouter fichier

        self.set_etape_suivante(
            ProcessusTransactionNouvelleVersionMetadata.attendre_transaction_transfertcomplete.__name__,
            [self._get_token_attente(), 'token2 pour le fun'])

    def ajouter_version_fichier(self):
        # Ajouter fichier

        self.set_etape_suivante(
            ProcessusTransactionNouvelleVersionMetadata.attendre_transaction_transfertcomplete.__name__,
            [self._get_token_attente()])

    def attendre_transaction_transfertcomplete(self):
        pass

    def confirmer_hash(self):
        # Verifie que le hash des deux transactions (metadata, transfer complete) est le meme.
        self.set_etape_suivante()  # Processus termine

    def _get_token_attente(self):
        fuuid = self.parametres.get('fuuid')
        token_attente = '%s:%s' % (ConstantesGrosFichiers.TRANSACTION_NOUVELLEVERSION_TRANSFERTCOMPLETE, fuuid)
        return token_attente

    def get_collection_transaction_nom(self):
        return ConstantesGrosFichiers.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesGrosFichiers.COLLECTION_PROCESSUS_NOM


class ProcessusTransactionNouvelleVersionTransfertComplete(MGProcessusTransaction):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        """ Emet un evenement pour indiquer que le transfert complete est arrive """


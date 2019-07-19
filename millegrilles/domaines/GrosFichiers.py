# Domaine de l'interface principale
from millegrilles import Constantes
from millegrilles.Domaines import GestionnaireDomaine

import logging
import datetime


class ConstantesGrosFichiers:
    """ Constantes pour le domaine de l'interface principale """

    DOMAINE_NOM = 'millegrilles.domaines.GrosFichiers'
    COLLECTION_TRANSACTIONS_NOM = DOMAINE_NOM
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_TRANSACTIONS_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_TRANSACTIONS_NOM
    QUEUE_NOM = 'millegrilles.domaines.GrosFichiers'

    LIBVAL_CONFIGURATION = 'configuration'

    # Document par defaut pour la configuration de l'interface principale
    DOCUMENT_DEFAUT = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_CONFIGURATION,
    }


class GestionnairePrincipale(GestionnaireDomaine):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._traitement_message = None
        self._traitement_requetes = None
        self.traiter_requete_noeud = None
        self._logger = logging.getLogger("%s.GestionnaireRapports" % __name__)

    def configurer(self):
        super().configurer()

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
        self._traitement_message.callbackAvecAck(ch, method, properties, body)

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
        pass

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

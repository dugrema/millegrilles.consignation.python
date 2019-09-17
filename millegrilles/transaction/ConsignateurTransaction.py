# Programme principal pour transferer les nouvelles transactions vers MongoDB

from millegrilles import Constantes
from millegrilles.dao.MessageDAO import JSONHelper, BaseCallback
from millegrilles.util.UtilScriptLigneCommande import ModeleConfiguration

from millegrilles import Constantes
from bson.objectid import ObjectId
from threading import Thread, Event

import logging
import datetime
import traceback


class ConsignateurTransaction(ModeleConfiguration):

    def __init__(self):
        super().__init__()
        self.json_helper = JSONHelper()
        self.message_handler = None
        self.__stop_event = Event()
        self.__channel = None

        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def configurer_parser(self):
        super().configurer_parser()

    # Initialise les DAOs, connecte aux serveurs.
    def initialiser(self, init_document=True, init_message=True, connecter=True):
        super().initialiser(init_document, init_message, connecter)

        if self.args.debug:
            logging.getLogger('millegrilles.SecuritePKI').setLevel(logging.DEBUG)

        self.message_handler = ConsignateurTransactionCallback(self.contexte)

        self.handler_entretien = EntretienCollectionsDomaines(self.contexte)
        self.handler_entretien.entretien_initial()

        # Executer la configuration pour RabbitMQ
        self.contexte.message_dao.register_channel_listener(self)
        self.contexte.message_dao.register_channel_listener(self.handler_entretien)

        self.__logger.info("Configuration et connection completee")

    def on_channel_open(self, channel):
        channel.add_on_close_callback(self.__on_channel_close)
        self.__channel = channel

        self.contexte.message_dao.configurer_rabbitmq()
        queue_name = self.contexte.configuration.queue_nouvelles_transactions
        channel.basic_consume(self.message_handler.callbackAvecAck, queue=queue_name, no_ack=False)
        # self.contexte.message_dao.demarrer_lecture_nouvelles_transactions(self.message_handler.callbackAvecAck)

    def __on_channel_close(self, channel=None, code=None, reason=None):
        self.__channel = None

    def is_channel_open(self):
        return self.__channel is not None

    def executer(self):
        while not self.__stop_event.is_set():
            self.__stop_event.wait(3600)  # On fait juste attendre l'evenement de fermeture

    def deconnecter(self):
        self.__stop_event.set()
        self.contexte.document_dao.deconnecter()
        self.contexte.message_dao.deconnecter()
        self.__logger.info("Deconnexion completee")


class ConsignateurTransactionCallback(BaseCallback):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    # Methode pour recevoir le callback pour les nouvelles transactions.
    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        routing_key = method.routing_key
        exchange = method.exchange
        if routing_key == Constantes.TRANSACTION_ROUTING_NOUVELLE:
            self.traiter_nouvelle_transaction(message_dict, exchange, properties)
        elif exchange == self.contexte.configuration.exchange_middleware:
            if routing_key == Constantes.TRANSACTION_ROUTING_EVENEMENT:
                self.ajouter_evenement(message_dict)
            else:
                raise ValueError("Type d'operation inconnue: %s" % str(message_dict))
        else:
            raise ValueError("Type d'operation inconnue: %s" % str(message_dict))

    def traiter_nouvelle_transaction(self, message_dict, exchange, properties):
        try:
            id_document = self.sauvegarder_nouvelle_transaction(message_dict, exchange)
            entete = message_dict[Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION]
            uuid_transaction = entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
            domaine = entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]

            # Copier properties utiles
            properties_mq = {}
            if properties.reply_to is not None:
                properties_mq['reply_to'] = properties.reply_to
            if properties.correlation_id is not None:
                properties_mq['correlation_id'] = properties.correlation_id

            self.contexte.message_dao.transmettre_evenement_persistance(
                id_document, uuid_transaction, domaine, properties_mq)
        except Exception as e:
            uuid_transaction = 'NA'
            en_tete = message_dict.get(Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE)
            if en_tete is not None:
                uuid_transaction = en_tete.get(Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID)
            self._logger.exception(
                'Erreur traitement transaction uuid=%s, transferee a transaction.staging',
                uuid_transaction
            )
            message_traceback = traceback.format_exc()
            self.traiter_erreur_persistance(message_dict, e, message_traceback)
            raise e  # Relancer l'exception pour traitement independant

    def traiter_erreur_persistance(self, dict_message, error, message_traceback):
        document_staging = {
            'transaction': dict_message,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT: {
                Constantes.EVENEMENT_DOCUMENT_PERSISTE: [datetime.datetime.now(tz=datetime.timezone.utc)]
            },
            'traceback': message_traceback,
            'erreur': {
                'message': str(error),
                'classe': error.__class__.__name__
            }

        }
        collection_erreurs = self.contexte.document_dao.get_collection(Constantes.COLLECTION_TRANSACTION_STAGING)
        collection_erreurs.insert_one(document_staging)

    def ajouter_evenement(self, message_dict):
        id_transaction =  message_dict[Constantes.MONGO_DOC_ID]
        nom_collection = message_dict[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]
        evenement = message_dict[Constantes.EVENEMENT_MESSAGE_EVENEMENT]
        self.ajouter_evenement_transaction(id_transaction, nom_collection, evenement)

    def ajouter_evenement_transaction(self, id_transaction, nom_collection, evenement):
        collection_transactions = self.contexte.document_dao.get_collection(nom_collection)

        transaction_complete = False
        if evenement in [
            Constantes.EVENEMENT_TRANSACTION_TRAITEE,
            Constantes.EVENEMENT_TRANSACTION_ERREUR_TRAITEMENT,
            Constantes.EVENEMENT_TRANSACTION_ERREUR_EXPIREE
        ]:
            transaction_complete = True

        libelle_transaction_traitee = '%s.%s.%s' % (
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
            self.contexte.configuration.nom_millegrille,
            evenement
        )
        libelle_transaction_complete = '%s.%s' %  (
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
            Constantes.EVENEMENT_TRANSACTION_COMPLETE
        )
        selection = {Constantes.MONGO_DOC_ID: ObjectId(id_transaction)}
        operation = {
            '$set': {
                libelle_transaction_traitee: datetime.datetime.now(tz=datetime.timezone.utc),
                libelle_transaction_complete: transaction_complete,
            }
        }
        resultat = collection_transactions.update_one(selection, operation)

        if resultat.modified_count != 1:
            raise Exception("Erreur ajout evenement transaction, updated: %d, ObjectId: %s, collection: %s, evenement: %s" % (resultat.modified_count, str(id_transaction), nom_collection, evenement))

    def sauvegarder_nouvelle_transaction(self, enveloppe_transaction, exchange):

        domaine_transaction = enveloppe_transaction[
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE
        ][
            Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE
        ]
        nom_collection = ConsignateurTransactionCallback.identifier_collection_domaine(domaine_transaction)
        collection_transactions = self.contexte.document_dao.get_collection(nom_collection)

        # Verifier la signature de la transaction
        enveloppe_certificat = self.contexte.verificateur_transaction.verifier(enveloppe_transaction)
        enveloppe_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_ORIGINE] = \
            enveloppe_certificat.authority_key_identifier

        # Ajouter l'element evenements et l'evenement de persistance
        estampille = enveloppe_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]['estampille']
        # Changer estampille du format epoch en un format date et sauver l'evenement
        date_estampille = datetime.datetime.fromtimestamp(estampille)
        evenements = {
            Constantes.EVENEMENT_DOCUMENT_PERSISTE: datetime.datetime.now(tz=datetime.timezone.utc),
            Constantes.EVENEMENT_SIGNATURE_VERIFIEE: datetime.datetime.now(tz=datetime.timezone.utc)
        }
        enveloppe_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT] = {
            Constantes.EVENEMENT_TRANSACTION_ESTAMPILLE: date_estampille,
            Constantes.EVENEMENT_TRANSACTION_COMPLETE: False,
            self.contexte.configuration.nom_millegrille: evenements
        }

        resultat = collection_transactions.insert_one(enveloppe_transaction)
        doc_id = resultat.inserted_id

        return doc_id

    @staticmethod
    def identifier_collection_domaine(domaine):

        domaine_split = domaine.split('.')

        nom_collection = None
        if domaine_split[0] == 'millegrilles' and domaine_split[1] == 'domaines':
            nom_collection = '.'.join(domaine_split[0:3])

        return nom_collection


class EntretienCollectionsDomaines(BaseCallback):

    def __init__(self, contexte):
        super().__init__(contexte)

        self.__thread_entretien = None
        self.__channel = None

        self.__liste_domaines = [
            'millegrilles.domaines.GrosFichiers',
            'millegrilles.domaines.MaitreDesCles',
            'millegrilles.domaines.Parametres',
            'millegrilles.domaines.Plume',
            'millegrilles.domaines.Principale',
            'millegrilles.domaines.SenseursPassifs',
        ]

        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def entretien_initial(self):
        self.__thread_entretien = Thread(target=self._run_entretien_initial, name="Entretien")
        self.__thread_entretien.start()

    def _run_entretien_initial(self):
        self.__logger.info("Entretien initial transactions")
        self._setup_transaction()
        self._setup_index_domaines()
        self.__thread_entretien = None  # Cleanup thread termine
        self.__logger.info("FIN Entretien initial transactions")

    def _setup_transaction(self):
        # Creer index: _mg-libelle
        collection = self.contexte.document_dao.get_collection(Constantes.COLLECTION_TRANSACTION_STAGING)
        collection.create_index([
            (Constantes.DOCUMENT_INFODOC_LIBELLE, 1)
        ])
        # Index domaine, _mg-libelle
        collection.create_index([
            ('%s.%s' %
             (Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION, Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE),
             1),
            (Constantes.DOCUMENT_INFODOC_LIBELLE, 1)
        ])

    def _setup_index_domaines(self):
        nom_millegrille = self.contexte.configuration.nom_millegrille

        for nom_collection_transaction in self.__liste_domaines:
            collection = self.contexte.document_dao.get_collection(nom_collection_transaction)
            champ_complete = '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_TRANSACTION_COMPLETE)
            champ_persiste = '%s.%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, nom_millegrille, Constantes.EVENEMENT_DOCUMENT_PERSISTE)
            champ_traitee = '%s.%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, nom_millegrille, Constantes.EVENEMENT_TRANSACTION_TRAITEE)

            # en-tete.uuid-transaction
            collection.create_index([
                ('%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE, Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID), 1)
            ])

            # _evenements.estampille
            collection.create_index([
                ('%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_TRANSACTION_ESTAMPILLE), -1)
            ])

            # _evenements.NOM_MILLEGRILLE.transaction_traitee
            collection.create_index([
                (champ_complete, 1),
                (champ_traitee, 1)
            ])

            # _evenements.NOM_MILLEGRILLE.transaction_persistee
            collection.create_index([
                (champ_complete, 1),
                (champ_persiste, 1)
            ])

    def _nettoyer_transactions_expirees(self):
        """
        Marque les transactions trop vieilles comme expirees.
        :return:
        """
        self.__logger.info("Entretien transactions expirees")

        nom_millegrille = self.contexte.configuration.nom_millegrille
        delta_expiration = datetime.timedelta(hours=1)
        date_courante = datetime.datetime.now(tz=datetime.timezone.utc)
        date_expiration = date_courante - delta_expiration
        operations = {
            '$set': {
                '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_TRANSACTION_COMPLETE): True,
                '%s.%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, nom_millegrille,
                               Constantes.EVENEMENT_TRANSACTION_ERREUR_EXPIREE): date_courante,
            }
        }

        for nom_collection_transaction in self.__liste_domaines:
            filtre = {
                '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_TRANSACTION_COMPLETE): False,
                '%s.%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, nom_millegrille, Constantes.EVENEMENT_DOCUMENT_PERSISTE): {'$gt': date_expiration},
            }

            self.__logger.debug("Entretien collection %s: %s" % (nom_collection_transaction, filtre))

            collection_transaction = self.contexte.document_dao.get_collection(nom_collection_transaction)
            collection_transaction.update(filtre, operations)

        self.__thread_entretien = None  # Cleanup thread termine
        self.__logger.info("FIN Entretien transactions expirees")

    def traiter_message(self, ch, method, properties, body):
        # Pour l'instant on a juste les evenements ceduleur
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        routing_key = method.routing_key
        exchange = method.exchange
        indicateurs = message_dict['indicateurs']

        if 'heure' in indicateurs and self.__thread_entretien is None:
            self.__thread_entretien = Thread(target=self._nettoyer_transactions_expirees, name="Entretien")
            self.__thread_entretien.start()

    def on_channel_open(self, channel):
        channel.add_on_close_callback(self.__on_channel_close)
        self.__channel = channel

        self.contexte.message_dao.configurer_rabbitmq()
        queue_name = Constantes.DEFAUT_QUEUE_ENTRETIEN_TRANSACTIONS
        channel.basic_consume(self.callbackAvecAck, queue=queue_name, no_ack=False)
        # self.contexte.message_dao.demarrer_lecture_nouvelles_transactions(self.message_handler.callbackAvecAck)

    def __on_channel_close(self, channel=None, code=None, reason=None):
        self.__channel = None

    def is_channel_open(self):
        return self.__channel is not None

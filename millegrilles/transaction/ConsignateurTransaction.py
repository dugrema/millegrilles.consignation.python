# Programme principal pour transferer les nouvelles transactions vers MongoDB

from millegrilles.dao.MessageDAO import JSONHelper, BaseCallback, CertificatInconnu
from millegrilles.util.UtilScriptLigneCommande import ModeleConfiguration

from millegrilles import Constantes
from bson.objectid import ObjectId
from threading import Thread, Event

import logging
import datetime
import traceback
import psutil


class ConsignateurTransaction(ModeleConfiguration):

    def __init__(self):
        super().__init__()
        self.json_helper = JSONHelper()
        self.message_handler = None
        self.handler_entretien = None
        self.evenements_handler = None
        self.__stop_event = Event()
        self.__init_config_event = Event()
        self.__channel = None
        self.__queue_name = None

        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def configurer_parser(self):
        super().configurer_parser()

    # Initialise les DAOs, connecte aux serveurs.
    def initialiser(self, init_document=True, init_message=True, connecter=True):
        super().initialiser(init_document, init_message, connecter)

        if self.args.debug:
            logging.getLogger('millegrilles.SecuritePKI').setLevel(logging.DEBUG)

        self.contexte.message_dao.register_channel_listener(self)

        # Executer la configuration pour RabbitMQ
        self.contexte.message_dao.configurer_rabbitmq()  # Possede un timer pour attendre le channel dao

        self.__init_config_event.wait(30)
        self.handler_entretien = EntretienCollectionsDomaines(self.contexte)
        self.handler_entretien.entretien_initial()
        self.message_handler = ConsignateurTransactionCallback(self.contexte)
        self.evenements_handler = EvenementTransactionCallback(self.contexte)

        queue_name = self.contexte.configuration.queue_nouvelles_transactions
        self.__channel.basic_consume(self.message_handler.callbackAvecAck, queue=queue_name, no_ack=False)

        evenements_queue_name = self.contexte.configuration.queue_evenements_transactions
        self.__channel.basic_consume(self.evenements_handler.callbackAvecAck, queue=evenements_queue_name, no_ack=False)

        self.contexte.message_dao.register_channel_listener(self.handler_entretien)

        self.__logger.info("Configuration et connection completee")

    def on_channel_open(self, channel):
        channel.add_on_close_callback(self.__on_channel_close)
        channel.basic_qos(prefetch_count=5)
        self.__channel = channel
        self.__init_config_event.set()

    def __on_channel_close(self, channel=None, code=None, reason=None):
        self.__channel = None

    def is_channel_open(self):
        return self.__channel is not None

    def executer(self):
        while not self.__stop_event.is_set():
            try:
                self.entretien()
            except Exception as e:
                self.__logger.exception("Erreur entretien")
            self.__stop_event.wait(30)

    def entretien(self):
        if not self.is_channel_open or not self.handler_entretien.is_channel_open:
            self.__logger.error("Un canal du consignateur de transactions est ferme")
            self.contexte.message_dao.enter_error_state()

    def deconnecter(self):
        self.__stop_event.set()
        self.contexte.document_dao.deconnecter()
        self.contexte.message_dao.deconnecter()
        self.__logger.info("Deconnexion completee")


class ConsignateurTransactionCallback(BaseCallback):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))
        self.__compteur = 0

    # Methode pour recevoir le callback pour les nouvelles transactions.
    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        routing_key = method.routing_key
        exchange = method.exchange
        if routing_key == Constantes.TRANSACTION_ROUTING_NOUVELLE:
            try:
                self.__compteur = self.__compteur + 1
                self._logger.info("Nouvelle transaction %d: %s" % (self.__compteur, str(message_dict['en-tete']['domaine'])))
                self.traiter_nouvelle_transaction(message_dict, exchange, properties)
            except Exception as e:
                self._logger.exception("Erreur traitement transaction")
        else:
            raise ValueError("Type d'operation inconnue: %s" % str(message_dict))

    def traiter_nouvelle_transaction(self, message_dict, exchange, properties):
        try:
            id_document, signature_valide = self.sauvegarder_nouvelle_transaction(message_dict, exchange)

            if signature_valide:
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

    def sauvegarder_nouvelle_transaction(self, enveloppe_transaction, exchange):

        domaine_transaction = enveloppe_transaction[
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE
        ][
            Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE
        ]
        nom_collection = ConsignateurTransactionCallback.identifier_collection_domaine(domaine_transaction)
        collection_transactions = self.contexte.document_dao.get_collection(nom_collection)

        # Verifier la signature de la transaction (pas fatal si echec, on va reessayer plus tard)
        signature_valide = False
        entete = enveloppe_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
        try:
            enveloppe_certificat = self.contexte.verificateur_transaction.verifier(enveloppe_transaction)
            enveloppe_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_ORIGINE] = \
                enveloppe_certificat.authority_key_identifier
            signature_valide = True
        except CertificatInconnu:
            fingerprint = entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_CERTIFICAT]
            self._logger.warning(
                "Signature transaction incorrect ou certificat manquant. fingerprint: %s, uuid-transaction: %s" % (
                    fingerprint, entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
                )
            )
            # Emettre demande pour le certificat manquant
            self.contexte.message_dao.transmettre_demande_certificat(fingerprint)

        # Ajouter l'element evenements et l'evenement de persistance
        estampille = enveloppe_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]['estampille']
        # Changer estampille du format epoch en un format date et sauver l'evenement
        date_estampille = datetime.datetime.fromtimestamp(estampille)
        evenements = {
            Constantes.EVENEMENT_DOCUMENT_PERSISTE: datetime.datetime.now(tz=datetime.timezone.utc),
        }
        if signature_valide:
            evenements[Constantes.EVENEMENT_SIGNATURE_VERIFIEE] = datetime.datetime.now(tz=datetime.timezone.utc)

        enveloppe_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT] = {
            Constantes.EVENEMENT_TRANSACTION_ESTAMPILLE: date_estampille,
            Constantes.EVENEMENT_TRANSACTION_COMPLETE: False,
            self.contexte.configuration.idmg: evenements
        }

        resultat = collection_transactions.insert_one(enveloppe_transaction)
        doc_id = resultat.inserted_id

        return doc_id, signature_valide

    @staticmethod
    def identifier_collection_domaine(domaine):

        domaine_split = domaine.split('.')

        nom_collection = None
        if domaine_split[0] == 'millegrilles' and domaine_split[1] == 'domaines':
            nom_collection = '.'.join(domaine_split[0:3])

        return nom_collection


class EvenementTransactionCallback(BaseCallback):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    # Methode pour recevoir le callback pour les nouvelles transactions.
    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        routing_key = method.routing_key
        exchange = method.exchange
        if exchange == self.contexte.configuration.exchange_middleware:
            if routing_key == Constantes.TRANSACTION_ROUTING_EVENEMENT:
                self.ajouter_evenement(message_dict)
            else:
                raise ValueError("Type d'operation inconnue: %s" % str(message_dict))
        else:
            raise ValueError("Type d'operation inconnue: %s" % str(message_dict))

    def ajouter_evenement(self, message_dict):
        id_transaction = message_dict[Constantes.MONGO_DOC_ID]
        nom_collection = message_dict[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]
        evenement = message_dict[Constantes.EVENEMENT_MESSAGE_EVENEMENT]
        self.ajouter_evenement_transaction(id_transaction, nom_collection, evenement)

    def ajouter_evenement_transaction(self, id_transaction, nom_collection, evenement):
        collection_transactions = self.contexte.document_dao.get_collection(nom_collection)

        transaction_complete = False
        if evenement in [
            Constantes.EVENEMENT_TRANSACTION_TRAITEE,
            Constantes.EVENEMENT_TRANSACTION_ERREUR_TRAITEMENT,
            Constantes.EVENEMENT_TRANSACTION_ERREUR_EXPIREE,
            Constantes.EVENEMENT_TRANSACTION_ERREUR_RESOUMISSION,
        ]:
            transaction_complete = True

        libelle_transaction_traitee = '%s.%s.%s' % (
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
            self.contexte.configuration.idmg,
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
        self.__throttle_event = Event()

        self.__liste_domaines = [
            'millegrilles.domaines.GrosFichiers',
            'millegrilles.domaines.MaitreDesCles',
            'millegrilles.domaines.Parametres',
            'millegrilles.domaines.Plume',
            'millegrilles.domaines.Principale',
            'millegrilles.domaines.SenseursPassifs',
            'millegrilles.domaines.Pki',
            'millegrilles.domaines.Taches',
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
        collection.create_index(
            [
                (Constantes.DOCUMENT_INFODOC_LIBELLE, 1)
            ],
            name='mg-libelle'
        )
        # Index domaine, _mg-libelle
        collection.create_index(
            [
                ('%s.%s' %
                 (Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION, Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE),
                 1),
                (Constantes.DOCUMENT_INFODOC_LIBELLE, 1)
            ],
            name='domaine-libelle'
        )

    def _setup_index_domaines(self):
        nom_millegrille = self.contexte.configuration.idmg

        for nom_collection_transaction in self.__liste_domaines:
            try:
                collection = self.contexte.document_dao.get_collection(nom_collection_transaction)
                champ_complete = '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_TRANSACTION_COMPLETE)
                champ_persiste = '%s.%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, nom_millegrille, Constantes.EVENEMENT_DOCUMENT_PERSISTE)
                champ_traitee = '%s.%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, nom_millegrille, Constantes.EVENEMENT_TRANSACTION_TRAITEE)

                # en-tete.uuid-transaction
                collection.create_index(
                    [
                        ('%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE, Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID), 1)
                    ],
                    name='uuid_transaction'
                )

                # _evenements.estampille
                collection.create_index(
                    [
                        ('%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_TRANSACTION_ESTAMPILLE), -1)
                    ],
                    name='estampille'
                )

                # _evenements.NOM_MILLEGRILLE.transaction_traitee
                collection.create_index(
                    [
                        (champ_complete, 1),
                        (champ_traitee, 1)
                    ],
                    name='transaction_traitee'
                )

                # _evenements.NOM_MILLEGRILLE.transaction_persistee
                collection.create_index(
                    [
                        (champ_complete, 1),
                        (champ_persiste, 1)
                    ],
                    name='transaction_persistee'
                )

            except Exception:
                self.__logger.exception("Erreur creation index de transactions dans %s" % nom_collection_transaction)

    def _verifier_signature(self):
        delta_verif = datetime.timedelta(minutes=5)
        date_courante = datetime.datetime.now(tz=datetime.timezone.utc)
        date_verif = date_courante - delta_verif

        nom_millegrille = self.configuration.idmg

        label_date_resoumise = '%s.%s.%s' % (
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
            nom_millegrille,
            Constantes.EVENEMENT_TRANSACTION_DATE_RESOUMISE
        )

        verificateur_transaction = self.contexte.verificateur_transaction
        for nom_collection_transaction in self.__liste_domaines:
            filtre = {
                '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_TRANSACTION_COMPLETE): False,
                '%s.%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, nom_millegrille, Constantes.EVENEMENT_DOCUMENT_PERSISTE): {'$lt': date_verif},
            }
            collection_transaction = self.contexte.document_dao.get_collection(nom_collection_transaction)
            curseur_transactions = collection_transaction.find(filtre).limit(2000)
            for doc_transaction in curseur_transactions:
                try:
                    transaction_id = doc_transaction['_id']
                    entete = doc_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
                    uuid_transaction = entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
                    evenements_transaction = doc_transaction.get(Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT)

                    self.__logger.info("Resoumission transaction non terminee: %s" % uuid_transaction)
                    try:
                        verificateur_transaction.verifier(doc_transaction)

                        compteur_resoumission = 0
                        if evenements_transaction is not None:
                            evenements_millegrille = evenements_transaction.get(nom_millegrille)
                            if evenements_millegrille is not None:
                                resoumissions = evenements_millegrille.get(Constantes.EVENEMENT_TRANSACTION_COMPTE_RESOUMISE)
                                if resoumissions is not None:
                                    compteur_resoumission = resoumissions

                        if compteur_resoumission < 3:
                            compteur_resoumission = compteur_resoumission + 1

                            # Signature valide, on trigger le traitement de persistance
                            label_signature = '%s.%s.%s' % (
                                Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
                                nom_millegrille,
                                Constantes.EVENEMENT_SIGNATURE_VERIFIEE
                            )
                            label_compte_resoumise = '%s.%s.%s' % (
                                Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
                                nom_millegrille,
                                Constantes.EVENEMENT_TRANSACTION_COMPTE_RESOUMISE
                            )
                            collection_transaction.update_one(
                                {'_id': transaction_id},
                                {'$set': {
                                    label_signature: date_courante,
                                    label_compte_resoumise: compteur_resoumission,
                                    label_date_resoumise: datetime.datetime.utcnow(),
                                }}
                            )

                            domaine = entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]

                            # Copier properties utiles
                            self.contexte.message_dao.transmettre_evenement_persistance(
                                str(transaction_id), uuid_transaction, domaine, {})
                        else:
                            # La transaction a ete re-soumise trop de fois, on la met en erreur
                            self.__logger.error("Marquer transaction comme resoumise trop de fois %s" % str(transaction_id))
                            libelle_transaction_traitee = '%s.%s.%s' % (
                                Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
                                self.contexte.configuration.idmg,
                                Constantes.EVENEMENT_TRANSACTION_ERREUR_RESOUMISSION
                            )
                            libelle_transaction_complete = '%s.%s' % (
                                Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
                                Constantes.EVENEMENT_TRANSACTION_COMPLETE
                            )
                            selection = {Constantes.MONGO_DOC_ID: transaction_id}
                            operation = {
                                '$set': {
                                    libelle_transaction_traitee: datetime.datetime.now(tz=datetime.timezone.utc),
                                    libelle_transaction_complete: True,
                                }
                            }
                            collection_transaction.update_one(selection, operation)

                    except ValueError:
                        fingerprint = entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_CERTIFICAT]
                        self.__logger.info(
                            "Signature transaction incorrect ou certificat manquant. fingerprint: %s, uuid-transaction: %s" % (
                                fingerprint, uuid_transaction
                            )
                        )
                        # Emettre demande pour le certificat manquant
                        self.contexte.message_dao.transmettre_demande_certificat(fingerprint)

                    self.__throttle_event.wait(0.01)

                except CertificatInconnu as ci:
                    fingerprint = ci.fingerprint
                    self.__logger.warning(
                        "Resoumission, certificat manquant. On le redemande. Fingerprint: %s" % fingerprint)
                    # Emettre demande pour le certificat manquant
                    self.contexte.message_dao.transmettre_demande_certificat(fingerprint)

                except Exception as e:
                    self.__logger.error("Erreur resoumission transaction (collection %s): %s" % (nom_collection_transaction, str(e)))

                finally:
                    self.__thread_entretien = None

    def _nettoyer_transactions_expirees(self):
        """
        Marque les transactions trop vieilles comme expirees.
        :return:
        """
        self.__logger.info("Entretien transactions expirees")

        nom_millegrille = self.contexte.configuration.idmg
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

        cpu_load = psutil.getloadavg()[0]
        if cpu_load < 3.0:
            if self.__thread_entretien is None or not self.__thread_entretien.is_alive():
                if 'heure' in indicateurs:
                    self.__thread_entretien = Thread(target=self._nettoyer_transactions_expirees, name="Entretien")
                    self.__thread_entretien.start()
                else:
                    self.__thread_entretien = Thread(target=self._verifier_signature, name="Entretien")
                    self.__thread_entretien.start()
        else:
            self.__logger.warning("CPU load %s > 2.5, pas d'entetien de transactions" % cpu_load)

    def on_channel_open(self, channel):
        channel.add_on_close_callback(self.__on_channel_close)
        self.__channel = channel
        channel.basic_qos(prefetch_count=50)
        queue_name = Constantes.DEFAUT_QUEUE_ENTRETIEN_TRANSACTIONS
        channel.basic_consume(self.callbackAvecAck, queue=queue_name, no_ack=False)

    def __on_channel_close(self, channel=None, code=None, reason=None):
        self.__channel = None

    def is_channel_open(self):
        return self.__channel is not None

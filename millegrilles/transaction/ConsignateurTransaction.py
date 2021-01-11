# Programme principal pour transferer les nouvelles transactions vers MongoDB
import logging
import datetime
import traceback
import psutil
import gc
import json

from bson.objectid import ObjectId
from threading import Thread, Event
from pymongo.errors import DuplicateKeyError

from millegrilles.dao.MessageDAO import JSONHelper, BaseCallback, CertificatInconnu
from millegrilles.util.UtilScriptLigneCommande import ModeleConfiguration
from millegrilles import Constantes
from millegrilles.util.Ceduleur import CeduleurMilleGrilles
from millegrilles.Domaines import GestionnaireDomaine
from millegrilles.SecuritePKI import AutorisationConditionnelleDomaine


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

        self.__thread_ceduleur = None

        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def configurer_parser(self):
        super().configurer_parser()

    # Initialise les DAOs, connecte aux serveurs.
    def initialiser(self, init_document=True, init_message=True, connecter=True):
        super().initialiser(init_document, init_message, connecter)
        # self.initialiser_2()

    def initialiser_2(self, contexte=None):
        super().initialiser_2(contexte)

        if self.args.debug:
            logging.getLogger('millegrilles.SecuritePKI').setLevel(logging.DEBUG)

        self.contexte.message_dao.register_channel_listener(self)

        # Executer la configuration pour RabbitMQ
        self.contexte.message_dao.configurer_rabbitmq()  # Possede un timer pour attendre le channel dao

        self.__init_config_event.wait(30)
        self.message_handler = ConsignateurTransactionCallback(self.contexte)
        self.evenements_handler = EvenementTransactionCallback(self.contexte)
        self.handler_entretien = EntretienCollectionsDomaines(self, self.contexte)
        self.handler_entretien.entretien_initial()

        self.contexte.message_dao.register_channel_listener(self.message_handler)
        self.contexte.message_dao.register_channel_listener(self.evenements_handler)
        self.contexte.message_dao.register_channel_listener(self.handler_entretien)

        # Demarrer thread ceduleur
        if not self.__thread_ceduleur:
            ceduleur = CeduleurMilleGrilles(self.contexte, self.__stop_event)
            self.__thread_ceduleur = Thread(target=ceduleur.executer, name='ceduleur')
            self.__thread_ceduleur.start()
        else:
            self.__logger.warning("Ceduleur deja demarre, initialiser_2 execute plus d'une fois")

        self.__logger.info("Configuration et connection completee")

    def on_channel_open(self, channel):
        super().on_channel_open(channel)
        channel.add_on_close_callback(self.__on_channel_close)
        channel.basic_qos(prefetch_count=5)
        self.__channel = channel
        self.__init_config_event.set()

    def __on_channel_close(self, channel=None, code=None, reason=None):
        self.__channel = None

        try:
            self.contexte.message_dao.enter_error_state()
        except Exception:
            self.__logger.exception("Erreur activation erreur state, on ferme")
            self.__stop_event.set()

    def is_channel_open(self):
        return self.__channel is not None and not self.__channel.is_closed

    def executer(self):
        while not self.__stop_event.is_set():
            try:
                self.entretien()
                gc.collect()
            except Exception as e:
                self.__logger.exception("Erreur entretien")
            self.__stop_event.wait(30)

    def entretien(self):
        if not self.is_channel_open or not self.handler_entretien.is_channel_open:
            self.__logger.error("Un canal du consignateur de transactions est ferme")
            self.__channel = None
            self.contexte.message_dao.enter_error_state()

    def deconnecter(self):
        self.__stop_event.set()
        # self.contexte.document_dao.deconnecter()
        self.contexte.message_dao.deconnecter()
        self.__logger.info("Deconnexion completee")


class ConsignateurTransactionCallback(BaseCallback):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))
        self.__compteur = 0
        self.__channel = None

    # Methode pour recevoir le callback pour les nouvelles transactions.
    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        routing_key = method.routing_key
        routing_key_split = routing_key.split('.')
        exchange = method.exchange
        if routing_key_split[0] == 'transaction':
            try:
                self.__compteur = self.__compteur + 1
                self._logger.debug("Nouvelle transaction %d: %s" % (self.__compteur, str(message_dict['en-tete']['domaine'])))
                self.traiter_nouvelle_transaction(message_dict, exchange, properties)
            except Exception as e:
                self._logger.exception("Erreur traitement transaction")
        elif routing_key_split[0] == 'commande' and routing_key_split[-1] == 'restaurerTransaction':
            try:
                self._logger.debug(
                    "Transaction restauree %s" % str(message_dict['en-tete']['domaine']))
                self.traiter_restauration_transaction(message_dict)
            except Exception as e:
                self._logger.exception("Erreur traitement transaction")
        else:
            raise ValueError("Type d'operation inconnue %s: %s" % (routing_key, str(message_dict)))

    def traiter_nouvelle_transaction(self, message_dict, exchange, properties):
        try:
            id_document, signature_valide = self.sauvegarder_nouvelle_transaction(message_dict, exchange)

            if signature_valide:
                entete = message_dict[Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION]
                uuid_transaction = entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
                domaine = entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]
                idmg_destination = entete.get(Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG_DESTINATION)

                properties_mq = {}
                if idmg_destination is not None and idmg_destination != self.configuration.idmg:
                    # La transaction est pour un tiers, relayer la transaction vers le tiers
                    # La reponse doit provenir de la MilleGrille destination
                    self._logger.debug("Relai de la transaction %s vers %s" % (uuid_transaction, idmg_destination))
                    self.contexte.generateur_transactions.relayer_transaction_vers_tiers(
                        message_dict, reply_to=properties.reply_to, correlation_id=properties.correlation_id)
                else:
                    # La transaction est locale
                    if properties.reply_to is not None:
                        properties_mq['reply_to'] = properties.reply_to
                    if properties.correlation_id is not None:
                        properties_mq['correlation_id'] = properties.correlation_id

                self.contexte.generateur_transactions.transmettre_evenement_persistance(
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

    def traiter_restauration_transaction(self, message_dict):
        try:
            # Retirer le _id - doit etre generer dans MongoDB.
            if message_dict.get('_id'):
                del message_dict['_id']

            self.sauvegarder_transaction_restauree(message_dict)
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
        try:
            collection_erreurs.insert_one(document_staging)
        except:
            self._logger.exception("Erreur sauvegarde transaction invalide")
            try:
                document_staging['transaction'] = json.dumps(dict_message, indent=2)
            except:
                document_staging['transaction'] = 'erreur sauvegarde'
            document_staging[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE] = dict_message.get(Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE)
            collection_erreurs.insert_one(document_staging)

    def sauvegarder_nouvelle_transaction(self, enveloppe_transaction, exchange):

        domaine_transaction = enveloppe_transaction[
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE
        ][
            Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE
        ]
        nom_collection = GestionnaireDomaine.identifier_collection_domaine(domaine_transaction)
        collection_transactions = self.contexte.document_dao.get_collection(nom_collection)

        # Verifier la signature de la transaction (pas fatal si echec, on va reessayer plus tard)
        signature_valide = False
        entete = enveloppe_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
        try:
            # enveloppe_certificat = self.contexte.verificateur_transaction.verifier(enveloppe_transaction)
            enveloppe_certificat = self.contexte.validateur_message.verifier(
                enveloppe_transaction, utiliser_date_message=True, utiliser_idmg_message=True)
            enveloppe_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_ORIGINE] = \
                enveloppe_certificat.authority_key_identifier
            signature_valide = True
        except CertificatInconnu:
            fingerprint = entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_FINGERPRINT_CERTIFICAT]
            self._logger.warning(
                "Signature transaction incorrect ou certificat manquant. fingerprint: %s, uuid-transaction: %s" % (
                    fingerprint, entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
                )
            )
            # # Emettre demande pour le certificat manquant
            # self.contexte.message_dao.transmettre_demande_certificat(fingerprint)
        # except AutorisationConditionnelleDomaine as acd:
        #     if domaine_transaction in acd.domaines:
        #         signature_valide = True
        #     else:
        #         # Pas autorise
        #         raise acd

        chaine_certificat = enveloppe_transaction.get(Constantes.TRANSACTION_MESSAGE_LIBELLE_CERTIFICAT_INCLUS)
        try:
            del enveloppe_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_CERTIFICAT_INCLUS]
        except KeyError:
            pass

        if chaine_certificat:
            self.__emettre_chaine(chaine_certificat)

        # Ajouter l'element evenements et l'evenement de persistance
        estampille = enveloppe_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]['estampille']
        # Changer estampille du format epoch en un format date et sauver l'evenement
        date_estampille = datetime.datetime.fromtimestamp(estampille)
        evenements = {
            Constantes.EVENEMENT_DOCUMENT_PERSISTE: datetime.datetime.now(tz=datetime.timezone.utc),
            Constantes.EVENEMENT_TRANSACTION_ESTAMPILLE: date_estampille,
            Constantes.EVENEMENT_TRANSACTION_COMPLETE: False,
            Constantes.EVENEMENT_TRANSACTION_BACKUP_FLAG: False,
        }
        if signature_valide:
            evenements[Constantes.EVENEMENT_SIGNATURE_VERIFIEE] = datetime.datetime.now(tz=datetime.timezone.utc)

        enveloppe_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT] = evenements

        try:
            resultat = collection_transactions.insert_one(enveloppe_transaction)
            doc_id = resultat.inserted_id
        except DuplicateKeyError as dke:
            # Verifier si la transaction a ete traite correctement - relancer le trigger de traitement sinon
            uuid_transaction = enveloppe_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
            filtre = {Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE + '.' + Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: uuid_transaction}
            doc_existant = collection_transactions.find_one(filtre)
            date_traitement = doc_existant['_evenements'].get('transaction_traitee')
            if date_traitement is None:
                # La transaction n'a pas ete traitee avec succes, on relance le trigger
                doc_id = doc_existant['_id']
                collection_transactions.update_one(
                    {'_id': doc_id},
                    {'$set': {'_evenements.transaction_complete': False}}
                )
            else:
                # Transaction deja traitee avec succes, on empeche l'execution subsequente
                raise dke

        return doc_id, signature_valide

    def __emettre_chaine(self, certs: list):
        self.contexte.signateur_transactions.emettre_certificat(certs)

    def sauvegarder_transaction_restauree(self, enveloppe_transaction):

        entete = enveloppe_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
        domaine_transaction = entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]

        nom_collection = GestionnaireDomaine.identifier_collection_domaine(domaine_transaction)
        collection_transactions = self.contexte.document_dao.get_collection(nom_collection)

        # Verifier la signature de la transaction (pas fatal si echec, on va reessayer plus tard)
        entete = enveloppe_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
        try:
            enveloppe_certificat = self.contexte.verificateur_transaction.verifier(enveloppe_transaction)
            enveloppe_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_ORIGINE] = \
                enveloppe_certificat.authority_key_identifier
            signature_valide = True
        except CertificatInconnu as ci:
            fingerprint = entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_CERTIFICAT]
            self._logger.warning(
                "Signature transaction incorrect ou certificat manquant. fingerprint: %s, uuid-transaction: %s" % (
                    fingerprint, entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
                )
            )
            # Emettre demande pour le certificat manquant
            self.contexte.message_dao.transmettre_demande_certificat(fingerprint)
            raise ci

        # Ajouter la date de restauration
        evenements = enveloppe_transaction.get(Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT)
        if not evenements:
            evenements = dict()
            enveloppe_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT] = evenements

        evenements[Constantes.EVENEMENT_TRANSACTION_BACKUP_RESTAURE] = datetime.datetime.utcnow()
        evenements[Constantes.EVENEMENT_TRANSACTION_BACKUP_FLAG] = True

        try:
            collection_transactions.insert_one(enveloppe_transaction)
        except DuplicateKeyError:
            # Ok, la transaction existe deja dans la collection - rien a faire
            pass

    def on_channel_open(self, channel):
        self.__channel = channel

        queue_name = self.contexte.configuration.queue_nouvelles_transactions
        channel.add_on_close_callback(self.__on_channel_close)
        channel.basic_qos(prefetch_count=1)
        channel.basic_consume(self.callbackAvecAck, queue=queue_name, no_ack=False)

    def __on_channel_close(self, channel=None, code=None, reason=None):
        self.__channel = None

    def is_channel_open(self):
        return self.__channel is not None and not self.__channel.is_closed


class EvenementTransactionCallback(BaseCallback):

    def __init__(self, contexte):
        super().__init__(contexte)
        self.__channel = None
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    # Methode pour recevoir le callback pour les nouvelles transactions.
    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        routing_key = method.routing_key
        exchange = method.exchange
        action = routing_key.split('.')[-1]
        if exchange in (Constantes.SECURITE_SECURE, Constantes.SECURITE_PROTEGE):
            if action == 'transactionEvenement':
                self.ajouter_evenement(message_dict)
            elif action == 'transactionReset':
                self.reset_evenements_transactions(message_dict)
            elif action == 'transactionToken':
                self.ajouter_evenement_token(message_dict)
            else:
                raise ValueError("Type d'operation inconnue: routing: %s, action=%s, message=%s" % (routing_key, action, str(message_dict)))
        else:
            raise ValueError("Type d'operation inconnue: routing=%s, action=%s, message=%s" % (routing_key, action, str(message_dict)))

    def ajouter_evenement(self, message_dict):

        nom_collection = message_dict[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]
        evenement = message_dict[Constantes.EVENEMENT_MESSAGE_EVENEMENT]

        try:
            id_transaction = message_dict[Constantes.MONGO_DOC_ID]
            self.set_evenement_traitement_transaction(id_transaction, nom_collection, evenement)
        except KeyError:
            # L'evenement n'est pas pour une seule transaction, on recupere la liste des uuids
            uuid_transactions = message_dict[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
            self.ajouter_evenement_transactions(uuid_transactions, nom_collection, evenement)

    def ajouter_evenement_token(self, message_dict):
        id_transaction = message_dict[Constantes.MONGO_DOC_ID]
        nom_collection = message_dict[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]
        token = message_dict[Constantes.EVENEMENT_MESSAGE_EVENEMENT_TOKEN]
        type_token = message_dict[Constantes.EVENEMENT_MESSAGE_TYPE_TOKEN]
        timestamp = message_dict[Constantes.EVENEMENT_MESSAGE_EVENEMENT_TIMESTAMP]

        self.set_evenement_token_transaction(id_transaction, nom_collection, type_token, token, timestamp)

    def reset_evenements_transactions(self, message_dict):
        """
        Permet d'ajouter un evenement a une liste de transactions par UUID.

        :param message_dict:
        :return:
        """
        nom_collection = message_dict[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]
        unset_fields = message_dict[Constantes.EVENEMENT_MESSAGE_UNSET]
        set_fields = message_dict[Constantes.EVENEMENT_MESSAGE_EVENEMENTS]

        unset_ops = dict()
        for field in unset_fields:
            unset_ops[field] = ''

        ops = {'$unset': unset_ops, '$set': set_fields}

        collection_transactions = self.contexte.document_dao.get_collection(nom_collection)
        collection_transactions.update_many({}, ops)

    def set_evenement_traitement_transaction(self, id_transaction, nom_collection, evenement):
        collection_transactions = self.contexte.document_dao.get_collection(nom_collection)

        transaction_complete = False
        if evenement in [
            Constantes.EVENEMENT_TRANSACTION_TRAITEE,
            Constantes.EVENEMENT_TRANSACTION_ERREUR_TRAITEMENT,
            Constantes.EVENEMENT_TRANSACTION_ERREUR_EXPIREE,
            Constantes.EVENEMENT_TRANSACTION_ERREUR_RESOUMISSION,
        ]:
            transaction_complete = True

        libelle_transaction_traitee = '%s.%s' % (
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
            evenement
        )
        libelle_transaction_complete = '%s.%s' % (
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
            raise Exception(
                "Erreur ajout evenement transaction, updated: %d, ObjectId: %s, collection: %s, evenement: %s" % (
                    resultat.modified_count, str(id_transaction), nom_collection, evenement
                )
            )

    def set_evenement_token_transaction(self, id_transaction, nom_collection, type_token, tokens, timestamp):
        timestamp_datetime = datetime.datetime.fromtimestamp(timestamp)
        for token in tokens:
            info_token = {'token': token, 'timestamp': timestamp_datetime}
            push_ops = {
                '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, type_token): info_token
            }
            ops = {
                '$push': push_ops
            }

            filtre = {
                Constantes.MONGO_DOC_ID: ObjectId(id_transaction)
            }

            collection_transactions = self.contexte.document_dao.get_collection(nom_collection)
            collection_transactions.update_one(filtre, ops)

    def ajouter_evenement_transactions(self, uuid_transaction: list, nom_collection: str, evenement: str):
        """
        Permet d'ajouter un evenement a une liste de transactions par UUID.

        :param uuid_transaction:
        :param nom_collection:
        :param evenement:
        :return:
        """
        collection_transactions = self.contexte.document_dao.get_collection(nom_collection)

        libelle_evenement = '%s.%s' % (
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
            evenement
        )
        selection = {
            '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE, Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID):
                {'$in': uuid_transaction}
        }
        set_ops = {
            libelle_evenement: datetime.datetime.now(tz=datetime.timezone.utc),
        }
        operation = {
            '$set': set_ops
        }

        if evenement in [
            Constantes.EVENEMENT_TRANSACTION_BACKUP_ERREUR,
            Constantes.EVENEMENT_TRANSACTION_BACKUP_HORAIRE_COMPLETE,
        ]:
            libelle_backup_flag = '%s.%s' % (
                Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
                Constantes.EVENEMENT_TRANSACTION_BACKUP_FLAG,
            )
            set_ops[libelle_backup_flag] = True

        resultat = collection_transactions.update_many(selection, operation)

        if resultat.modified_count != len(uuid_transaction):
            raise Exception(
                "Erreur ajout evenement a des transactions, updated: %d, collection: %s, evenement: %s, uuids: %s" % (
                    resultat.modified_count, nom_collection, evenement, str(uuid_transaction)
                )
            )

    @staticmethod
    def identifier_collection_domaine(domaine):

        domaine_split = domaine.split('.')

        nom_collection = None
        if domaine_split[0] == 'millegrilles' and domaine_split[1] == 'domaines':
            nom_collection = '.'.join(domaine_split[0:3])

        return nom_collection

    def on_channel_open(self, channel):
        self.__channel = channel

        self._logger.debug("Chargement channel evenements : %s" % str(channel))

        evenements_queue_name = self.contexte.configuration.queue_evenements_transactions
        channel.add_on_close_callback(self.__on_channel_close)
        channel.basic_qos(prefetch_count=1)
        channel.basic_consume(self.callbackAvecAck, queue=evenements_queue_name, no_ack=False)

    def __on_channel_close(self, channel=None, code=None, reason=None):
        self.__channel = None

    def is_channel_open(self):
        return self.__channel is not None and not self.__channel.is_closed


class EntretienCollectionsDomaines(BaseCallback):

    def __init__(self, consignateur: ConsignateurTransaction, contexte):
        super().__init__(contexte)
        self.__consignateur = consignateur

        self.__thread_entretien = None
        self.__channel = None
        self.__throttle_event = Event()

        self.__liste_domaines = dict()

        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def entretien_initial(self):
        self.__thread_entretien = Thread(target=self._run_entretien_initial, name="Entretien")
        self.__thread_entretien.start()

    def _run_entretien_initial(self):
        self.__logger.info("Entretien initial transactions")
        try:
            self._setup_transaction()
            self.__thread_entretien = None  # Cleanup thread termine
            self.__logger.info("FIN Entretien initial transactions")
        except Exception:
            self.__logger.exception("Erreur entretien initial, on ferme le consignateur de transaction")
            self.__consignateur.deconnecter()

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

    def _setup_index_domaines(self, nom_collection_transaction):
        try:
            collection = self.contexte.document_dao.get_collection(nom_collection_transaction)
            champ_complete = '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_TRANSACTION_COMPLETE)
            champ_persiste = '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_DOCUMENT_PERSISTE)
            champ_traitee = '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_TRANSACTION_TRAITEE)
            champ_backup_flag = '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_TRANSACTION_BACKUP_FLAG)

            # en-tete.uuid-transaction
            collection.create_index(
                [
                    ('%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE, Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID), 1)
                ],
                name='uuid_transaction',
                unique=True,
            )

            # _evenements.estampille
            collection.create_index(
                [
                    ('%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_TRANSACTION_ESTAMPILLE), -1)
                ],
                name='estampille'
            )

            # _evenements.transaction_traitee
            collection.create_index(
                [
                    (champ_complete, 1),
                    (champ_traitee, 1)
                ],
                name='transaction_traitee'
            )

            # _evenements.transaction_persistee
            collection.create_index(
                [
                    (champ_complete, 1),
                    (champ_persiste, 1)
                ],
                name='transaction_persistee'
            )

            # _evenements.backup_horaire
            collection.create_index(
                [
                    ('_evenements.transaction_traitee', 1),
                    (champ_complete, 1),
                    (champ_backup_flag, 1)
                ],
                name='transaction_backup_flag2'
            )

        except Exception:
            self.__logger.exception("Erreur creation index de transactions dans %s" % nom_collection_transaction)

    def _verifier_signature(self):
        delta_verif = datetime.timedelta(minutes=5)
        date_courante = datetime.datetime.now(tz=datetime.timezone.utc)
        date_verif = date_courante - delta_verif

        idmg = self.configuration.idmg

        label_date_resoumise = '%s.%s' % (
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
            Constantes.EVENEMENT_TRANSACTION_DATE_RESOUMISE
        )

        verificateur_transaction = self.contexte.verificateur_transaction
        for nom_collection_transaction in self.__liste_domaines:
            filtre = {
                '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_TRANSACTION_COMPLETE): False,
                '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_DOCUMENT_PERSISTE): {'$lt': date_verif},
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
                            resoumissions = evenements_transaction.get(Constantes.EVENEMENT_TRANSACTION_COMPTE_RESOUMISE)
                            if resoumissions is not None:
                                compteur_resoumission = resoumissions

                        if compteur_resoumission < 3:
                            compteur_resoumission = compteur_resoumission + 1

                            # Signature valide, on trigger le traitement de persistance
                            label_signature = '%s.%s' % (
                                Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
                                Constantes.EVENEMENT_SIGNATURE_VERIFIEE
                            )
                            label_compte_resoumise = '%s.%s' % (
                                Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
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
                            self.contexte.generateur_transactions.transmettre_evenement_persistance(
                                str(transaction_id), uuid_transaction, domaine, {})
                        else:
                            # La transaction a ete re-soumise trop de fois, on la met en erreur
                            self.__logger.error("Marquer transaction comme resoumise trop de fois %s" % str(transaction_id))
                            libelle_transaction_traitee = '%s.%s' % (
                                Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
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

        idmg = self.contexte.configuration.idmg
        delta_expiration = datetime.timedelta(hours=1)
        date_courante = datetime.datetime.now(tz=datetime.timezone.utc)
        date_expiration = date_courante - delta_expiration
        operations = {
            '$set': {
                '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_TRANSACTION_COMPLETE): True,
                '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
                               Constantes.EVENEMENT_TRANSACTION_ERREUR_EXPIREE): date_courante,
            }
        }

        for nom_collection_transaction in self.__liste_domaines:
            filtre = {
                '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_TRANSACTION_COMPLETE): False,
                '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_DOCUMENT_PERSISTE): {'$gt': date_expiration},
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

        if routing_key.startswith('ceduleur'):
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
        elif routing_key == Constantes.EVENEMENT_ROUTING_PRESENCE_DOMAINES:
            self.__traiter_presence_domaine(message_dict, properties)

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

    def __traiter_presence_domaine(self, message_dict: dict, properties):
        domaine = message_dict['domaine']
        exchanges = message_dict.get('exchanges_routing')
        info_domaine = self.__liste_domaines.get(domaine)
        if not info_domaine:
            # Ajouter routing key
            routing = 'transaction.%s.#.*' % domaine
            self.__channel.queue_bind(
                queue=Constantes.DEFAUT_QUEUE_NOUVELLES_TRANSACTIONS,
                exchange=Constantes.SECURITE_PROTEGE,
                routing_key=routing,
                callback=None
            )

            if exchanges.get(Constantes.SECURITE_PRIVE) is not None:
                # On a des messages sur l'exchange prive, on permet aussi les transactions a ce niveau
                self.__channel.queue_bind(
                    queue=Constantes.DEFAUT_QUEUE_NOUVELLES_TRANSACTIONS,
                    exchange=Constantes.SECURITE_PRIVE,
                    routing_key=routing,
                    callback=None
                )

            # Ajouter collection/indices
            self._setup_index_domaines(domaine)

            # Conserver info domaine
            self.__liste_domaines[domaine] = info_domaine

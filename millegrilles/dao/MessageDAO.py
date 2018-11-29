# Gestion des messages via Pika.
import codecs
import pika
import json
import traceback
import threading
import logging

from millegrilles import Constantes
from pika.credentials import PlainCredentials

''' 
DAO vers la messagerie
Connection a un moteur de messagerie via Pika.
'''


class PikaDAO:

    def __init__(self, configuration):
        self._lock_transmettre_message = threading.Lock()

        self.configuration = configuration
        self.connectionmq = None
        self.channel = None

        self._actif = False
        self.in_error = True

        self.json_helper = JSONHelper()

    # Connecter au serveur RabbitMQ
    # Le callback est une methode qui va etre appelee lorsqu'un message est recu
    def connecter(self):
        credentials = PlainCredentials(
            self.configuration.mq_user,
            self.configuration.mq_password,
            erase_on_connect=True
        )

        ssl_option = self.configuration.mq_ssl
        self.connectionmq = pika.BlockingConnection(
            pika.ConnectionParameters(
                host=self.configuration.mq_host,
                port=self.configuration.mq_port,
                heartbeat=60,
                credentials=credentials,
                ssl=ssl_option == 'on'  # Mettre SSL lorsque ca fonctionnera avec RabbitMQ
            )
        )
        self.channel = self.connectionmq.channel()
        self.channel.basic_qos(prefetch_count=1)

        self._actif = True
        self.in_error = False

        return self.connectionmq

    def configurer_rabbitmq(self):

        # S'assurer que toutes les queues durables existes. Ces queues doivent toujours exister
        # pour eviter que des messages de donnees originales ne soient perdus.
        nom_millegrille = self.configuration.nom_millegrille
        nom_echange_evenements = self.configuration.exchange_evenements
        nom_q_nouvelles_transactions = self.queuename_nouvelles_transactions()
        nom_q_erreurs_transactions = self.queuename_erreurs_transactions()
        nom_q_mgp_processus = self.queuename_mgp_processus()
        nom_q_erreurs_processus = self.queuename_erreurs_processus()

        nom_q_generateur_documents = self.queuename_generateur_documents()

        # Creer l'echange de type topics pour toutes les MilleGrilles
        self.channel.exchange_declare(
            exchange=nom_echange_evenements,
            exchange_type='topic',
            durable=True
        )

        # Creer la Q de nouvelles transactions pour cette MilleGrille
        self.channel.queue_declare(
            queue=nom_q_nouvelles_transactions,
            durable=True)

        self.channel.queue_bind(
            exchange=nom_echange_evenements,
            queue=nom_q_nouvelles_transactions,
            routing_key='%s.transaction.nouvelle' % nom_millegrille
        )

        # Creer la Q de processus MilleGrilles Python (mgp) pour cette MilleGrille
        self.channel.queue_declare(
            queue=nom_q_mgp_processus,
            durable=True)

        self.channel.queue_bind(
            exchange=nom_echange_evenements,
            queue=nom_q_mgp_processus,
            routing_key='%s.mgpprocessus.#' % nom_millegrille
        )

        # Creer la Q d'erreurs dans les transactions pour cette MilleGrille
        self.channel.queue_declare(
            queue=nom_q_erreurs_transactions,
            durable=True)

        self.channel.queue_bind(
            exchange=nom_echange_evenements,
            queue=nom_q_erreurs_transactions,
            routing_key='%s.transaction.erreur' % nom_millegrille
        )

        # Creer la Q d'erreurs dans les processus pour cette MilleGrille
        self.channel.queue_declare(
            queue=nom_q_erreurs_processus,
            durable=True)

        self.channel.queue_bind(
            exchange=nom_echange_evenements,
            queue=nom_q_erreurs_processus,
            routing_key='%s.processus.erreur' % nom_millegrille
        )

        # Creer la Q pour le gestionnaire de generateurs de documents
        self.channel.queue_declare(
            queue=nom_q_generateur_documents,
            durable=True)

        self.channel.queue_bind(
            exchange=nom_echange_evenements,
            queue=nom_q_generateur_documents,
            routing_key='%s.generateurdocuments.#' % nom_millegrille
        )

    ''' Prepare la reception de message '''

    def demarrer_lecture_nouvelles_transactions(self, callback):

        queue_name = 'mg.%s.%s' % (self.configuration.nom_millegrille, self.configuration.queue_nouvelles_transactions)

        self.channel.basic_consume(callback, queue=queue_name, no_ack=False)

        try:
            self.channel.start_consuming()

        except OSError as oserr:
            logging.error("erreur start_consuming, probablement du a la fermeture de la queue: %s" % oserr)

    ''' Demarre la lecture de la queue mgp_processus. Appel bloquant. '''

    def demarrer_lecture_etape_processus(self, callback):
        self.channel.basic_consume(callback,
                                   queue=self.queuename_mgp_processus(),
                                   no_ack=False)
        try:
            self.channel.start_consuming()
        except OSError as oserr:
            logging.error("erreur start_consuming, probablement du a la fermeture de la queue: %s" % oserr)

    ''' Demarre la lecture de la queue mgp_processus. Appel bloquant. '''

    def demarrer_lecture_generateur_documents(self, callback):
        self.channel.basic_consume(callback,
                                   queue=self.queuename_generateur_documents(),
                                   no_ack=False)
        try:
            self.channel.start_consuming()
        except OSError as oserr:
            logging.error("erreur start_consuming, probablement du a la fermeture de la queue: %s" % oserr)

    ''' 
    Methode generique pour transmettre un evenement JSON avec l'echange millegrilles
    
    :param routing_key: Routing key utilise pour distribuer le message.
    :param message_dict: Dictionnaire du contenu du message qui sera encode en JSON
    '''

    def transmettre_message(self, message_dict, routing_key, delivery_mode_v=1):

        if self.connectionmq is None or self.connectionmq.is_closed:
            raise ExceptionConnectionFermee("La connexion Pika n'est pas ouverte")

        message_utf8 = self.json_helper.dict_vers_json(message_dict)
        with self._lock_transmettre_message:
            self.channel.basic_publish(
                exchange=self.configuration.exchange_evenements,
                routing_key=routing_key,
                body=message_utf8,
                properties=pika.BasicProperties(delivery_mode=delivery_mode_v))
        self.in_error = False

    def transmettre_nouvelle_transaction(self, document_transaction):
        routing_key = '%s.transaction.nouvelle' % self.configuration.nom_millegrille
        # Utiliser delivery mode 2 (persistent) pour les transactions
        self.transmettre_message(document_transaction, routing_key, delivery_mode_v=2)

    def transmettre_evenement_persistance(self, id_document, id_transaction, document_transaction=None):

        message = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_ID_MONGO: str(id_document),
            Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: id_transaction,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT: "transaction_persistee"
        }
        message_utf8 = self.json_helper.dict_vers_json(message)

        if document_transaction is not None and document_transaction[
                Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION].get("domaine") is not None:
            nom_domaine = document_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION].get("domaine")
            routing_key = '%s.destinataire.domaine.%s' % (self.configuration.nom_millegrille, nom_domaine)
        else:
            routing_key = '%s.transaction.persistee' % self.configuration.nom_millegrille

        self.channel.basic_publish(
            exchange='millegrilles.evenements',
            routing_key=routing_key,
            body=message_utf8)

    '''
    Transmet un declencheur pour une etape de processus MilleGrilles.
    
    :param id_document: Document contenant l'information pour ce processus.
    :param nom_process: Nom du processus a executer.
    :param nom_etape: (Optionnel) Nom de la prochaine etape a declencher. Defaut: initiale
    :param evenement_declencheur: (Optionnel) Evenement qui a declenche l'execution de l'etape courante.
    :param dict_parametres: (Optionnel) Parametres a utiliser pour la prochaine etape du processus.
    '''

    def transmettre_evenement_mgpprocessus(self, id_document, nom_processus, nom_etape='initiale'):
        message = {
            Constantes.PROCESSUS_MESSAGE_LIBELLE_ID_DOC_PROCESSUS: str(id_document),
            Constantes.PROCESSUS_MESSAGE_LIBELLE_PROCESSUS: nom_processus,
            Constantes.PROCESSUS_DOCUMENT_LIBELLE_ETAPESUIVANTE: nom_etape
        }

        message_utf8 = self.json_helper.dict_vers_json(message)

        routing_key = '%s.mgpprocessus.%s.%s' % \
                      (self.configuration.nom_millegrille,
                       nom_processus,
                       nom_etape)

        self.channel.basic_publish(exchange=self.configuration.exchange_evenements,
                                   routing_key=routing_key,
                                   body=message_utf8)

    '''
    Methode a utiliser pour mettre fin a l'execution d'un processus pour une transaction suite a une erreur fatale.
    
    :param id_document: Document affecte (Object ID dans Mongo)
    :param id_transaction: (Optionnel) Identificateur de la transaction qui est bloquee
    :param detail: (Optionnel) Information sur l'erreur.
    '''

    def transmettre_erreur_transaction(self, id_document, id_transaction=None, detail=None):

        message = {
            Constantes.MONGO_DOC_ID: id_document,
        }
        if id_transaction is not None:
            message[Constantes.TRANSACTION_MESSAGE_LIBELLE_ID_MONGO] = id_transaction
        if detail is not None:
            message["erreur"] = str(detail)
            message["stacktrace"] = traceback.format_exception(etype=type(detail), value=detail,
                                                               tb=detail.__traceback__)

        message_utf8 = self.json_helper.dict_vers_json(message)

        self.channel.basic_publish(exchange=self.configuration.exchange_evenements,
                                   routing_key='%s.transaction.erreur' % self.configuration.nom_millegrille,
                                   body=message_utf8)

    '''
     Methode a utiliser pour mettre fin a l'execution d'un processus pour une transaction suite a une erreur fatale.

     :param id_document: Document affecte (Object ID dans Mongo)
     :param id_transaction: (Optionnel) Identificateur de la transaction qui est bloquee
     :param detail: (Optionnel) Information sur l'erreur.
     '''

    def transmettre_erreur_processus(self, id_document_processus, message_original=None, detail=None):

        message = {
            "_id": id_document_processus,
        }
        if message_original is not None:
            message['message_original'] = message_original
        if detail is not None:
            message["erreur"] = str(detail)
            message["stacktrace"] = traceback.format_exception(etype=type(detail), value=detail,
                                                               tb=detail.__traceback__)

        message_utf8 = self.json_helper.dict_vers_json(message)

        self.channel.basic_publish(exchange=self.configuration.exchange_evenements,
                                   routing_key='%s.processus.erreur' % self.configuration.nom_millegrille,
                                   body=message_utf8)

    # def transmettre_evenement_generateur_documents(self, message):
    #
    #     chemin = message.get(Constantes.DOCUMENT_INFODOC_CHEMIN)
    #     if chemin is not None:
    #         chemin = '.%s' % '.'.join(chemin)
    #     else:
    #         chemin = ''
    #
    #     message_utf8 = self.json_helper.dict_vers_json(message)
    #
    #     self.channel.basic_publish(
    #         exchange=self.configuration.exchange_evenements,
    #         routing_key='%s.generateurdocuments%s' % (
    #             self.configuration.nom_millegrille, chemin),
    #         body=message_utf8)

    # Mettre la classe en etat d'erreur
    def enter_error_state(self):
        self.in_error = True

        if self.channel is not None:
            try:
                self.channel.stop_consuming()
            except Exception as e:
                logging.warning("MessageDAO.enterErrorState: Erreur stop consuming %s" % str(e))

        self.deconnecter()

    # Se deconnecter de RabbitMQ
    def deconnecter(self):
        self._actif = False
        try:
            if self.connectionmq is not None:
                if self.channel is not None:
                    self.channel.stop_consuming()
                    self.channel.close()
                if self.connectionmq is not None:
                    self.connectionmq.close()
        finally:
            self.channel = None
            self.connectionmq = None

    def _queuename(self, nom_queue):
        return "mg.%s.%s" % (self.configuration.nom_millegrille, nom_queue)

    def queuename_nouvelles_transactions(self):
        return self._queuename(self.configuration.queue_nouvelles_transactions)

    def queuename_erreurs_transactions(self):
        return self._queuename(self.configuration.queue_erreurs_transactions)

    def queuename_erreurs_processus(self):
        return self._queuename(self.configuration.queue_erreurs_processus)

    def queuename_mgp_processus(self):
        return self._queuename(self.configuration.queue_mgp_processus)

    def queuename_generateur_documents(self):
        return self._queuename(self.configuration.queue_generateur_documents)


# Classe avec utilitaires pour JSON
class JSONHelper:

    def __init__(self):
        self.reader = codecs.getreader("utf-8")

    def dict_vers_json(self, enveloppe_dict):
        message_utf8 = json.dumps(enveloppe_dict, sort_keys=True, ensure_ascii=False)
        return message_utf8

    def bin_utf8_json_vers_dict(self, json_utf8):
        message_json = json_utf8.decode("utf-8")
        dict = json.loads(message_json)
        return dict


''' 
Classe qui facilite l'implementation de callbacks avec ACK
'''


class BaseCallback:

    def __init__(self, configuration):

        if configuration is None:
            raise TypeError('configuration ne doit pas etre None')

        self.json_helper = JSONHelper()
        self._configuration = configuration

    def callbackAvecAck(self, ch, method, properties, body):
        try:
            self.traiter_message(ch, method, properties, body)
        except Exception as e:
            logging.warning("Erreur dans callbackAvecAck, exception: %s" % str(e))
            self.transmettre_erreur(ch, body, e)
        finally:
            self.transmettre_ack(ch, method)

    def transmettre_ack(self, ch, method):
        ch.basic_ack(delivery_tag=method.delivery_tag)

    def transmettre_erreur(self, ch, body, erreur):
        message = {
            "message_original": str(body)
        }
        if erreur is not None:
            message["erreur"] = str(erreur)
            message["stacktrace"] = traceback.format_exception(etype=type(erreur), value=erreur,
                                                               tb=erreur.__traceback__)

        message_utf8 = self.json_helper.dict_vers_json(message)

        ch.basic_publish(exchange=self._configuration.exchange_evenements,
                         routing_key='%s.processus.erreur' % self._configuration.nom_millegrille,
                         body=message_utf8)

    ''' Methode qui peut etre remplacee dans la sous-classe '''

    def traiter_message(self, ch, method, properties, body):
        raise NotImplemented('traiter_message() methode doit etre implementee')


class ExceptionConnectionFermee(Exception):
    pass

# Gestion des messages via Pika.
import codecs
import pika
import json
import traceback
import logging
import ssl

from threading import Lock

from millegrilles import Constantes
from pika.credentials import PlainCredentials, ExternalCredentials

''' 
DAO vers la messagerie
Connection a un moteur de messagerie via Pika.
'''


class PikaDAO:

    def __init__(self, configuration):
        self._lock_transmettre_message = Lock()

        self.configuration = configuration
        self.connectionmq = None
        self.channel = None

        self._actif = False
        self.in_error = True

        self.json_helper = JSONHelper()

    def preparer_connexion(self):
        """ Retourne un dictionnaire avec les parametres de connexion a RabbitMQ """

        connection_parameters = {
            'host': self.configuration.mq_host,
            'port': self.configuration.mq_port,
            'virtual_host': self.configuration.nom_millegrille,
            'heartbeat': self.configuration.mq_heartbeat
        }

        if self.configuration.mq_auth_cert == 'on':
            # Va faire la connection via plugin configure dans MQ, normalement c'est rabbitmq_auth_mechanism_ssl
            connection_parameters['credentials'] = ExternalCredentials()
        else:
            credentials = {
                'username': self.configuration.mq_user,
                'password': self.configuration.mq_password,
                'erase_on_connect': True
            }
            connection_parameters['credentials'] = PlainCredentials(**credentials)

        if self.configuration.mq_ssl == 'on':
            ssl_options = {
                'ssl_version': ssl.PROTOCOL_TLSv1_2,
                'keyfile': self.configuration.mq_keyfile,
                'certfile': self.configuration.mq_certfile,
                'ca_certs': self.configuration.mq_cafile,
                'cert_reqs': ssl.CERT_REQUIRED
            }

            connection_parameters['ssl'] = True
            connection_parameters['ssl_options'] = ssl_options

        return connection_parameters

    def connecter(self, separer=False):
        """
        Connecter au serveur RabbitMQ
        Le callback est une methode qui va etre appelee lorsqu'un message est recu

        :param separer: Si False, la connexion est ouverte pour l'instance PikaDAO, Si True, on retourne la connexion
                        sans conserver de pointeur.
        :return: Connexion a RabbitMQ.
        """

        try:
            parametres = pika.ConnectionParameters(**self.preparer_connexion())
            connectionmq = pika.BlockingConnection(parametres)
            channel = connectionmq.channel()
            channel.basic_qos(prefetch_count=1)

            if not separer:
                # La connexion est pour l'instance de PikaDAO
                self._actif = True
                self.in_error = False
                self.connectionmq = connectionmq
                self.channel = channel
        except Exception as e:
            if not separer:
                self.in_error = True
            raise e  # S'assurer de mettre le flag d'erreur

        return connectionmq

    def configurer_rabbitmq(self):

        # S'assurer que toutes les queues durables existes. Ces queues doivent toujours exister
        # pour eviter que des messages de donnees originales ne soient perdus.
        # nom_echange_evenements = self.configuration.exchange_evenements
        nom_echange_middleware = self.configuration.exchange_middleware
        nom_echanges = [
            nom_echange_middleware,
            self.configuration.exchange_inter,
            self.configuration.exchange_noeuds,
            self.configuration.exchange_public
        ]
        nom_q_nouvelles_transactions = self.queuename_nouvelles_transactions()
        nom_q_erreurs_transactions = self.queuename_erreurs_transactions()
        nom_q_mgp_processus = self.queuename_mgp_processus()
        nom_q_erreurs_processus = self.queuename_erreurs_processus()

        # Creer l'echange de type topics pour toutes les MilleGrilles
        for nom_echange in nom_echanges:
            self.channel.exchange_declare(
                exchange=nom_echange,
                exchange_type='topic',
                durable=True
            )

        # Creer la Q de nouvelles transactions pour cette MilleGrille
        self.channel.queue_declare(
            queue=nom_q_nouvelles_transactions,
            durable=True)

        for nom_echange in nom_echanges:
            self.channel.queue_bind(
                exchange=nom_echange,
                queue=nom_q_nouvelles_transactions,
                routing_key='transaction.nouvelle'
            )

        # Creer la Q de processus MilleGrilles Python (mgp) pour cette MilleGrille
        self.channel.queue_declare(
            queue=nom_q_mgp_processus,
            durable=True)

        self.channel.queue_bind(
            exchange=nom_echange_middleware,
            queue=nom_q_mgp_processus,
            routing_key='mgpprocessus.#'
        )

        # Creer la Q d'erreurs dans les transactions pour cette MilleGrille
        self.channel.queue_declare(
            queue=nom_q_erreurs_transactions,
            durable=True)

        self.channel.queue_bind(
            exchange=nom_echange_middleware,
            queue=nom_q_erreurs_transactions,
            routing_key='transaction.erreur'
        )

        # Creer la Q d'erreurs dans les processus pour cette MilleGrille
        self.channel.queue_declare(
            queue=nom_q_erreurs_processus,
            durable=True)

        self.channel.queue_bind(
            exchange=nom_echange_middleware,
            queue=nom_q_erreurs_processus,
            routing_key='processus.erreur'
        )

    def start_consuming(self):
        """ Demarre la lecture de messages RabbitMQ """
        try:
            self.channel.start_consuming()

        except OSError as oserr:
            logging.error("erreur start_consuming, probablement du a la fermeture de la queue: %s" % oserr)

    ''' Prepare la reception de message '''

    def enregistrer_callback(self, queue, callback):
        queue_name = queue
        self.channel.basic_consume(callback, queue=queue_name, no_ack=False)

    def inscrire_topic(self, exchange, routing: list, callback):
        resultat = self.channel.queue_declare(queue='', exclusive=True)
        nom_queue = resultat.method.queue
        print("Resultat creation queue: %s" % nom_queue)
        for routing_key in routing:
            self.channel.queue_bind(queue=nom_queue, exchange=exchange, routing_key=routing_key)
        tag_queue = self.channel.basic_consume(callback, queue=nom_queue, no_ack=False)
        print("Tag queue: %s" % tag_queue)

    def demarrer_lecture_nouvelles_transactions(self, callback):
        queue_name = self.configuration.queue_nouvelles_transactions
        self.channel.basic_consume(callback, queue=queue_name, no_ack=False)
        self.start_consuming()

    def demarrer_lecture_etape_processus(self, callback):
        """ Demarre la lecture de la queue mgp_processus. Appel bloquant. """

        self.channel.basic_consume(callback,
                                   queue=self.queuename_mgp_processus(),
                                   no_ack=False)
        self.start_consuming()

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
                exchange=self.configuration.exchange_middleware,
                routing_key=routing_key,
                body=message_utf8,
                properties=pika.BasicProperties(delivery_mode=delivery_mode_v))
        self.in_error = False

    def transmettre_nouvelle_transaction(self, document_transaction):
        routing_key = 'transaction.nouvelle'
        # Utiliser delivery mode 2 (persistent) pour les transactions
        self.transmettre_message(document_transaction, routing_key, delivery_mode_v=2)

    def transmettre_notification(self, document_transaction, sub_routing_key):
        routing_key = 'notification.%s' % sub_routing_key
        # Utiliser delivery mode 2 (persistent) pour les notifications
        self.transmettre_message(document_transaction, routing_key, delivery_mode_v=2)

    def transmettre_evenement_persistance(self, id_document, id_transaction, nom_domaine, document_transaction=None):
        message = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_ID_MONGO: str(id_document),
            Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: id_transaction,
            Constantes.EVENEMENT_MESSAGE_EVENEMENT: "transaction_persistee",
            Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE: nom_domaine
        }
        message_utf8 = self.json_helper.dict_vers_json(message)
        routing_key = 'destinataire.domaine.%s' % nom_domaine

        with self._lock_transmettre_message:
            self.channel.basic_publish(
                exchange=self.configuration.exchange_middleware,
                routing_key=routing_key,
                body=message_utf8)

    ''' 
    Transmet un evenement de ceduleur. Utilise par les gestionnaires (ou n'importe quel autre processus abonne)
    pour declencher des processus reguliers. 
    
    Message: 
    {
      "evenements": "minute",
      "timestamp": {
        "annee": 2018, "mois": 12, "jour": 8, "heure": 9, "minute": 54, "joursemaine": 5
      },
      "indicateurs": [
        "heure", "TIMEZONE", "jour", "mois", "annee", "semaine"
      ]
    }
    
    Les indicateurs speciaux suivants sont ajoutes a la liste "indicateurs" lorsqu'applicable:
    - "heure"    # lorsque minute == 0
    - "UTC"      # Lorsque c'est pour UTC. Autres time zones peuvent etre EST (ou EDT), etc.
    - "jour"     # lorsque heure == 0 et minute == 0
    - "mois"     # lorsque jour == 1 et heure == 0 et minute == 0
    - "annee"    # lorsque mois == 1 et jour == 1 et heure == 0 et minute == 0
    - "semaine"  # lorsque joursemaine == 0 et heure == 0 et minute == 0
    
    Noter que ces memes indicateurs sont aussi ajoutes a la routing key. Il est possible de s'abonner
    uniquement a la notification desiree.
    
    routing_key: 
    - "sansnom.ceduleur.minute" # Cle de base (sansnom est le nom de la MilleGrille)
    - "sansnom.ceduleur.minute.heure.jour.mois.annee.semaine": Lorsque tous les indicateurs sont inclus
    - "sansnom.ceduleur.minute.heure.jour": Nouvelle journee a minuit.
    '''
    def transmettre_evenement_ceduleur(self, ts_dict, indicateurs):

        message = {
            Constantes.EVENEMENT_MESSAGE_EVENEMENT: Constantes.EVENEMENT_CEDULEUR,
            'timestamp': ts_dict,
            'indicateurs': indicateurs
        }
        message_utf8 = self.json_helper.dict_vers_json(message)

        # Creer la routing key avec les indicateurs (join l'array avec .)
        ind_routing_key = '.'.join(indicateurs)
        if len(ind_routing_key) > 0:
            ind_routing_key = '.%s' % ind_routing_key
        routing_key = 'ceduleur.minute%s' % ind_routing_key

        with self._lock_transmettre_message:
            self.channel.basic_publish(
                exchange=self.configuration.exchange_middleware,
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

        routing_key = 'mgpprocessus.%s.%s' % \
                      (nom_processus,
                       nom_etape)

        with self._lock_transmettre_message:
            self.channel.basic_publish(exchange=self.configuration.exchange_middleware,
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

        with self._lock_transmettre_message:
            self.channel.basic_publish(exchange=self.configuration.exchange_middleware,
                                       routing_key='transaction.erreur',
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

        with self._lock_transmettre_message:
            self.channel.basic_publish(exchange=self.configuration.exchange_middleware,
                                       routing_key='processus.erreur',
                                       body=message_utf8)

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

    def queuename_nouvelles_transactions(self):
        return self.configuration.queue_nouvelles_transactions

    def queuename_erreurs_transactions(self):
        return self.configuration.queue_erreurs_transactions

    def queuename_erreurs_processus(self):
        return self.configuration.queue_erreurs_processus

    def queuename_mgp_processus(self):
        return self.configuration.queue_mgp_processus


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

    def __init__(self, contexte):

        if contexte is None:
            raise TypeError('configuration ne doit pas etre None')

        self.json_helper = JSONHelper()
        self._contexte = contexte

    def callbackAvecAck(self, ch, method, properties, body):
        try:
            self.traiter_message(ch, method, properties, body)
        except Exception as e:
            logging.exception("Erreur dans callbackAvecAck, exception: %s" % str(e))
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

        ch.basic_publish(exchange=self._contexte.configuration.exchange_middleware,
                         routing_key='processus.erreur',
                         body=message_utf8)

    ''' Methode qui peut etre remplacee dans la sous-classe '''

    def traiter_message(self, ch, method, properties, body):
        raise NotImplemented('traiter_message() methode doit etre implementee')

    @property
    def contexte(self):
        return self._contexte


class ExceptionConnectionFermee(Exception):
    pass

# Gestion des messages via Pika.
import codecs
import pika
import json
import traceback
import logging
import ssl

from threading import Lock, Event, Thread

from millegrilles import Constantes
from pika.credentials import PlainCredentials, ExternalCredentials
from pika.exceptions import AMQPConnectionError

''' 
DAO vers la messagerie
Connection a un moteur de messagerie via Pika.
'''


class PikaDAO:

    def __init__(self, configuration):
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))
        self._lock_transmettre_message = Lock()

        self._attendre_channel = Event()

        self.configuration = configuration
        self.connectionmq = None
        self.channel = None

        self._queue_reponse = None

        self._executer_configurer_rabbitmq = False

        self._actif = False
        self._in_error = True

        # Thread utilisee pour verifier le fonctionnement correct de MQ
        self.__stop_event = Event()
        self.__thread_ioloop = None
        self._intervalle_maintenance = 30  # secondes entre execution de maintenance de connexion
        self.__thread_maintenance = Thread(target=self.executer_maintenance, name="MQ-Maint")
        self.__thread_maintenance.start()

        # Liste des processus qui veulent se faire allouer un channel au demarrage
        # Methode appellee: channel_open(channel)
        self.__liste_listeners_channels = None

        self.json_helper = JSONHelper()

    def preparer_connexion(self):
        """ Retourne un dictionnaire avec les parametres de connexion a RabbitMQ """

        connection_parameters = {
            'host': self.configuration.mq_host,
            'port': self.configuration.mq_port,
            'virtual_host': self.configuration.nom_millegrille,
            'heartbeat': self.configuration.mq_heartbeat,
            'blocked_connection_timeout': self.configuration.mq_heartbeat/3
        }

        self._logger.info("Connecter RabbitMQ, parametres de connexion: %s" % str(connection_parameters))

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

        self._logger.info("Connecter RabbitMQ")

        if self.connectionmq is not None:
            self._logger.warning("Appel de connecter avec connection deja ouverte")
            connectionmq = self.connectionmq
            self.connectionmq = None
            self.channel = None
            self.__thread_ioloop = None

            try:
                connectionmq.close()
            except Exception as e:
                self._logger.debug("Erreur fermeture MQ avant de reconnecter: %s" % str(e))

        try:
            self._lock_transmettre_message.acquire(blocking=True, timeout=5)
            parametres_connexion = self.preparer_connexion()
            parametres = pika.ConnectionParameters(**parametres_connexion)
            self.connectionmq = pika.SelectConnection(
                parameters=parametres,
                on_open_callback=self.__on_connection_open,
                on_close_callback=self.__on_connection_close,
            )
            self.__thread_ioloop = Thread(name='MQ-IOloop', target=self.__run_ioloop)
            self.__thread_ioloop.start()  # Va faire un hook avec la nouvelle connexion MQ immediatement

        except Exception as e:
            self.enter_error_state()
            raise e  # S'assurer de mettre le flag d'erreur

        self._actif = True  # Le fait de se connecter indique que le DAO doit est actif
        return self.connectionmq

    def __on_connection_open(self, connection):
        self._logger.info("Callback connection, on ouvre le channel")
        connection.add_on_close_callback(self.__on_connection_close)
        connection.channel(on_open_callback=self.__on_channel_open)

        # Aussi allouer un channel a chaque listener inscrit
        if self.__liste_listeners_channels is not None:
            for listener in self.__liste_listeners_channels:
                self.__ouvrir_channel_listener(listener)

    def __on_channel_open(self, channel):
        self.channel = channel
        channel.basic_qos(prefetch_count=1)
        channel.add_on_close_callback(self.__on_channel_close)
        self._actif = True
        self._in_error = False

        self.__stop_event.clear()
        self._attendre_channel.set()  # Declenche execution processus en attente de la connexion
        self._lock_transmettre_message.release()

        self._logger.info("Connection / channel prets")

    def __on_connection_close(self, connection=None, code=None, reason=None):
        self.connectionmq = None
        self.channel = None
        self.__thread_ioloop = None
        if not self.__stop_event.is_set():
            self._logger.error("Connection fermee anormalement: %s, %s" % (code, reason))
            self.enter_error_state()
        else:
            self._logger.info("Connection fermee normalement: %s, %s" % (code, reason))

    def __on_channel_close(self, channel=None, code=None, reason=None):
        self._logger.warning("Channel ferme: %s, %s" % (code, reason))
        self.channel = None
        self._in_error = True  # Au cas ou la fermeture ne soit pas planifiee

    def register_channel_listener(self, listener):
        self._logger.info("Enregistrer listener pour channel %s" % listener.__class__.__name__)
        if self.__liste_listeners_channels is None:
            self.__liste_listeners_channels = list()
        self.__liste_listeners_channels.append(listener)
        self._logger.info("On a %d listeners de channels" % len(self.__liste_listeners_channels))

        # On verifie si on peut ouvrir le channel immediatement
        if self.connectionmq is not None and not self.connectionmq.is_closed and not self._in_error:
            self.__ouvrir_channel_listener(listener)

    def __ouvrir_channel_listener(self, listener):
        self.connectionmq.channel(on_open_callback=listener.on_channel_open)

    def configurer_rabbitmq(self):

        self.attendre_channel(timeout=30)
        if not self._attendre_channel.is_set():
            raise Exception("Channel MQ n'est pas ouvert")

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
            durable=True,
            callback=None
        )

        for nom_echange in nom_echanges:
            self.channel.queue_bind(
                exchange=nom_echange,
                queue=nom_q_nouvelles_transactions,
                routing_key=Constantes.TRANSACTION_ROUTING_NOUVELLE,
                callback=None
            )

        self.channel.queue_bind(
            exchange=self.configuration.exchange_middleware,
            queue=nom_q_nouvelles_transactions,
            routing_key=Constantes.TRANSACTION_ROUTING_EVENEMENT,
            callback=None
        )

        self.channel.queue_declare(
            queue=Constantes.DEFAUT_QUEUE_ENTRETIEN_TRANSACTIONS,
            durable=False,
            callback=None
        )

        self.channel.queue_bind(
            exchange=self.configuration.exchange_middleware,
            queue=Constantes.DEFAUT_QUEUE_ENTRETIEN_TRANSACTIONS,
            routing_key='ceduleur.#',
            callback=None
        )

        # Creer la Q d'erreurs dans les processus pour cette MilleGrille
        self.channel.queue_declare(
            queue=nom_q_erreurs_processus,
            durable=True,
            callback=None
        )

        self.channel.queue_bind(
            exchange=nom_echange_middleware,
            queue=nom_q_erreurs_processus,
            routing_key='processus.erreur',
            callback=None
        )

    def start_consuming(self):
        self._logger.warning("start_consuming(): Deprecated, gere dans MessageDAO")

    def __run_ioloop(self):
        self._logger.info("Demarrage MQ-IOLoop")
        try:
            self.connectionmq.ioloop.start()
        except AMQPConnectionError as e:
            self._logger.error("Erreur ouverture connexion MQ: %s" % str(e))
            self.enter_error_state()
        self._logger.info("Fin execution MQ-IOLoop")

    def run_ioloop(self):
        self._logger.warning("run_ioloop(): Deprecated, gere dans MessageDAO")

    def enregistrer_callback(self, queue, callback):
        queue_name = queue
        self.channel.basic_consume(callback, queue=queue_name, no_ack=False)

    def inscrire_topic(self, exchange, routing: list, callback):
        def callback_inscrire(
                queue, self=self, exchange_in=exchange, routing_in=frozenset(routing), callback_in=callback):
            nom_queue = queue.method.queue
            self._queue_reponse = nom_queue
            self._logger.debug("Resultat creation queue: %s" % nom_queue)
            bindings = set()
            bindings.update(routing_in)
            bindings.add('reponse.%s' % nom_queue)
            for routing_key in bindings:
                self.channel.queue_bind(queue=nom_queue, exchange=exchange_in, routing_key=routing_key, callback=None)
            tag_queue = self.channel.basic_consume(callback_in, queue=nom_queue, no_ack=False)
            self._logger.debug("Tag queue: %s" % tag_queue)
        
        self.channel.queue_declare(queue='', exclusive=True, callback=callback_inscrire)

    def demarrer_lecture_nouvelles_transactions(self, callback):
        queue_name = self.configuration.queue_nouvelles_transactions
        self.channel.basic_consume(callback, queue=queue_name, no_ack=False)

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

    def transmettre_message(self, message_dict, routing_key, delivery_mode_v=1, encoding=json.JSONEncoder, reply_to=None, correlation_id=None, channel=None):

        if self.connectionmq is None or self.connectionmq.is_closed:
            raise ExceptionConnectionFermee("La connexion Pika n'est pas ouverte")

        if channel is None:
            # Utiliser le channel implicite
            if self.channel is None:
                # Le channel n'est pas pret, on va l'attendre max 30 secondes (cycle de maintenance)
                with self._lock_transmettre_message:
                    pass  # On fait juste attendre que le channel soit pret
            channel = self.channel

        properties = pika.BasicProperties(delivery_mode=delivery_mode_v)
        if reply_to is not None:
            properties.reply_to = reply_to
        if correlation_id is not None:
            properties.correlation_id = correlation_id

        message_utf8 = self.json_helper.dict_vers_json(message_dict, encoding)
        with self._lock_transmettre_message:
            channel.basic_publish(
                exchange=self.configuration.exchange_middleware,
                routing_key=routing_key,
                body=message_utf8,
                properties=properties)
        self._in_error = False

    ''' 
    Methode generique pour transmettre un evenement JSON avec l'echange millegrilles

    :param routing_key: Routing key utilise pour distribuer le message.
    :param message_dict: Dictionnaire du contenu du message qui sera encode en JSON
    '''

    def transmettre_message_noeuds(self, message_dict, routing_key, delivery_mode_v=1,
                                   encoding=json.JSONEncoder, reply_to=None, correlation_id=None):

        if self.connectionmq is None or self.connectionmq.is_closed:
            raise ExceptionConnectionFermee("La connexion Pika n'est pas ouverte")

        properties = pika.BasicProperties(delivery_mode=delivery_mode_v)
        if reply_to is not None:
            properties.reply_to = reply_to
        if correlation_id is not None:
            properties.correlation_id = correlation_id

        message_utf8 = self.json_helper.dict_vers_json(message_dict, encoding)
        with self._lock_transmettre_message:
            self.channel.basic_publish(
                exchange=self.configuration.exchange_noeuds,
                routing_key=routing_key,
                body=message_utf8,
                properties=properties,
                mandatory=True)
        self._in_error = False

    def transmettre_reponse(self, message_dict, replying_to, correlation_id, delivery_mode_v=1, encoding=json.JSONEncoder):

        if self.connectionmq is None or self.connectionmq.is_closed:
            raise ExceptionConnectionFermee("La connexion Pika n'est pas ouverte")

        properties = pika.BasicProperties(delivery_mode=delivery_mode_v)
        properties.correlation_id = correlation_id

        message_utf8 = self.json_helper.dict_vers_json(message_dict, encoding)
        with self._lock_transmettre_message:
            self.channel.basic_publish(
                exchange='',  # Exchange default
                routing_key=replying_to,
                body=message_utf8,
                properties=properties,
                mandatory=True)
        self._in_error = False

    def transmettre_nouvelle_transaction(self, document_transaction, reply_to, correlation_id, channel=None):
        routing_key = 'transaction.nouvelle'
        # Utiliser delivery mode 2 (persistent) pour les transactions
        self.transmettre_message(
            document_transaction, routing_key, delivery_mode_v=2, reply_to=reply_to, correlation_id=correlation_id, channel=channel)

    def transmettre_notification(self, document_transaction, sub_routing_key):
        routing_key = 'notification.%s' % sub_routing_key
        # Utiliser delivery mode 2 (persistent) pour les notifications
        self.transmettre_message(document_transaction, routing_key, delivery_mode_v=2)

    def transmettre_demande_certificat(self, fingerprint):
        routing_key = 'pki.requete.%s' % fingerprint
        # Utiliser delivery mode 2 (persistent) pour les notifications
        self.transmettre_message({'fingerprint': fingerprint}, routing_key, delivery_mode_v=2)
        self.transmettre_message_noeuds({'fingerprint': fingerprint}, routing_key, delivery_mode_v=2)

    def transmettre_evenement_persistance(self, id_document, id_transaction, nom_domaine, properties_mq):
        message = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_ID_MONGO: str(id_document),
            Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: id_transaction,
            Constantes.EVENEMENT_MESSAGE_EVENEMENT: "transaction_persistee",
            Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE: nom_domaine,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_PROPERTIES_MQ: properties_mq
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

    def transmettre_evenement_mgpprocessus(self, nom_domaine: str, id_document, nom_processus, nom_etape='initiale',
                                           tokens=None,
                                           info=None):
        message = {
            Constantes.PROCESSUS_MESSAGE_LIBELLE_ID_DOC_PROCESSUS: str(id_document),
            Constantes.PROCESSUS_MESSAGE_LIBELLE_PROCESSUS: nom_processus,
            Constantes.PROCESSUS_DOCUMENT_LIBELLE_ETAPESUIVANTE: nom_etape
        }

        if tokens is not None:
            message[Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKEN_RESUMER] = tokens

        if info is not None:
            message[Constantes.PROCESSUS_DOCUMENT_LIBELLE_INFO] = info

        message_utf8 = self.json_helper.dict_vers_json(message)

        # routing_key = 'mgpprocessus.%s.%s' % \
        #               (nom_processus,
        #                nom_etape)

        routing_key = 'processus.domaine.%s.%s.%s' % \
                      (nom_domaine, nom_processus, nom_etape)

        with self._lock_transmettre_message:
            self.channel.basic_publish(exchange=self.configuration.exchange_middleware,
                                       routing_key=routing_key,
                                       body=message_utf8)

    def transmettre_evenement_mgp_resumer(self, nom_domaine, id_document_declencheur, tokens: list,
                                          id_document_processus_attente=None):
        message = {
            Constantes.EVENEMENT_MESSAGE_EVENEMENT: Constantes.EVENEMENT_RESUMER,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE: nom_domaine,
            Constantes.PROCESSUS_MESSAGE_LIBELLE_ID_DOC_PROCESSUS_DECLENCHEUR: str(id_document_declencheur),
            Constantes.PROCESSUS_MESSAGE_LIBELLE_RESUMER_TOKENS: tokens,
        }
        if id_document_processus_attente is not None:
            message[Constantes.PROCESSUS_MESSAGE_LIBELLE_ID_DOC_PROCESSUS_ATTENTE] = str(id_document_processus_attente)

        message_utf8 = self.json_helper.dict_vers_json(message)
        routing_key = 'processus.domaine.%s.resumer' % nom_domaine

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
        self._logger.warning("MQ Enter error state")
        self._in_error = True

        try:
            if self.channel is not None:
                self.channel.close()
        except Exception as e:
            self._logger.warning("MessageDAO.enterErrorState: Erreur stop consuming %s" % str(e))
        finally:
            self.channel = None

        try:
            if self.connectionmq is not None:
                self.connectionmq.close()
        except Exception as e:
            self._logger.info("Erreur fermeture connexion dans enter_error_state(): %s" % str(e))
        finally:
            self.connectionmq = None
            self.__thread_ioloop = None

    # Se deconnecter de RabbitMQ
    def deconnecter(self):
        self._actif = False
        self.__stop_event.set()

        if self.connectionmq is not None:
            try:
                self.connectionmq.close()
            finally:
                self.connectionmq = None

        self.channel = None
        self.__thread_ioloop = None

    def executer_maintenance(self):

        self._logger.info("Demarrage maintenance")
        self.__stop_event.wait(self._intervalle_maintenance)  # Attendre avant premier cycle de maintenance

        while not self.__stop_event.is_set():
            self._logger.debug("Maintenance MQ, in error: %s" % self._in_error)

            try:
                if self.connectionmq is not None and self.channel is None:
                    self._logger.error("La connection MQ est invalide - channel n'est pas ouvert.")
                    self.enter_error_state()
                elif self.connectionmq is None or self.connectionmq.is_closed:
                    self._logger.warning("La connection MQ est fermee. On tente de se reconnecter.")
                    self.connecter()
                else:
                    self._logger.debug("Rien a faire pour reconnecter a MQ")

                    # Verifier si les listeners fonctionnent bien
                    if self.__liste_listeners_channels is not None:
                        for listener in self.__liste_listeners_channels:
                            if 'is_channel_open' in dir(listener):  # Methode est optionnelle
                                if not listener.is_channel_open():
                                    self._logger.warning("Re-ouverture d'un channel de listener")
                                    self.__ouvrir_channel_listener(listener)

            except Exception as e:
                self._logger.exception("Erreur dans boucle de maintenance: %s" % str(e), exc_info=e)
                self.enter_error_state()

            self.__stop_event.wait(self._intervalle_maintenance)

        self._logger.info("MQ-Maint closing")

    def attendre_channel(self, timeout):
        self._attendre_channel.wait(timeout)

    def queuename_nouvelles_transactions(self):
        return self.configuration.queue_nouvelles_transactions

    def queuename_erreurs_transactions(self):
        return self.configuration.queue_erreurs_transactions

    def queuename_erreurs_processus(self):
        return self.configuration.queue_erreurs_processus

    def queuename_mgp_processus(self):
        return self.configuration.queue_mgp_processus

    @property
    def queue_reponse(self):
        return self._queue_reponse

    @property
    def in_error(self):
        return self._in_error


# Classe avec utilitaires pour JSON
class JSONHelper:

    def __init__(self):
        self.reader = codecs.getreader("utf-8")

    def dict_vers_json(self, enveloppe_dict, encoding=json.JSONEncoder):
        message_utf8 = json.dumps(enveloppe_dict, sort_keys=True, ensure_ascii=False, cls=encoding)
        return message_utf8

    def bin_utf8_json_vers_dict(self, json_utf8):
        message_json = json_utf8.decode("utf-8")
        dict = json.loads(message_json)
        return dict


class TraitementMessageCallback:
    """
    Classe qui facilite l'implementation de callbacks avec ACK
    """

    def __init__(self, message_dao, configuration):
        self.__json_helper = JSONHelper()
        self.__message_dao = message_dao
        self.__configuration = configuration
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def callbackAvecAck(self, ch, method, properties, body):
        try:
            self.traiter_message(ch, method, properties, body)
        except CertificatInconnu as ci:
            fingerprint = ci.fingerprint
            self.__logger.warning("Certificat inconnu, on fait la demande %s" % fingerprint)
            self.message_dao.transmettre_demande_certificat(fingerprint)
        except Exception as e:
            self.__logger.error("Erreur dans callbackAvecAck, exception: %s" % str(e))
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

        message_utf8 = self.__json_helper.dict_vers_json(message)

        ch.basic_publish(exchange=self.__configuration.exchange_middleware,
                         routing_key='processus.erreur',
                         body=message_utf8)

    def decoder_message_json(self, body):
        return self.__json_helper.bin_utf8_json_vers_dict(body)

    @property
    def message_dao(self):
        return self.__message_dao

    @property
    def configuration(self):
        return self.__configuration

    @property
    def json_helper(self):
        return self.__json_helper

    def traiter_message(self, ch, method, properties, body):
        """
        Traitement du message. A implementer dans la sous-classe.
        :param ch:
        :param method:
        :param properties:
        :param body:
        :return:
        """
        raise NotImplemented('traiter_message() methode doit etre implementee')


class BaseCallback(TraitementMessageCallback):

    def __init__(self, contexte):
        super().__init__(message_dao=contexte.message_dao, configuration=contexte.configuration)
        self._contexte = contexte

    @property
    def contexte(self):
        return self._contexte


class TraitementMessageDomaine(TraitementMessageCallback):

    def __init__(self, gestionnaire_domaine):
        super().__init__(message_dao=gestionnaire_domaine.message_dao, configuration=gestionnaire_domaine.configuration)
        self._gestionnaire = gestionnaire_domaine

    @property
    def document_dao(self):
        return self._gestionnaire.document_dao

    @property
    def gestionnaire(self):
        return self._gestionnaire


class TraitementMessageDomaineMiddleware(TraitementMessageDomaine):

    def traiter_message(self, ch, method, properties, body):
        routing_key = method.routing_key
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)

        if evenement == Constantes.EVENEMENT_TRANSACTION_PERSISTEE:
            # Verifier quel processus demarrer.
            routing_key_sansprefixe = routing_key.replace(
                'destinataire.domaine.',
                ''
            )

            try:
                processus = self.gestionnaire.identifier_processus(routing_key_sansprefixe)
                self.gestionnaire.demarrer_processus(processus, message_dict)
            except Exception as e:
                self.gestionnaire.marquer_transaction_en_erreur(message_dict)
                raise e
        else:
            raise ValueError("Type de transaction inconnue: routing: %s, message: %s" % (routing_key, evenement))


class TraitementMessageDomaineRequete(TraitementMessageDomaine):

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)

        try:
            self.gestionnaire.verificateur_transaction.verifier(message_dict)

            # routing_key = method.routing_key
            # exchange = method.exchange
            # evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)

            resultats = list()
            for requete in message_dict['requetes']:
                resultat = self.executer_requete(requete)
                resultats.append(resultat)

            # Genere message reponse
            self.transmettre_reponse(message_dict, resultats, properties.reply_to, properties.correlation_id)
        except CertificatInconnu as ci:
            fingerprint = ci.fingerprint
            self.message_dao.transmettre_demande_certificat(fingerprint)


    def executer_requete(self, requete):
        collection = self.gestionnaire.get_collection()
        filtre = requete.get('filtre')
        projection = requete.get('projection')
        sort_params = requete.get('sort')
        hint = requete.get('hint')

        if projection is None:
            curseur = collection.find(filtre)
        else:
            curseur = collection.find(filtre, projection)

        if sort_params is not None:
            curseur.sort(sort_params)

        if hint is not None:
            curseur.hint(hint)

        resultats = list()
        for resultat in curseur:
            resultats.append(resultat)

        return resultats

    def transmettre_reponse(self, requete, resultats, replying_to, correlation_id=None):
        # enveloppe_val = generateur.soumettre_transaction(requete, 'millegrilles.domaines.Principale.creerAlerte')
        if correlation_id is None:
            correlation_id = requete[Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]

        message_resultat = {
            'resultats': resultats,
        }

        self.gestionnaire.generateur_transactions.transmettre_reponse(message_resultat, replying_to, correlation_id)


class TraitementMessageCedule(TraitementMessageDomaine):

    def traiter_message(self, ch, method, properties, body):
        routing_key = method.routing_key
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)

        if evenement == Constantes.EVENEMENT_CEDULEUR:
            self.traiter_evenement(message_dict)
        else:
            raise ValueError("Type de transaction inconnue: routing: %s, message: %s" % (routing_key, evenement))

    def traiter_evenement(self, message):
        self.gestionnaire.traiter_cedule(message)


class ExceptionConnectionFermee(Exception):
    pass


class CertificatInconnu(Exception):

    def __init__(self, message, errors=None, fingerprint=None):
        super().__init__(message, errors)
        self.errors = errors
        self.__fingerprint = fingerprint

    @property
    def fingerprint(self):
        return self.__fingerprint

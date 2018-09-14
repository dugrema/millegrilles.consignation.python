# Gestion des messages via Pika.
import codecs
import pika
import json
import uuid
import time


''' 
DAO vers la messagerie
Connection a un moteur de messagerie via Pika.
'''


class PikaDAO:

    def __init__(self, configuration):
        self.configuration = configuration
        self.connectionmq = None
        self.channel = None

        self.inError = True

        self.json_helper = JSONHelper()

    # Connecter au serveur RabbitMQ
    # Le callback est une methode qui va etre appelee lorsqu'un message est recu
    def connecter(self):
        self.connectionmq = pika.BlockingConnection(pika.ConnectionParameters(
            self.configuration.mq_host,
            self.configuration.mq_port))
        self.channel = self.connectionmq.channel()

        return self.connectionmq

    def configurer_rabbitmq(self):

        # S'assurer que toutes les queues existes
        nom_millegrille = self.configuration.nom_millegrille
        nom_echange_evenements = self.configuration.exchange_evenements
        nom_q_nouvelles_transactions = "mg.%s.%s" % (nom_millegrille, self.configuration.queue_nouvelles_transactions)
        nom_q_entree_processus =  "mg.%s.%s" % (nom_millegrille, self.configuration.queue_entree_processus)

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
            exchange = nom_echange_evenements,
            queue=nom_q_nouvelles_transactions,
            routing_key='%s.transaction.nouvelle' % nom_millegrille
        )

        # Creer la Q d'entree de processus (workflows) pour cette MilleGrille
        self.channel.queue_declare(
            queue=nom_q_entree_processus,
            durable=True)

        self.channel.queue_bind(
            exchange = nom_echange_evenements,
            queue=nom_q_entree_processus,
            routing_key='%s.transaction.persistee' % nom_millegrille
        )


    ''' Prepare la reception de message '''
    def demarrer_lecture_nouvelles_transactions(self, callback):
        self.channel.basic_consume(callback,
                                   queue='mg.%s.%s' % (self.configuration.nom_millegrille, self.configuration.queue_nouvelles_transactions),
                                   no_ack=False)

        self.channel.start_consuming()

    ''' Transmet un message. La connexion doit etre ouverte. '''
    def transmettre_message_transaction(self, message_dict):

        if self.connectionmq == None or self.connectionmq.is_closed :
            raise Exception("La connexion Pika n'est pas ouverte")

        enveloppe = self.preparer_enveloppe(message_dict)
        uuid_transaction = enveloppe["info-transaction"]["id-transaction"]
        message_utf8 = self.json_helper.dict_vers_json(enveloppe)

        self.channel.basic_publish(exchange=self.configuration.exchange_evenements,
                              routing_key='%s.transaction.nouvelle' % self.configuration.nom_millegrille,
                              body=message_utf8)

        return uuid_transaction

    def preparer_enveloppe(self, message_dict):

        # Ajouter identificateur unique et temps de la transaction
        uuid_transaction = uuid.uuid1()
        meta = {}
        meta["id-transaction"] = "%s" % uuid_transaction
        meta["estampille"] = int(time.time())
        meta["signature-contenu"] = ""

        enveloppe = {}
        enveloppe["info-transaction"] = meta
        enveloppe["charge-utile"] = message_dict

        return enveloppe

    def transmettre_evenement_persistance(self, id_document, id_transaction):

        message = {"_id": str(id_document), "id-transaction": id_transaction, "evenement": "transaction_persistee"}
        message_utf8 = self.json_helper.dict_vers_json(message)

        self.channel.basic_publish(exchange='millegrilles.evenements',
                              routing_key='%s.transaction.persistee' % self.configuration.nom_millegrille,
                              body=message_utf8)


    # Mettre la classe en etat d'erreur
    def enterErrorState(self):
        self.inError = True

        if self.channel != None:
            try:
                self.channel.stop_consuming()
            except:
                None

        self.deconnecter()

    # Se deconnecter de RabbitMQ
    def deconnecter(self):
        try:
            if self.connectionmq != None:
                self.connectionmq.close()
        finally:
            self.channel = None
            self.connectionmq = None

''' Classe avec utilitaires pour JSON '''


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

    def __init__(self):
        None

    def callbackAvecAck(self, ch, method, properties, body):
        ch.basic_ack(delivery_tag=method.delivery_tag)

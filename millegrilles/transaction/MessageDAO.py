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

        self.reader = codecs.getreader("utf-8")

        self.inError = True

    # Connecter au serveur RabbitMQ
    # Le callback est une methode qui va etre appelee lorsqu'un message est recu
    def connecter(self):
        self.connectionmq = pika.BlockingConnection(pika.ConnectionParameters(
            self.configuration.mq_host,
            self.configuration.mq_port))
        self.channel = self.connectionmq.channel()

        # S'assurer que toutes les queues existes
        self.channel.queue_declare(queue=self.configuration.queue_nouvelles_transactions)

        return self.connectionmq

    ''' Prepare la reception de message '''
    def demarrer_lecture_nouvelles_transactions(self, callback):
        self.channel.basic_consume(callback,
                                   queue=self.configuration.queue_nouvelles_transactions,
                                   no_ack=False)

        self.channel.start_consuming()

    ''' Transmet un message. La connexion doit etre ouverte. '''
    def transmettre_message_transaction(self, message_dict):

        if self.connectionmq == None or self.connectionmq.is_closed :
            raise Exception("La connexion Pika n'est pas ouverte")

        enveloppe = self.preparer_enveloppe(message_dict)
        uuid_transaction = enveloppe["meta"]["id-transaction"]
        message_utf8 = json.dumps(enveloppe, sort_keys=True)

        self.channel.basic_publish(exchange='',
                              routing_key=self.configuration.queue_nouvelles_transactions,
                              body=message_utf8)

        return uuid_transaction

    def preparer_enveloppe(self, message_dict):

        # Ajouter identificateur unique et temps de la transaction
        uuid_transaction = uuid.uuid1()
        meta = {}
        meta["id-transaction"] = "%s" % uuid_transaction
        meta["estampille"] = int(time.time())

        enveloppe = {}
        enveloppe["trmeta"] = meta
        enveloppe["contenu"] = message_dict

        return enveloppe

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


''' 
Classe qui facilite l'implementation de callbacks avec ACK
'''


class BaseCallback:

    def __init__(self):
        None

    def callbackAvecAck(self, ch, method, properties, body):
        ch.basic_ack(delivery_tag=method.delivery_tag)

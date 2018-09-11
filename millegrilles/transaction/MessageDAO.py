''' Gestion des messages via Pika.
'''
import json, time, sys, os, traceback, codecs
import pika

''' DAO vers la messagerie
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
            self.configuration.mqHost,
            self.configuration.mqPort))
        self.channel = self.connectionmq.channel()

        return self.connectionmq

    def preparerQueueNouvellesTransactions(self, callback):
        self.channel.queue_declare(queue=self.configuration.mqQueueNouvellesTransactions)

        self.channel.basic_consume(callback,
                                   queue=self.configuration.mqQueueNouvellesTransactions,
                                   no_ack=False)

        self.channel.start_consuming()


    # Mettre la classe en etat d'erreur
    def enterErrorState(self):
        self.inError = True

        if self.channel != None:
            try:
                self.channel.stop_consuming()
            except:
                None

        self.disconnect()

    # Se deconnecter de RabbitMQ
    def deconnecter(self):
        try:
            if self.connectionmq != None:
                self.connectionmq.close()
        finally:
            self.channel = None
            self.connectionmq = None

''' Classe qui facilite l'implementation de callbacks avec ACK
'''
class BaseCallback:

    def __init__(self):
        None

    def callbackNouvelleTransaction(self, ch, method, properties, body):
        ch.basic_ack(delivery_tag=method.delivery_tag)

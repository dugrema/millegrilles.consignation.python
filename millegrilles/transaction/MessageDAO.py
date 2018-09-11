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
    def connecter(self, callback):
        self.connectionmq = pika.BlockingConnection(pika.ConnectionParameters(self.configuration.mqHost))
        self.channel = self.connectionmq.channel()
        self.channel.queue_declare(queue=self.configuration.mqQueue)

        self.channel.basic_consume(callback,
                                   queue=self.configuration.mqQueue,
                                   no_ack=True)

        self.channel.start_consuming()

        return self.connectionmq

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

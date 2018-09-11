''' Script de test pour transmettre message de transaction

'''

import pika
import json, time

#credentials = pika.PlainCredentials('mathieu', 'p1234')
#connection = pika.BlockingConnection(pika.ConnectionParameters('cuisine', 5674, credentials=credentials))

connection = pika.BlockingConnection( pika.ConnectionParameters('dev2', 5672) )
channel = connection.channel()
channel.queue_declare(queue='transactions')

message = {
    "contenu": "Valeur"
}

message_utf8 = json.dumps(message)

channel.basic_publish(exchange='',
                      routing_key='transactions',
                      body=message_utf8)

print("Sent: %s" % message)

connection.close()

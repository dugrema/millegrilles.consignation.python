# Script de test pour transmettre message de transaction

import datetime, time

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles import Constantes
from millegrilles.domaines.Principale import ConstantesPrincipale
from threading import Thread, Event
import json


contexte = ContexteRessourcesMilleGrilles()
contexte.initialiser(init_document=False)


class MessagesSample(BaseCallback):

    def __init__(self):
        super().__init__(contexte)
        self.contexte.message_dao.register_channel_listener(self)
        self.generateur = GenerateurTransaction(self.contexte)

        self.queue_name = None

        self.channel = None
        self.event_recu = Event()

    def on_channel_open(self, channel):
        # Enregistrer la reply-to queue
        self.channel = channel
        channel.queue_declare(durable=True, exclusive=True, callback=self.queue_open_local)

    def queue_open_local(self, queue):
        self.queue_name = queue.method.queue
        print("Queue: %s" % str(self.queue_name))

        self.channel.basic_consume(self.callbackAvecAck, queue=self.queue_name, no_ack=False)
        self.executer()

    def run_ioloop(self):
        self.contexte.message_dao.run_ioloop()

    def deconnecter(self):
        self.contexte.message_dao.deconnecter()

    def traiter_message(self, ch, method, properties, body):
        print("Message recu, correlationId: %s" % properties.correlation_id)
        message = json.loads(str(body, 'utf-8'))
        print(json.dumps(message, indent=4))

    def transmettre_commande_nouveau_torrent(self):
        commande = {
            'nom': 'ma_collection_figee',
            'securite': '1.public',  # Niveau de securite global du torrent
            'uuid': '7fd1c894-0f15-11ea-bb74-00155d011f09',
            'etiquettes': {},
            'commentaires': "J'aime bian les torrents",
            'documents': [
                {
                    # Contenu equivalent a une transaction millegrilles.domaines.GrosFichiers.nouvelleVersion.metadata
                    # La millegrille qui recoit ce torrent va agir de la meme facon quelle le ferait avec une nouvelle
                    # transaction (qui sera extraite et soumise sur reception du torrent).
                    'uuid': '264ca437-4574-4b1d-8088-142af87a6954',  # uuid fichier
                    'fuuid': '0b6e8fe0-0d63-11ea-80d1-bf0de6b5e47c',
                    # 'fuuid': '50f05190-0d6b-11ea-80d1-bf0de6b5e47c',  # fuuid version
                    'nom': 'Estheticians dont have to wax male genitalia against their will BC tribunal .pdf',
                    'mimetype': 'application/pdf',
                    'securite': '3.protege',
                    "taille": 807264,
                    'sha256': '6f8378ec73a354453dec5c955c617f5295d55fe873cae3d49b3ea87aea13adbd',
                }
            ],
        }
        enveloppe_val = self.generateur.transmettre_commande(
            commande, 'commande.torrent.creerNouveau')

        print("Envoi commande torrent: %s" % enveloppe_val)
        return enveloppe_val

    def transmettre_demande_etat_torrent(self):
        requete = {}
        enveloppe_val = self.generateur.transmettre_requete(
            requete, 'torrent.etat', 'abcd', self.queue_name)

        print("Envoi requete etat torrent: %s" % enveloppe_val)
        return enveloppe_val


    def executer(self):
        # enveloppe = sample.transmettre_commande_nouveau_torrent()
        sample.transmettre_demande_etat_torrent()

# --- MAIN ---
sample = MessagesSample()

# TEST

# FIN TEST
sample.event_recu.wait(5)
sample.deconnecter()


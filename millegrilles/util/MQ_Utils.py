# Utils MQ
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles

import logging

logging.basicConfig()
logging.getLogger('GestionQueues').setLevel(logging.DEBUG)


class GestionQueues:

    LISTE_QUEUES = [
        'entretien_transactions',
        'erreurs_processus',
        'millegrilles.domaines.GrosFichiers.transactions',
        'millegrilles.domaines.MaitreDesCles.ceduleur',
        'millegrilles.domaines.MaitreDesCles.processus',
        'millegrilles.domaines.MaitreDesCles.requete.noeuds',
        'millegrilles.domaines.MaitreDesCles.transactions',
        'millegrilles.domaines.Parametres.ceduleur',
        'millegrilles.domaines.Parametres.processus',
        'millegrilles.domaines.Parametres.requete.noeuds',
        'millegrilles.domaines.Parametres.transactions',
        'millegrilles.domaines.Pki',
        'millegrilles.domaines.Pki.ceduleur',
        'millegrilles.domaines.Pki.certificats',
        'millegrilles.domaines.Pki.processus',
        'millegrilles.domaines.Pki.requete.noeuds',
        'millegrilles.domaines.Pki.transactions',
        'millegrilles.domaines.Plume.ceduleur',
        'millegrilles.domaines.Plume.processus',
        'millegrilles.domaines.Plume.requete.noeuds',
        'millegrilles.domaines.Plume.transactions',
        'millegrilles.domaines.Principale',
        'millegrilles.domaines.Principale.ceduleur',
        'millegrilles.domaines.Principale.inter',
        'millegrilles.domaines.Principale.noeuds',
        'millegrilles.domaines.Principale.processus',
        'millegrilles.domaines.Principale.requete.noeuds',
        'millegrilles.domaines.Principale.transactions',
        'millegrilles.domaines.SenseursPassifs',
        'millegrilles.domaines.SenseursPassifs.ceduleur',
        'millegrilles.domaines.SenseursPassifs.inter',
        'millegrilles.domaines.SenseursPassifs.noeuds',
        'millegrilles.domaines.SenseursPassifs.processus',
        'millegrilles.domaines.SenseursPassifs.requete.noeuds',
        'millegrilles.domaines.SenseursPassifs.transactions',
        'nouvelles_transactions',
    ]

    def __init__(self):
        self.contexte = ContexteRessourcesMilleGrilles()
        self.contexte.initialiser(init_message=True)
        self.contexte.message_dao.register_channel_listener(self)
        self.channel = None

    def on_channel_open(self, channel):
        self.channel = channel
        self.executer()

    def executer(self):
        self.supprimer_queues()
        # self.contexte.message_dao.deconnecter()

    def supprimer_queues(self):
        channel = self.channel
        # channel.queue_delete(queue=GestionQueues.LISTE_QUEUES[0], callback=self.print)
        for queue in GestionQueues.LISTE_QUEUES:
            channel.queue_delete(queue=queue, callback=self.print)

    def print(self, arg1):
        print(str(arg1))

GestionQueues()

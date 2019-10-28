# Script de test pour transmettre message de transaction

import datetime, time

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles import Constantes
from millegrilles.domaines.Principale import ConstantesPrincipale

from millegrilles.util.BaseSendMessage import BaseEnvoyerMessageEcouter


class MessagesSample(BaseEnvoyerMessageEcouter):

    def __init__(self):
        super().__init__()

    def transmettre_lecture(self):
        temps_lecture = datetime.datetime.now()
        # temps_lecture_ajuste = temps_lecture + datetime.timedelta(hours=4)

        senseurs = [
            {
                "humidite": 31.6,
                "temperature": 26,
                "type": "am2302",
            },
            {
                "humidite": 20,
                "temperature": 27,
                "type": "th",
            },
            {
                "pression": 99.8,
                "temperature": 38,
                "type": "tp",
            },
            {
                "temperature": None,
                "type": "onewire/temperature",
                "adresse": '2854ab799711030c'
            },
            {
                "temperature": None,
                "type": "tpvide",
            },

        ]

        message_dict = dict()
        message_dict['uuid_senseur'] = 'f14951f2f43211e99259b827eb53ee51'
        message_dict['noeud'] = 'domaine_SenseursPassifs'
        message_dict['timestamp'] = int(temps_lecture.timestamp())
        message_dict['senseurs'] = senseurs

        enveloppe_val = self.generateur.soumettre_transaction(
            message_dict, 'millegrilles.domaines.SenseursPassifs.lecture', reply_to=self.queue_name, correlation_id='efgh')

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def changer_nom(self):
        temps_lecture = datetime.datetime.now()
        # temps_lecture_ajuste = temps_lecture + datetime.timedelta(hours=4)

        message_dict = {
            'senseur': 5,
            'noeud': 'domaine_SenseursPassifs',
            'location': "Bazaar"
        }

        enveloppe_val = self.generateur.soumettre_transaction(
            message_dict,
            'millegrilles.domaines.SenseursPassifs.changementAttributSenseur',
            reply_to=self.queue_name,
            correlation_id='efgh'
        )

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def supprimer_senseur(self):
        temps_lecture = datetime.datetime.now()
        # temps_lecture_ajuste = temps_lecture + datetime.timedelta(hours=4)

        message_dict = {
            'senseurs': [6, 7],
            'noeud': 'domaine_SenseursPassifs',
        }

        enveloppe_val = self.generateur.soumettre_transaction(
            message_dict,
            'millegrilles.domaines.SenseursPassifs.suppressionSenseur',
            reply_to=self.queue_name,
            correlation_id='efgh'
        )

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def requete_profil_usager(self):
        requete_profil = {
            'filtre': {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPrincipale.LIBVAL_PROFIL_USAGER,
            }
        }
        requetes = {'requetes': [requete_profil]}
        enveloppe_requete = self.generateur.transmettre_requete(
            requetes, 'millegrilles.domaines.Principale', reply_to=self.queue_name, correlation_id='abcd-1234')

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

# --- MAIN ---
sample = MessagesSample()

# TEST
enveloppe = sample.transmettre_lecture()
# enveloppe = sample.changer_nom()
# enveloppe = sample.supprimer_senseur()

sample.recu.wait(60)

# FIN TEST
sample.deconnecter()

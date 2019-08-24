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

        message_dict = dict()
        message_dict['senseur'] = 8
        message_dict['noeud'] = 'domaine_SenseursPassifs'
        message_dict['temps_lecture'] = int(temps_lecture.timestamp())
        message_dict['temperature'] = 32.1
        message_dict['humidite'] = 67.3
        message_dict['pression'] = 103.3
        message_dict['bat_mv'] = 3498
        message_dict['hachi-parmentier'] = '5G_ Washington appelle à la prudence Techno.pdf'

        message = {
            "fuuid": "5a9dda40-c618-11e9-9c91-472b85679e72", "securite": "2.prive",
             "repertoire_uuid": "b6138062-c5de-11e9-b6d2-02420a0000d7",
             "nom": "5G_ Washington appelle à la prudence Techno.pdf", "taille": 565352, "mimetype": "application/pdf",
             "reception": {"methode": "coupdoeil", "noeud": "public1.maple.mdugre.info"},

        }

        enveloppe_val = self.generateur.soumettre_transaction(
            message, 'millegrilles.domaines.SenseursPassifs.lecture', reply_to=self.queue_name, correlation_id='efgh')

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

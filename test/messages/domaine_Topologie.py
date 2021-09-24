# Script de test pour transmettre message de transaction


# Script de test pour transmettre message de transaction

import datetime
import time
import json
import base64
import binascii

from millegrilles import Constantes
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles.domaines.Topologie import ConstantesTopologie
from millegrilles.util.Chiffrage import ChiffrerChampDict, DechiffrerChampDict
from millegrilles.util.BaseTestMessages import DomaineTest

from threading import Thread, Event


contexte = ContexteRessourcesMilleGrilles()
contexte.initialiser()

NOEUD_ID = '43eee47d-fc23-4cf5-b359-70069cf06600'


class MessagesSample(DomaineTest):

    def __init__(self):
        super().__init__(contexte)
        # self.contexte.message_dao.register_channel_listener(self)
        self.generateur = GenerateurTransaction(self.contexte)

        # self.channel = None
        # self.event_recu = Event()

    # def on_channel_open(self, channel):
    #     # Enregistrer la reply-to queue
    #     self.channel = channel
    #     channel.queue_declare(durable=True, exclusive=True, callback=self.queue_open_local)
    #
    # def queue_open_local(self, queue):
    #     self.queue_name = queue.method.queue
    #     print("Queue: %s" % str(self.queue_name))
    #
    #     self.channel.basic_consume(self.callbackAvecAck, queue=self.queue_name, no_ack=False)
    #     self.executer()
    #
    # def run_ioloop(self):
    #     self.contexte.message_dao.run_ioloop()
    #
    # def deconnecter(self):
    #     self.contexte.message_dao.deconnecter()
    #
    # def traiter_message(self, ch, method, properties, body):
    #     print("Message recu, correlationId: %s" % properties.correlation_id)
    #     print(json.dumps(json.loads(body.decode('utf-8')), indent=4))
    #     print("Channel : " + str(ch))
    #     print("Method : " + str(method))
    #     print("Properties : " + str(properties))
    #     print("Channel virtual host : " + str(ch.connection.params.virtual_host))

    def requete_liste_domaines(self):
        requete = {}
        domaine_action = ConstantesTopologie.REQUETE_LISTE_DOMAINES
        enveloppe_val = self.generateur.transmettre_requete(
            requete,
            'CoreTopologie',
            action='listeDomaines',
            reply_to=self.queue_name,
            correlation_id='efgh'
        )
        print("Envoi metadata: %s" % enveloppe_val)

    def requete_liste_noeuds(self):
        requete = {}  # {"noeud_id": "36652245-1c1a-4686-8686-21dcebbdf43f"}
        enveloppe_val = self.generateur.transmettre_requete(
            requete,
            'CoreTopologie',
            action='listeNoeuds',
            reply_to=self.queue_name,
            correlation_id='efgh',
            securite=Constantes.SECURITE_PROTEGE
        )
        print("Envoi metadata: %s" % enveloppe_val)

    def requete_liste_applications(self):
        requete = {}
        # domaine_action = ConstantesTopologie.REQUETE_LISTE_APPLICATIONS_DEPLOYEES
        # enveloppe_val = self.generateur.transmettre_requete(
        #     requete, domaine_action,
        #     reply_to=self.queue_name, correlation_id='efgh')
        enveloppe_val = self.generateur.transmettre_requete(
            requete,
            'CoreTopologie',
            action='listeApplicationsDeployees',
            reply_to=self.queue_name, correlation_id='efgh',
            securite=Constantes.SECURITE_PRIVE
        )
        print("Envoi metadata: %s" % enveloppe_val)

    def requete_liste_noeud_detail(self):
        requete = {
            'noeud_id': NOEUD_ID,
            'all_info': True,
        }
        domaine_action = ConstantesTopologie.REQUETE_LISTE_NOEUDS
        enveloppe_val = self.generateur.transmettre_requete(
            requete, domaine_action,
            reply_to=self.queue_name, correlation_id='efgh')
        print("Envoi metadata: %s" % enveloppe_val)

    def requete_info_domaine(self):
        requete = {'domaine': 'CatalogueApplications'}
        domaine_action = ConstantesTopologie.REQUETE_INFO_DOMAINE
        enveloppe_val = self.generateur.transmettre_requete(
            requete, domaine_action,
            reply_to=self.queue_name, correlation_id='efgh')
        print("Envoi metadata: %s" % enveloppe_val)

    def requete_info_noeud(self):
        requete = {'noeud_id': '5e9e7984-7828-4a1d-8740-74fbf9676e0c'}
        domaine_action = ConstantesTopologie.REQUETE_INFO_NOEUD
        enveloppe_val = self.generateur.transmettre_requete(
            requete, domaine_action,
            reply_to=self.queue_name, correlation_id='efgh')
        print("Envoi metadata: %s" % enveloppe_val)

    def requete_neuds_awss3(self):
        domaine_action = 'requete.Topologie.' + ConstantesTopologie.REQUETE_LISTE_NOEUDS_AWSS3
        enveloppe_val = self.generateur.transmettre_requete(
            dict(), domaine_action,
            reply_to=self.queue_name, correlation_id='efgh')
        print("Envoi metadata: %s" % enveloppe_val)

    def transaction_ajouter_domaine(self):
        requete = {
            'noeud_id': '5ee16193-49a3-443f-ae4e-894a65de647d',
            "nom": "SenseursPassifs",
            "module": "millegrilles.domaines.SenseursPassifs",
            "classe": "GestionnaireSenseursPassifs"
        }
        domaine_action = ConstantesTopologie.TRANSACTION_AJOUTER_DOMAINE_DYNAMIQUE
        enveloppe_val = self.generateur.soumettre_transaction(
            requete, domaine_action,
            reply_to=self.queue_name, correlation_id='efgh')
        print("Envoi metadata: %s" % enveloppe_val)

    def transaction_supprimer_domaine(self):
        requete = {
            'noeud_id': '5ee16193-49a3-443f-ae4e-894a65de647d',
            "nom": "SenseursPassifs",
        }
        domaine_action = ConstantesTopologie.TRANSACTION_SUPPRIMER_DOMAINE_DYNAMIQUE
        enveloppe_val = self.generateur.soumettre_transaction(
            requete, domaine_action,
            reply_to=self.queue_name, correlation_id='efgh')
        print("Envoi metadata: %s" % enveloppe_val)

    def transaction_consignation_web(self):
        noeud_id = '5e9e7984-7828-4a1d-8740-74fbf9676e0c'
        access_key = 'DADAXXXAAABBBCCCC000DADA'

        indicateurs_document = {
            'libelle': ConstantesTopologie.LIBVAL_NOEUD,
            ConstantesTopologie.CHAMP_NOEUDID: noeud_id,
            'champ': ConstantesTopologie.CHAMP_CONSIGNATION_WEB + '.' + ConstantesTopologie.CHAMP_AWSS3_CREDENTIALS_ACCESSKEY,
        }

        self.event_recu.clear()
        self.generateur.transmettre_requete(
            dict(),
            Constantes.ConstantesMaitreDesCles.DOMAINE_NOM + '.' + Constantes.ConstantesMaitreDesCles.REQUETE_CERT_MAITREDESCLES,
            reply_to=self.queue_name,
            correlation_id='test',
        )
        self.event_recu.wait(3)
        cert_maitrecles = self.messages.pop()

        chiffreur = ChiffrerChampDict(self.contexte)
        access_key_chiffre = chiffreur.chiffrer(cert_maitrecles, ConstantesTopologie.DOMAINE_NOM, indicateurs_document, access_key)

        transaction = {
            ConstantesTopologie.CHAMP_NOEUDID: noeud_id,

            ConstantesTopologie.CHAMP_CONSIGNATION_WEB_MODE: ConstantesTopologie.VALEUR_AWSS3_CONSIGNATION_WEB_AWSS3,
            # ConstantesTopologie.CHAMP_AWSS3_CREDENTIALS_REGION: 'us-east-2',
            # ConstantesTopologie.CHAMP_AWSS3_CREDENTIALS_ACCESSID: 'AKIA2JHYIVE5O2ZXZNA6',
            ConstantesTopologie.CHAMP_AWSS3_BUCKET_REGION: 'us-east-1',
            # ConstantesTopologie.CHAMP_AWSS3_BUCKET_NAME: 'millegrilles-site1',
            # ConstantesTopologie.CHAMP_AWSS3_BUCKET_DIRFICHIER: 'QME8SjhaCFySD9qBt1AikQ1U7WxieJY2xDg2JCMczJST/public',

            ConstantesTopologie.CHAMP_AWSS3_CREDENTIALS_ACCESSKEY: access_key_chiffre['contenu'],
        }

        # Emettre transaction deja signee avec les cles asymetriques
        transaction_maitrecles = access_key_chiffre['maitrecles']
        domaine_action = 'transaction.' + transaction_maitrecles['en-tete']['domaine']
        self.generateur.emettre_message(transaction_maitrecles, domaine_action)

        # Soumettre transaction avec le secret chiffre
        domaine_action = ConstantesTopologie.DOMAINE_NOM + '.' + ConstantesTopologie.TRANSACTION_CONFIGURER_CONSIGNATION_WEB
        self.generateur.soumettre_transaction(
            transaction, domaine_action,
            reply_to=self.queue_name, correlation_id='efgh')

    def dechiffrer_secret_consignation_web(self):

        # Demander permission de dechiffrage a topologie - forward a maitre des cles pour reourner reponse
        # Meme approche que pour dechiffrer un grosfichier

        noeud_id = '5e9e7984-7828-4a1d-8740-74fbf9676e0c'
        identificateurs_document = {
            'libelle': ConstantesTopologie.LIBVAL_NOEUD,
            ConstantesTopologie.CHAMP_NOEUDID: noeud_id,
            'champ': ConstantesTopologie.CHAMP_CONSIGNATION_WEB + '.' + ConstantesTopologie.CHAMP_AWSS3_CREDENTIALS_ACCESSKEY,
        }

        self.event_recu.clear()
        self.generateur.transmettre_requete(
            {'identificateurs_document': identificateurs_document},
            ConstantesTopologie.DOMAINE_NOM + '.' + ConstantesTopologie.REQUETE_PERMISSION,
            reply_to=self.queue_name,
            correlation_id='test',
            ajouter_certificats=True,
        )
        self.event_recu.wait(3)
        permission = self.messages.pop()
        self.event_recu.clear()

        signateur = self.contexte.signateur_transactions
        iv_base64 = permission['iv']
        secret_base64 = permission['cle']
        password_bytes = signateur.dechiffrage_asymmetrique(secret_base64)
        # password_bytes = binascii.unhexlify(password_bytes)

        # Dechiffrer secret
        contenu = {
            'secret_chiffre': "s8PvG7YfVEdwjoH2LR63wkGfihYGdlomEkdn8echLGhmwNwk8YjlLBSrAogtSFFw"
        }

        dechiffreur = DechiffrerChampDict(self.contexte)
        contenu_dechiffre = dechiffreur.dechiffrer(contenu, iv_base64, password_bytes)

        print("Contenu dechiffre : %s" % contenu_dechiffre)

    def executer(self):
        sample.requete_liste_domaines()
        # sample.requete_liste_noeuds()
        # sample.requete_liste_applications()
        # sample.requete_liste_noeud_detail()
        # sample.requete_info_domaine()
        # sample.requete_info_noeud()
        # sample.transaction_ajouter_domaine()
        # sample.transaction_supprimer_domaine()
        # self.transaction_consignation_web()
        # self.dechiffrer_secret_consignation_web()
        # self.requete_neuds_awss3()

# --- MAIN ---
sample = MessagesSample()

# TEST

# FIN TEST
Event().wait(120)
sample.deconnecter()

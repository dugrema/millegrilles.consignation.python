# Script de test pour transmettre message de transaction

import datetime, time
import json
from uuid import uuid4

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles import Constantes
from millegrilles.Constantes import ConstantesGrosFichiers
from threading import Thread, Event


contexte = ContexteRessourcesMilleGrilles()
contexte.initialiser()


class MessagesSample(BaseCallback):

    def __init__(self):
        super().__init__(contexte)
        self.contexte.message_dao.register_channel_listener(self)
        self.generateur = GenerateurTransaction(self.contexte)

        self.fichier_fuuid = "39c1e1b0-b6ee-11e9-b0cd-d30e8fab842j"

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
        reponse = json.loads(body.decode('utf-8'))
        print(json.dumps(reponse, indent=2))

    def transaction_nouvelle_version_metadata(self):
        transaction = {
            'nom_fichier': 'Bill Morneau resigns as finance minister and MP, will seek to lead OECD.pdf',
            'securite': '3.protege',
            'fuuid': str(uuid4()),
            'mimetype': 'image/blarghs',
            'taille': 1190698,
            'hachage': 'sha512_b64:ONOJGqswORDLwxeB/82dewqx2kAyOD0k3YQkipbkCBt3CyYAqk6BwAPw+sAFLo8BmRmLvNGlpmnnuFPs0hAmfg==',
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, ConstantesGrosFichiers.TRANSACTION_NOUVELLEVERSION_METADATA,
            reply_to=self.queue_name, correlation_id='efgh')

        print("Envoi metadata: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_nouvelle_version_transfertcomplete(self):
        transaction = {
            "fuuid": self.fichier_fuuid,
            "sha256": "739291ef2f7f3e0f945712112df9a62aeb2642d3828551f9fa3c95449a415e30",
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.nouvelleVersion.transfertComplete',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Envoi transfert complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_renommer_document(self):
        transaction = {
            "uuid": "ea1e1a37-14ef-46f4-8a75-021850e0630a",
            "nom": 'Bashir Bouzouka 3!.jpg',
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, ConstantesGrosFichiers.TRANSACTION_RENOMMER_DOCUMENT,
            reply_to=self.queue_name, correlation_id='abcd')

        print("Renommer repertoire complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_changer_etiquettes_fichier(self):
        transaction = {
            "uuid": "1385e685-0630-4372-87a0-224804dfe7fd",
            "etiquettes": ['efgh', '1234', 'pUBlic', '4.disseminer', 'HÉ! ayoye mé açcents']
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.changerEtiquettesFichier',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Changer libelle complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_decrire_fichier(self):
        transaction = {
            "uuid": "41548d46-c12b-41f6-b205-4c0ae7d64c16",
            "commentaires": "J'ai un commentaire. Ye! Pis on en rajoute.",
            "titre": {'en': 'Name in English', 'fr': 'Nom en francais'},
            "description": {
                'en': 'Complete description of the file',
                'fr': 'Description complete du fichier',
            }
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'GrosFichiers.' + ConstantesGrosFichiers.TRANSACTION_DECRIRE_DOCUMENT,
            reply_to=self.queue_name, correlation_id='abcd'
        )

        print("Renommer repertoire complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_supprimer_fichier(self):
        transaction = {
            ConstantesGrosFichiers.DOCUMENT_LISTE_UUIDS: [
                "53aca732-fa3c-4e21-9462-e01e5157741a"
            ],
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, ConstantesGrosFichiers.TRANSACTION_SUPPRIMER_FICHIER,
            reply_to=self.queue_name, correlation_id='abcd')

        print("Renommer repertoire complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_recuperer_fichier(self):
        transaction = {
            ConstantesGrosFichiers.DOCUMENT_LISTE_UUIDS: [
                "53aca732-fa3c-4e21-9462-e01e5157741a"
            ],
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, ConstantesGrosFichiers.TRANSACTION_RECUPERER_FICHIER,
            reply_to=self.queue_name, correlation_id='abcd')

        print("Renommer repertoire complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_creer_collection_vide(self):
        transaction = {
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.nouvelleCollection',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Complete : %s" % enveloppe_val)
        return enveloppe_val

    def transaction_creer_collection_2docs(self):
        transaction = {
            "documents": [
                {'uuid': 'b63c5771-d2c8-4d5c-9db5-fdbe0a35ac36'},
                {'uuid': 'ff754f4a-6df1-4fbc-ab64-70693c7c487f'},
            ]
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.nouvelleCollection',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Complete : %s" % enveloppe_val)
        return enveloppe_val

    def transaction_renommer_collection(self):
        transaction = {
            "uuid": "0fda4ce6-0ecf-11ea-bb74-00155d011f09",
            "nom": "sous_test_change_2",
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.renommerCollection',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Renommer repertoire complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_supprimer_collection(self):
        transaction = {
            "uuid": "0fda4ce6-0ecf-11ea-bb74-00155d011f09",
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.supprimerCollection',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Renommer repertoire complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_recuperer_collection(self):
        transaction = {
            "uuid": "0fda4ce6-0ecf-11ea-bb74-00155d011f09",
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.recupererCollection',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Renommer repertoire complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_figer_collection(self):
        transaction = {
            "uuid": "a80c39cc-16ca-11ea-9318-00155d011f09",
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.figerCollection',
            reply_to=self.queue_name, correlation_id='abcd')

        print("transaction_figer_collection: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_changer_etiquettes_collection(self):
        transaction = {
            "uuid": "a80c39cc-16ca-11ea-9318-00155d011f09",
            "etiquettes": ['abcd', '1234']
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'millegrilles.domaines.GrosFichiers.changerEtiquettesCollection',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Renommer repertoire complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_ajouter_fichiers_collection(self):
        transaction = {
            "uuid": "5edceede-f77c-11ea-8eb7-ff28b56f498d",
            ConstantesGrosFichiers.DOCUMENT_COLLECTION_DOCS_UUIDS: [
                'ab13c39c-35e4-4f60-a353-ef2b63d92c54',
            ]
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, 'GrosFichiers.ajouterFichiersCollection',
            reply_to=self.queue_name, correlation_id='abcd')

        print("Renommer repertoire complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_retirer_fichiers_collection(self):
        transaction = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: "862a4348-b85a-4ab7-8021-ca26c9bb58bf",
            ConstantesGrosFichiers.DOCUMENT_COLLECTION_DOCS_UUIDS: [
                '53aca732-fa3c-4e21-9462-e01e5157741a',
            ]
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, ConstantesGrosFichiers.TRANSACTION_RETIRER_FICHIERS_COLLECTION,
            reply_to=self.queue_name, correlation_id='abcd')

        print("Renommer repertoire complete: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_changer_favoris(self):
        transaction = {
            ConstantesGrosFichiers.DOCUMENT_COLLECTION_DOCS_UUIDS: {
                'b212db7f-27f7-4d1e-bba2-5b2293e4d9ea': False,
                '2ca533be-c463-4cc3-b729-5bf34f53c623': True,
            }
        }

        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, ConstantesGrosFichiers.TRANSACTION_CHANGER_FAVORIS,
            reply_to=self.queue_name, correlation_id='abcd')

        print("Ajouter favori: %s" % enveloppe_val)
        return enveloppe_val

    def requete_activite(self):
        requete = {
            'skip': 0,
            'limit': 3,
        }

        enveloppe_val = self.generateur.transmettre_requete(
            requete, Constantes.ConstantesGrosFichiers.REQUETE_ACTIVITE_RECENTE,
            reply_to=self.queue_name, correlation_id='abcd')

        print("Activite recente %s" % enveloppe_val)
        return enveloppe_val

    def requete_corbeille(self):
        requete = {
            'skip': 0,
            'limit': 3,
        }

        enveloppe_val = self.generateur.transmettre_requete(
            requete, Constantes.ConstantesGrosFichiers.REQUETE_CORBEILLE,
            reply_to=self.queue_name, correlation_id='abcd')

        print("Activite recente %s" % enveloppe_val)
        return enveloppe_val

    def requete_documents_collection(self):
        requete = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: '5edceede-f77c-11ea-8eb7-ff28b56f498d',
            'skip': 1,
            'limit': 2,
            'sort_keys': ['nom_collection', 'nom_fichier']
        }
        enveloppe_val = self.generateur.transmettre_requete(
            requete, Constantes.ConstantesGrosFichiers.REQUETE_CONTENU_COLLECTION,
            reply_to=self.queue_name, correlation_id='abcd')

        print("requete_documents_collection %s" % enveloppe_val)
        return enveloppe_val

    def requete_documents_par_uuid(self):
        requete = {
            ConstantesGrosFichiers.DOCUMENT_LISTE_UUIDS: ['5edceede-f77c-11ea-8eb7-ff28b56f498d'],
        }
        enveloppe_val = self.generateur.transmettre_requete(
            requete, Constantes.ConstantesGrosFichiers.REQUETE_DOCUMENTS_PAR_UUID,
            reply_to=self.queue_name, correlation_id='abcd')

        print("requete_documents_collection %s" % enveloppe_val)
        return enveloppe_val

    def transaction_associer_preview(self):
        transaction = {
            'uuid': 'af6606b0-fac9-11ea-af1c-37323461d64a',
            'fuuid': '40b268a7-2af4-4424-97ff-cb2a3610b7a1',
            ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE_PREVIEW: 'image/blarghs',
            ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW: str(uuid4()),
        }
        enveloppe_val = self.generateur.soumettre_transaction(
            transaction, ConstantesGrosFichiers.TRANSACTION_ASSOCIER_PREVIEW,
            reply_to=self.queue_name, correlation_id='efgh')

        print("Envoi metadata: %s" % enveloppe_val)
        return enveloppe_val

    def requete_decryptage_cle_fuuid(self):
        requete_cert_maitredescles = {
            'fuuid': "ddb0d8f0-f7b4-11ea-89ec-13126005a8b0"
        }
        enveloppe_requete = self.generateur.transmettre_requete(
            requete_cert_maitredescles,
            'MaitreDesCles.%s' % Constantes.ConstantesMaitreDesCles.REQUETE_DECRYPTAGE_GROSFICHIER,
            'abcd-1234',
            self.queue_name
        )

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def requete_permission_decryptage_cle_fuuid(self):
        # mq_cert = self.configuration.mq_certfile
        # with open(mq_cert, 'r') as fichier:
        #     mq_certfile = fichier.read()

        signateur = self.contexte.signateur_transactions
        certs = signateur.chaine_certs

        # certs = signateur.split_chaine_certificats(mq_certfile)

        requete_cert_maitredescles = {
            'fuuid': "ddb0d8f0-f7b4-11ea-89ec-13126005a8b0",
            'roles_permis': ['domaines'],
            '_certificat_tiers': certs
        }
        enveloppe_requete = self.generateur.transmettre_requete(
            requete_cert_maitredescles,
            'MaitreDesCles.%s' % Constantes.ConstantesMaitreDesCles.REQUETE_DECRYPTAGE_GROSFICHIER,
            'abcd-1234',
            self.queue_name
        )

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def executer(self):
        # enveloppe = sample.requete_profil_usager()

        # enveloppe1 = sample.transaction_nouvelle_version_metadata()
        # enveloppe2 = sample.transaction_nouvelle_version_transfertcomplete()
        # enveloppe6 = sample.transaction_renommer_fichier()
        # enveloppe11 = sample.transaction_commenter_fichier()
        # enveloppe8 = sample.transaction_changer_etiquettes_fichier()
        # enveloppe = sample.transaction_supprimer_fichier()
        # enveloppe = sample.transaction_recuperer_fichier()

        # enveloppe3 = sample.transaction_creer_collection_vide()
        # enveloppe3 = sample.transaction_creer_collection_2docs()
        # enveloppe4 = sample.transaction_renommer_collection()
        # enveloppe7 = sample.transaction_ajouter_fichiers_collection()
        # enveloppe7 = sample.transaction_retirer_fichiers_collection()
        # enveloppe = sample.transaction_changer_etiquettes_collection()
        # enveloppe5 = sample.transaction_figer_collection()
        # enveloppe5 = sample.transaction_supprimer_collection()
        # enveloppe5 = sample.transaction_recuperer_collection()

        # enveloppe = sample.transaction_changer_favoris()

        # enveloppe1 = sample.transaction_nouvelle_version_metadata()
        # enveloppe = sample.requete_activite()
        # enveloppe = sample.requete_corbeille()
        # enveloppe = sample.requete_documents_collection()
        # enveloppe = sample.requete_documents_par_uuid()
        # enveloppe = sample.transaction_associer_preview()
        # sample.requete_decryptage_cle_fuuid()
        # sample.requete_permission_decryptage_cle_fuuid()
        # sample.transaction_renommer_document()
        sample.transaction_decrire_fichier()

        pass


# --- MAIN ---
sample = MessagesSample()

# TEST

# FIN TEST
sample.event_recu.wait(10)
sample.deconnecter()


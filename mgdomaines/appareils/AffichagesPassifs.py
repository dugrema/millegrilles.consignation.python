# Affichages sans interaction/boutons qui sont controles via documents ou timers.
import traceback
import datetime
import logging
import time
from threading import Thread, Event

# from pymongo.errors import OperationFailure, ServerSelectionTimeoutError
# from bson import ObjectId

from millegrilles import Constantes
from millegrilles.domaines.SenseursPassifs import SenseursPassifsConstantes
from millegrilles.dao.MessageDAO import BaseCallback


class DocumentCallback(BaseCallback):
    """
    Sauvegarde le document recu s'il fait parti de la liste.
    """

    def __init__(self, contexte, documents, liste_ids):
        super().__init__(contexte)
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))
        self.documents = documents
        self.liste_ids = liste_ids

    def traiter_message(self, ch, method, properties, body):
        message_json = self.decoder_message_json(body)
        routing_key = method.routing_key

        self.__logger.debug("Message recu: routing=%s, contenu=%s" % (routing_key, str(message_json)))

        # Determiner type de message
        documents = list()
        if routing_key.startswith('noeuds.source.millegrilles_domaines_SenseursPassifs.documents'):
            # Probablement une mise a jour d'un document existant
            documents = [message_json]
            document_keys = self.documents.keys()
            for document in documents:
                doc_id = document.get("_id")
                if doc_id in document_keys:
                    self.__logger.debug("Accepte document _id:%s" % doc_id)
                    self.documents[doc_id] = document
        elif properties.correlation_id == 'etat_senseurs_initial':
            self.__logger.info("Recu message d'etat des senseurs initial")
            self.__logger.debug("%s" % str(message_json))
            for reponse in message_json.get('resultats'):
                for document in reponse:
                    documents.append(document)
                    self.documents[document.get('_id')] = document


# Affichage qui se connecte a un ou plusieurs documents et recoit les changements live
class AfficheurDocumentMAJDirecte:

    # :params intervalle_secs: Intervalle (secondes) entre rafraichissements si watch ne fonctionne pas.
    def __init__(self, contexte, intervalle_secs=30):
        self._contexte = contexte
        self._documents = dict()
        self._intervalle_secs = intervalle_secs
        self._intervalle_erreurs_secs = 60  # Intervalle lors d'erreurs
        self._cycles_entre_rafraichissements = 20  # 20 Cycles
        self._age_donnee_expiree = 120  # Secondes pour considerer une lecture comme expiree (stale)
        self._stop_event = Event()  # Evenement qui indique qu'on arrete la thread

        # self._collection = None
        # self._curseur_changements = None  # Si None, on fonctionne par timer
        # self._watch_desactive = False  # Si true, on utilise watch. Sinon on utilise le timer
        self._thread_maj_document = None
        self._thread_watchdog = None  # Thread qui s'assure que les connexions fonctionnent
        self._compteur_cycle = 0  # Utilise pour savoir quand on rafraichit, tente de reparer connexion, etc.
        self._age_donnee_expiree_timedelta = datetime.timedelta(seconds=self._age_donnee_expiree)

        self.channel = None
        self._queue_reponse = None

        self.traitement_callback = None

        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def start(self):
        # Enregistrer callback
        self.traitement_callback = DocumentCallback(self._contexte, self._documents, self.get_filtre())
        self.contexte.message_dao.register_channel_listener(self)   # Callback sur on_channel_open avec le channel

    def on_channel_open(self, channel):
        self.channel = channel

        # Creer la Q de callback, listener pour documents
        self.channel.queue_declare(queue='', exclusive=True, callback=self.callback_inscrire)

    def callback_inscrire(self, queue):
        nom_queue = queue.method.queue
        self._queue_reponse = nom_queue
        self.__logger.info("Resultat creation queue: %s" % nom_queue)
        routing_key = "%s.#" % SenseursPassifsConstantes.QUEUE_ROUTING_CHANGEMENTS
        self.channel.queue_bind(queue=nom_queue, exchange=self._contexte.configuration.exchange_noeuds, routing_key=routing_key, callback=None)
        tag_queue = self.channel.basic_consume(self.traitement_callback.callbackAvecAck, queue=nom_queue, no_ack=False)
        self.__logger.debug("Tag queue: %s" % tag_queue)

        self.initialiser_documents()

    def reconnecter(self):
        self.contexte.message_dao.deconnecter()
        self._stop_event.set()
        time.sleep(0.5)
        self._stop_event.clear()
        self._stop_event.wait(10)  # Attendre 10 secondes et ressayer du debut
        self.contexte.message_dao.connecter()
        self.start()

    def fermer(self):
        self._stop_event.set()
        self._contexte.message_dao.deconnecter()

    def get_filtre(self):
        raise NotImplemented('Doit etre implementee dans la sous-classe')

    def initialiser_documents(self):
        self.charger_documents()  # Charger une version initiale des documents

    def charger_documents(self):
        # Charger la version la plus recente de chaque document
        requete = {'requetes': [{
            'type': 'mongodb',
            "filtre": self.get_filtre()
        }]}

        try:
            self._contexte.generateur_transactions.transmettre_requete(
                requete,
                'millegrilles.domaines.SenseursPassifs',
                'etat_senseurs_initial',
                self._queue_reponse)
        except Exception as e:
            self.__logger.exception("Erreur transmission requete documents", e)

    def get_documents(self):
        return self._documents

    @property
    def contexte(self):
        return self._contexte


# Classe qui charge des senseurs pour afficher temperature, humidite, pression/tendance
# pour quelques senseurs passifs.
class AfficheurSenseurPassifTemperatureHumiditePression(AfficheurDocumentMAJDirecte):

    taille_ecran = 16
    taille_titre_tph = taille_ecran - 11
    taille_titre_press = taille_ecran - 10

    ligne_expiree_format = "{location:<%d} <Expire>" % taille_titre_press
    ligne_tph_format = "{location:<%d} {temperature: 5.1f}C/{humidite:2.0f}%%" % taille_titre_tph
    ligne_pression_format = "{titre:<%d} {pression:5.1f}kPa{tendance}" % taille_titre_press

    def __init__(self, contexte, senseur_ids, intervalle_secs=30):
        super().__init__(contexte, intervalle_secs)
        self._senseur_ids = senseur_ids
        self._thread_affichage = None
        self._thread_horloge = None
        self._horloge_event = Event()  # Evenement pour synchroniser l'heure
        self._lignes_ecran = None
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def get_collection(self):
        return self.contexte.document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_DOCUMENTS_NOM)

    def get_filtre(self):
        filtre = {
            "_mg-libelle": "senseur.individuel",
            "senseur": {
                "$in": [senseur for senseur in self._senseur_ids]
            }
        }
        return filtre

    def start(self):
        super().start()  # Demarre thread de lecture de documents
        self._thread_horloge = Thread(target=self.set_horloge_event)
        self._thread_horloge.start()

        # Thread.start
        self._thread_affichage = Thread(target=self.run_affichage)
        self._thread_affichage.start()
        logging.info("AfficheurDocumentMAJDirecte: thread demarree")

    def set_horloge_event(self):
        while not self._stop_event.is_set():
            # logging.debug("Tick")
            self._horloge_event.set()
            self._stop_event.wait(1)

    def run_affichage(self):

        while not self._stop_event.is_set():  # Utilise _stop_event de la superclasse pour synchroniser l'arret

            try:
                self._compteur_cycle += 1
                if self._compteur_cycle > self._cycles_entre_rafraichissements:
                    self._compteur_cycle = 0  # Reset compteur de cycles
                    self.charger_documents()  # On recharge les documents

                self.afficher_tph()

                # Afficher heure et date pendant 5 secondes
                self.afficher_heure()

            except Exception as e:
                logging.error("Erreur durant affichage: %s" % str(e))
                traceback.print_exc()
                # self.reconnecter()

    def maj_affichage(self, lignes_affichage):
        self._lignes_ecran = lignes_affichage

    def afficher_tph(self):
        if not self._stop_event.is_set():
            lignes = self.generer_lignes()
            lignes.reverse()  # On utilise pop(), premieres lectures vont a la fin

            while len(lignes) > 0:
                lignes_affichage = [lignes.pop()]
                if len(lignes) > 0:
                    lignes_affichage.append(lignes.pop())

                # Remplacer contenu ecran
                self.maj_affichage(lignes_affichage)

                logging.debug("Affichage: %s" % lignes_affichage)
                self._stop_event.wait(5)

    def afficher_heure(self):
        nb_secs = 5
        self._horloge_event.clear()
        while not self._stop_event.is_set() and nb_secs > 0:
            self._horloge_event.wait(1)
            nb_secs -= 1

            # Prendre heure courante, formatter
            now = datetime.datetime.now()
            datestring = now.strftime('%Y-%m-%d')
            timestring = now.strftime('%H:%M:%S')

            lignes_affichage = [datestring, timestring]
            logging.debug("Horloge: %s" % str(lignes_affichage))
            self.maj_affichage(lignes_affichage)

            # Attendre 1 seconde
            self._horloge_event.clear()
            self._horloge_event.wait(1)

    def generer_lignes(self):
        lignes = []
        pression = None
        tendance = None

        date_now = datetime.datetime.now()
        for senseur_id in self._documents:
            senseur = self._documents[senseur_id].copy()
            if senseur.get('location') is not None:
                if len(senseur.get('location')) > AfficheurSenseurPassifTemperatureHumiditePression.taille_titre_tph:
                    senseur['location'] = senseur['location'][:AfficheurSenseurPassifTemperatureHumiditePression.taille_titre_tph]
            else:
                senseur['location'] = '%s' % senseur.get('senseur')

            derniere_lecture = senseur['temps_lecture']
            date_chargee = datetime.datetime.fromtimestamp(derniere_lecture)
            date_expiration = date_chargee + self._age_donnee_expiree_timedelta
            self.__logger.debug("Date expiration lecture: %s, datenow: %s" % (date_expiration, date_now))
            if date_expiration < date_now:
                ligne_donnee = AfficheurSenseurPassifTemperatureHumiditePression.ligne_expiree_format.format(**senseur)
            else:
                ligne_donnee = AfficheurSenseurPassifTemperatureHumiditePression.ligne_tph_format.format(**senseur)

                # S'assurer d'utiliser une pression recente
                pression_senseur = senseur.get('pression')
                if pression is None and pression_senseur is not None and pression_senseur > 0.0:
                    pression = pression_senseur

                if tendance is None and senseur.get('pression_tendance') is not None:
                    tendance = senseur['pression_tendance']

            lignes.append(ligne_donnee)

        if pression is not None:
            lecture = {'titre': 'Press.', 'pression': pression, 'tendance': tendance}
            contenu = AfficheurSenseurPassifTemperatureHumiditePression.ligne_pression_format.format(**lecture)
            lignes.append(contenu)

        return lignes



# Affichages sans interaction/boutons qui sont controles via documents ou timers.
import traceback
import datetime
import logging
import time
import pytz
import json

from threading import Thread, Event
from typing import Optional

from millegrilles import Constantes
from millegrilles.Constantes import SenseursPassifsConstantes
from millegrilles.dao.MessageDAO import BaseCallback


class DocumentCallback(BaseCallback):
    """
    Sauvegarde le document recu s'il fait parti de la liste.
    """

    def __init__(self, contexte, afficheur):
        super().__init__(contexte)
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))
        self.afficheur = afficheur

    def traiter_message(self, ch, method, properties, body):
        message_json = self.decoder_message_json(body)
        routing_key = method.routing_key
        action = routing_key.split('.')[-1]
        correlation_id = properties.correlation_id

        # De-dupe, ignorer message
        try:
            uuid_message = message_json[
                Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
            if uuid_message != self.afficheur.dernier_evenement_uuid:
                self.__logger.info("Message recu: routing=%s, correlation_id=%s, contenu=%s" % (routing_key, correlation_id, message_json))
                self.afficheur.dernier_evenement_uuid = message_json[
                    Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
            else:
                self.__logger.info("Message duplique recu, on l'ignore : %s" % uuid_message)
                return
        except KeyError:
            if self.__logger.isEnabledFor(logging.DEBUG):
                self.__logger.exception("Erreur verification duplication de message")

        # Determiner type de message
        if correlation_id == 'affichage_lcd' or action == 'majNoeudConfirmee':
            self.__logger.debug("Recu configuration LCD : %s", message_json)
            self.afficheur.maj_configuration(message_json)
        elif correlation_id == 'senseurs_par_uuid':
            self.__logger.debug("Recu maj liste senseurs : %s", message_json)
            self.afficheur.maj_liste_senseurs(message_json)
        elif action in ['lecture', 'lectureConfirmee']:
            # Probablement une mise a jour d'un document existant
            noeud_id = message_json['noeud_id']
            uuid_senseur = message_json['uuid_senseur']
            senseurs = message_json['senseurs']
            self.afficheur.traiter_lecture(noeud_id, uuid_senseur, senseurs)


# Affichage qui se connecte a un ou plusieurs documents et recoit les changements live
class AfficheurDocumentMAJDirecte:

    # :params intervalle_secs: Intervalle (secondes) entre rafraichissements si watch ne fonctionne pas.
    def __init__(self, contexte, noeud_id: str = None, timezone_horloge: str = None, intervalle_secs=30):
        self._contexte = contexte
        self._noeud_id = noeud_id or self._contexte.configuration.noeud_id
        self._documents = dict()  # Cache de documents utilise pour l'affichage
        self._intervalle_secs = intervalle_secs
        self._intervalle_erreurs_secs = 60  # Intervalle lors d'erreurs
        self._cycles_entre_rafraichissements = 20  # 20 Cycles
        self._age_donnee_expiree = 300  # Secondes pour considerer une lecture comme expiree (stale)
        self._stop_event = Event()  # Evenement qui indique qu'on arrete la thread

        self._configuration_affichage_lcd: Optional[dict] = None
        self._cles_senseurs_supportes = list()

        # self._collection = None
        # self._curseur_changements = None  # Si None, on fonctionne par timer
        # self._watch_desactive = False  # Si true, on utilise watch. Sinon on utilise le timer
        self._timezone_horloge = None
        self._thread_maj_document = None
        self._thread_watchdog = None  # Thread qui s'assure que les connexions fonctionnent
        self._compteur_cycle = 0  # Utilise pour savoir quand on rafraichit, tente de reparer connexion, etc.
        self._age_donnee_expiree_timedelta = datetime.timedelta(seconds=self._age_donnee_expiree)

        self.channel = None
        self._queue_reponse = None

        self.traitement_callback = None
        self.dernier_evenement_uuid = None

        if timezone_horloge is not None:
            self._timezone_horloge = pytz.timezone(timezone_horloge)

        self._actif = False

        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def start(self):
        # Enregistrer callback
        self.__logger.debug("AfficheurDocumentMAJDirecte.start()")
        self._actif = True
        self.traitement_callback = DocumentCallback(self._contexte, self)
        self.contexte.message_dao.register_channel_listener(self)   # Callback sur on_channel_open avec le channel

    def on_channel_open(self, channel):
        self.channel = channel

        # Creer la Q de callback, listener pour documents
        self.channel.queue_declare(queue='', exclusive=True, callback=self.callback_inscrire)

    def callback_inscrire(self, queue):
        nom_queue = queue.method.queue
        self._queue_reponse = nom_queue
        self.__logger.info("AfficheurDocumentMAJDirecte: Resultat creation queue: %s" % nom_queue)

        routing_keys = [
            'evenement.' + SenseursPassifsConstantes.EVENEMENT_DOMAINE_LECTURE,
            'evenement.' + SenseursPassifsConstantes.EVENEMENT_DOMAINE_LECTURE_CONFIRMEE,
            'evenement.' + SenseursPassifsConstantes.EVENEMENT_MAJ_NOEUD_CONFIRMEE,
        ]
        # exchanges = [self._contexte.configuration.exchange_defaut]
        # if exchanges[0] == Constantes.SECURITE_PROTEGE:
        #     exchanges.append(Constantes.SECURITE_PRIVE)

        exchanges = [Constantes.SECURITE_PRIVE]

        self.__logger.info("Binding q %s sur exchanges %s" % (nom_queue, exchanges))

        for rk in routing_keys:
            for exchange in exchanges:
                self.channel.queue_bind(queue=nom_queue, exchange=exchange, routing_key=rk, callback=None)

        tag_queue = self.channel.basic_consume(nom_queue, self.traitement_callback.callbackAvecAck, auto_ack=False)
        self.__logger.debug("Queue %s, tag queue: %s" % (queue.method.queue, tag_queue))

        self.initialiser_documents()

    # def reconnecter(self):
    #     self.contexte.message_dao.deconnecter()
    #     self._stop_event.set()
    #     time.sleep(0.5)
    #     self._stop_event.clear()
    #     self._stop_event.wait(10)  # Attendre 10 secondes et ressayer du debut
    #     self.contexte.message_dao.connecter()
    #     self.start()

    def fermer(self):
        self._actif = False
        self._stop_event.set()
        # self._contexte.message_dao.deconnecter()

    def get_filtre(self):
        raise NotImplemented('Doit etre implementee dans la sous-classe')

    def initialiser_documents(self):
        self.charger_documents()  # Charger une version initiale des documents

    def charger_documents(self):
        # Charger la version la plus recente de chaque document
        requete = {'noeud_id': self._noeud_id}

        try:
            self._contexte.generateur_transactions.transmettre_requete(
                requete,
                domaine="SenseursPassifs",
                action='getNoeud',
                correlation_id='affichage_lcd',
                reply_to=self._queue_reponse,
                ajouter_certificats=True
            )
        except Exception as e:
            self.__logger.exception("Erreur transmission requete documents", e)

    def rafraichir_senseurs(self):
        configuration_affichage = self._configuration_affichage_lcd
        try:
            config_lcd = configuration_affichage['lcd_affichage']
        except KeyError:
            pass
        else:
            uuid_senseurs = [s['uuid'] for s in config_lcd if s.get('uuid') is not None]
            requete = {'uuid_senseurs': uuid_senseurs}
            try:
                self._contexte.generateur_transactions.transmettre_requete(
                    requete,
                    'requete.SenseursPassifs.' + SenseursPassifsConstantes.REQUETE_LISTE_SENSEURS_PAR_UUID,
                    'senseurs_par_uuid',
                    self._queue_reponse
                )
            except Exception as e:
                self.__logger.exception("Erreur transmission requete rafraichir senseurs", e)

    def traiter_lecture(self, noeud_id: str, uuid_senseur: str, senseurs: dict):
        cle_senseur = uuid_senseur
        if cle_senseur in self._cles_senseurs_supportes:
            try:
                doc_noeud = self._documents[cle_senseur]
            except KeyError:
                doc_noeud = dict()
                self._documents[cle_senseur] = doc_noeud

            try:
                senseurs_existants = doc_noeud['senseurs']
            except KeyError:
                senseurs_existants = dict()
                doc_noeud['senseurs'] = senseurs_existants

            # Conserver app individuellement - les messages peuvent etre transmis separement pour un meme senseur
            for app_cle, valeur in senseurs.items():
                senseurs_existants[app_cle] = valeur
        else:
            for app_cle, valeur in senseurs.items():
                cle_split = app_cle.split('/')
                if cle_split[0] == 'blynk':
                    # C'est un bouton blynk, voir si on peut mapper l'action
                    appareil = cle_split[-1]  # appareil = vpin
                    self.traiter_action(appareil, valeur)

    def traiter_action(self, appareil: str, valeur: dict):
        if self._configuration_affichage_lcd.get('lcd_vpin_onoff') == appareil:
            self.toggle_lcd_onoff(valeur['valeur'])
        elif self._configuration_affichage_lcd.get('lcd_vpin_navigation') == appareil:
            self.lcd_navigation(valeur['valeur'])

    def toggle_lcd_onoff(self, valeur: str):
        raise NotImplemented()

    def lcd_navigation(self, valeur: str):
        raise NotImplemented()

    def maj_configuration(self, configuration: dict):
        self.__logger.info("MAJ configuration : %s" % str(configuration))
        self._configuration_affichage_lcd = configuration

        actif = configuration.get('lcd_actif')
        if actif is True:
            self.__logger.debug("Recu nouvelle configuration avec lcd_actif is True, on s'assure que la thread est active")
        elif actif is False:
            self.__logger.debug("Recu nouvelle configuration avec lcd_actif is False, on ferme la thread")

        noeud_id = configuration['noeud_id']

        # Formatter l'affichage, compiler valeurs a ecouter/conserver
        cles_senseurs_supportes = set()

        lcd_affichage = configuration.get('lcd_affichage')
        if lcd_affichage is not None:
            for ligne in lcd_affichage:
                uuid_senseur = ligne['uuid']
                if uuid_senseur is not None and uuid_senseur != '':
                    cles_senseurs_supportes.add(uuid_senseur)

        self._cles_senseurs_supportes = list(cles_senseurs_supportes)

        # Hook pour rafraichir les senseurs (e.g. utile si nouveau senseur ajoute dans la configuration)
        self.rafraichir_senseurs()

    def maj_liste_senseurs(self, params: dict):
        for s in params['senseurs']:
            try:
                noeud_id = s['noeud_id']
                uuid_senseur = s['uuid_senseur']
                senseurs = s['senseurs']
                self.traiter_lecture(noeud_id, uuid_senseur, senseurs)
            except KeyError:
                pass

    def get_documents(self):
        return self._documents

    @property
    def contexte(self):
        return self._contexte


class AffichageAvecConfiguration(AfficheurDocumentMAJDirecte):

    def __init__(self, contexte, noeud_id: str = None, timezone_horloge: str = None, intervalle_secs=30):
        super().__init__(contexte, noeud_id, timezone_horloge, intervalle_secs)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self._thread_affichage: Optional[Thread] = None
        self._thread_horloge: Optional[Thread] = None
        self._horloge_event = Event()  # Evenement pour synchroniser l'heure
        self._lignes_ecran: Optional[list] = None  # Affichage actuel de l'ecran
        self._affichage_actif = True

        self._user_event = Event()

    def start(self):
        self.__logger.info("AffichageAvecConfiguration.start()")
        super().start()  # Demarre thread de lecture de documents
        self._thread_horloge = Thread(target=self.set_horloge_event, daemon=True)
        self._thread_horloge.start()

        # Thread.start
        self._thread_affichage = Thread(target=self.run_affichage, daemon=True)
        self._thread_affichage.start()
        self.__logger.info("AfficheurDocumentMAJDirecte: thread demarree")

    def fermer(self):
        super().fermer()
        self._user_event.set()

    def set_horloge_event(self):
        while not self._stop_event.is_set():
            # logging.debug("Tick")
            self._horloge_event.set()
            self._stop_event.wait(1)

    def maj_affichage(self, lignes_affichage):
        self._lignes_ecran = lignes_affichage

    def run_affichage(self):

        while not self._stop_event.is_set():  # Utilise _stop_event de la superclasse pour synchroniser l'arret

            try:
                self._compteur_cycle += 1
                if self._compteur_cycle > self._cycles_entre_rafraichissements:
                    self._compteur_cycle = 0  # Reset compteur de cycles
                    self.charger_documents()  # On recharge les documents

                self.executer_affichage()

                # Afficher heure et date pendant 5 secondes
                self.afficher_heure()

            except ConfigurationPasRecue:
                self.__logger.warning("La configuration LCD n'est pas encore recue, on attend pour demarrer l'affichage")
                if self.__logger.isEnabledFor(logging.INFO):
                    self.__logger.exception("Erreur configuration pas recue")
                self._user_event.wait(5)
            except Exception as e:
                self.__logger.exception("Erreur durant affichage")

                # Throttling
                self._user_event.wait(5)

    def executer_affichage(self):
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
                self._user_event.clear()
                self._user_event.wait(5)

    def afficher_heure(self):
        nb_secs = 5
        self._horloge_event.clear()
        while not self._stop_event.is_set() and nb_secs > 0:
            if self._user_event.is_set():
                # Sortir de la boucle horloge
                break

            nb_secs -= 1

            # Prendre heure courante, formatter
            now = datetime.datetime.utcnow().astimezone(pytz.UTC)  # Set date a UTC
            if self._timezone_horloge is not None:
                now = now.astimezone(self._timezone_horloge)  # Converti vers timezone demande
            datestring = now.strftime('%Y-%m-%d')
            timestring = now.strftime('%H:%M:%S')

            lignes_affichage = [datestring, timestring]
            logging.debug("Horloge: %s" % str(lignes_affichage))
            self.maj_affichage(lignes_affichage)

            # Attendre 1 seconde
            self._horloge_event.clear()
            self._horloge_event.wait(1)

    def generer_lignes(self) -> list:
        """
        Genere toutes les lignes de donnees en utilisant le formattage demande
        :return:
        """
        lignes = []

        try:
            noeud_id = self._configuration_affichage_lcd['noeud_id']
        except (TypeError, KeyError):
            raise ConfigurationPasRecue('lcd_affichage')

        try:
            formattage = self._configuration_affichage_lcd['lcd_affichage']
            for ligne in formattage:
                self.__logger.debug("Formatter ligne %s" % str(ligne))
                lignes.append(self.formatter_ligne(noeud_id, ligne))

            return lignes
        except KeyError:
            return []  # Aucune configuration

    def formatter_ligne(self, noeud_id: str, formattage: dict):
        format = formattage['affichage']

        uuid_senseur = formattage.get('uuid')
        cle_senseur = uuid_senseur

        cle_appareil = formattage.get('appareil')

        # Si on a un senseur/cle, on va chercher la valeur dans le cache de documents
        if uuid_senseur is not None and uuid_senseur != '' and \
                cle_appareil is not None and cle_appareil != '':

            flag = ''
            try:
                doc_senseur = self._documents[cle_senseur]
                doc_appareil = doc_senseur['senseurs'][cle_appareil]
                try:
                    ts_app = doc_appareil['timestamp']
                    date_courante = datetime.datetime.utcnow()
                    date_lecture = datetime.datetime.fromtimestamp(ts_app)
                    exp_1 = datetime.timedelta(minutes=5)
                    exp_2 = datetime.timedelta(minutes=30)
                    if date_lecture + exp_2 < date_courante:
                        flag = '!'
                    elif date_lecture + exp_1 < date_courante:
                        flag = '?'
                except KeyError:
                    pass
                valeur = doc_appareil['valeur']
            except KeyError:
                # Noeud/senseur/appareil inconnu
                self.__logger.warning("Noeud %s, senseur %s, appareil %s inconnu" % (noeud_id, uuid_senseur, cle_appareil))
                return 'N/A'

            try:
                return format.format(valeur,) + flag
            except KeyError:
                return '!' + format

        else:
            # Formattage libre avec valeurs systeme
            return format

    def toggle_lcd_onoff(self, valeur: str):
        if valeur == '1':
            self._affichage_actif = True
        else:
            self._affichage_actif = False

    def lcd_navigation(self, valeur: str):
        if valeur == '1':  # Next
            self._user_event.set()
            self._horloge_event.set()
        elif valeur == '0':  # Precedent
            pass
        elif valeur == '2':  # Refresh from top
            pass
            

# Classe qui charge des senseurs pour afficher temperature, humidite, pression/tendance
# pour quelques senseurs passifs.
class AfficheurSenseurPassifTemperatureHumiditePression(AfficheurDocumentMAJDirecte):

    taille_ecran = 16
    taille_titre_tph = taille_ecran - 11
    taille_titre_press = taille_ecran - 10

    ligne_expiree_format = "{location:<%d} <Expire>" % taille_titre_press
    ligne_tph_format = "{location:<%d} {temperature}/{humidite}" % taille_titre_tph
    ligne_pression_format = "{titre:<%d} {pression:5.1f}kPa{tendance}" % taille_titre_press

    def __init__(self, contexte, noeud_id: str = None, timezone_horloge: str = 'America/Toronto', senseur_ids: list = None, intervalle_secs=30):
        super().__init__(contexte, noeud_id, timezone_horloge, intervalle_secs)
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
            "uuid_senseur": {
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
                # Throttling
                self._stop_event.wait(5)
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
            now = datetime.datetime.utcnow().astimezone(pytz.UTC)  # Set date a UTC
            if self._timezone_horloge is not None:
                now = now.astimezone(self._timezone_horloge)  # Converti vers timezone demande
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

            liste_affichage = senseur.get('affichage')
            if liste_affichage is not None:
                for cle_appareil, appareil in liste_affichage.items():
                    appareil_copy = appareil.copy()

                    location = appareil.get('location')
                    if location is None:
                        location = senseur.get('location')
                        if location is None:
                            location = senseur.get('uuid_senseur')

                    appareil_copy['location'] = location[:AfficheurSenseurPassifTemperatureHumiditePression.taille_titre_tph]

                    # S'assurer d'avoir une valeur pour formatter temperature et humidite
                    if appareil_copy.get('temperature') is not None:
                        appareil_copy['temperature'] = '{temperature: 5.1f}C'.format(**appareil_copy)
                    else:
                        appareil_copy['temperature'] = 'N.D'
                    if appareil_copy.get('humidite') is not None:
                        appareil_copy['humidite'] = '{humidite:2.0f}%%'.format(**appareil_copy)
                    else:
                        appareil_copy['humidite'] = 'N.D'

                    derniere_lecture = appareil['timestamp']
                    date_chargee = datetime.datetime.fromtimestamp(derniere_lecture)
                    date_expiration = date_chargee + self._age_donnee_expiree_timedelta
                    self.__logger.debug("Date expiration lecture: %s, datenow: %s" % (date_expiration, date_now))
                    if date_expiration < date_now:
                        ligne_donnee = AfficheurSenseurPassifTemperatureHumiditePression.ligne_expiree_format.format(**appareil_copy)
                    else:
                        ligne_donnee = AfficheurSenseurPassifTemperatureHumiditePression.ligne_tph_format.format(**appareil_copy)

                    # S'assurer d'utiliser une pression recente
                    pression_senseur = appareil.get('pression')
                    if pression is None and pression_senseur is not None and pression_senseur > 0.0:
                        pression = pression_senseur

                    if tendance is None :
                        tendance = senseur.get('pression_tendance')

                    lignes.append(ligne_donnee)
            else:
                self.__logger.warning("Senseur %s n'a pas d'element affichage" % senseur_id)

        if pression is not None:
            lecture = {'titre': 'Press.', 'pression': pression, 'tendance': tendance}
            contenu = AfficheurSenseurPassifTemperatureHumiditePression.ligne_pression_format.format(**lecture)
            lignes.append(contenu)

        return lignes


class ConfigurationPasRecue(Exception):
    """ La configuration n'a pas encore ete recue """
    pass

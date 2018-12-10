# Module qui permet d'extraire des pages web ou feed RSS et de les sauvegarder comme "transaction:

import urllib.request
import certifi
import logging
import feedparser

from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles.Domaines import GestionnaireDomaine
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles import Constantes
from millegrilles.processus.MGProcessus import MGProcessusTransaction


class WebPollConstantes:

    COLLECTION_NOM = 'mgdomaines_web_WebPoll'

    # Document de configuration de reference s'il n'existe pas deja
    # Se document se trouve dans la collection mgdomaines_web_WebPoll, _mg-libelle: configuration.
    document_configuration_reference = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: 'configuration',
        'taches': {
            'exemple1': {
                'commentaire': 'Ceci est une tache de telechargement exemple. Voir parametres de ce dictionnaire',
                'url': 'https://redmine.maple.mdugre.info/projects.atom?key=85de669522c8...',
                'type': 'rss',
                'domaine': 'mgdomaines.web.WebPoll.RSS'
            },
            'exemple2': {
                'commentaire': 'Ceci est une tache de telechargement de page',
                'url': 'https://www.maple.mdugre.info/',
                'type': 'page',
                'domaine': 'mgdomaines.web.WebPoll.WebPageDownload.informationspeciale.mathieu'
            },
            'minimal': {
                'url': 'http://exemple.minimal'
            },
            'meteo_russell': {
                "commentaire": "Telechargement previsions meteo Environnement Canada pour Ottawa-Metcalfe",
                "url": "https://weather.gc.ca/rss/city/on-52_e.xml",
                "type": "rss",
                "domaine": "mgdomaines.web.WebPoll.RSS.weather_gc_ca.russell"
            }
        },
        'minute': ['exemple1'],
        'minute%2': [],
        'minute%3': [],
        'minute%4': [],
        'minute%6': [],
        'minute%12': [],
        'heure': ['exemple2', 'minimal'],
        'heure%2': [],
        'heure%3': [],
        'heure%4': [],
        'heure%6': [],
        'heure%12': [],
        'jour': [],
        'semaine': [],
        'mois': []
    }


class GestionnaireWebPoll(GestionnaireDomaine):
    """ Gestionnaire du domaine Web Poller. Telecharge des documents a frequence reguliere. """

    def __init__(self, configuration, message_dao, document_dao):
        super().__init__(configuration, message_dao, document_dao)
        self._traitement_lecture = None

        self._downloaders = {}

        self._logger = logging.getLogger("%s.GestionnaireWebPoll" % __name__)

    def configurer(self):
        super().configurer()
        self._traitement_lecture = TraitementMessageWebPoll(self)
        self.traiter_transaction = self._traitement_lecture.callbackAvecAck

        nom_millegrille = self.configuration.nom_millegrille
        nom_queue_webpoll = self.get_nom_queue()

        # Configurer la Queue pour WebPoll sur RabbitMQ
        self.message_dao.channel.queue_declare(
            queue=nom_queue_webpoll,
            durable=True)

        # Si la Q existe deja, la purger. Ca ne sert a rien de poller les memes documents plusieurs fois.
        self.message_dao.channel.queue_purge(
            queue=nom_queue_webpoll
        )

        self.message_dao.channel.queue_bind(
            exchange=self.configuration.exchange_evenements,
            queue=nom_queue_webpoll,
            routing_key='%s.destinataire.domaine.mgdomaines.web.WebPoll.#' % nom_millegrille
        )

        self.message_dao.channel.queue_bind(
            exchange=self.configuration.exchange_evenements,
            queue=nom_queue_webpoll,
            routing_key='%s.ceduleur.#' % nom_millegrille
        )

        # Configurer MongoDB, inserer le document de configuration de reference s'il n'existe pas
        collection_webpoll = self.document_dao.get_collection(WebPollConstantes.COLLECTION_NOM)

        # Trouver le document de configuration
        document_configuration = collection_webpoll.find_one(
            {Constantes.DOCUMENT_INFODOC_LIBELLE: 'configuration'}
        )
        if document_configuration is None:
            self._logger.info("On insere le document de configuration de reference pour WebPoll")
            collection_webpoll.insert(WebPollConstantes.document_configuration_reference)
        else:
            self._logger.info("Document de configuration de telechargement: %s" % str(document_configuration))

        self._downloaders['page'] = WebPageDownload(self.configuration, self.message_dao)
        self._downloaders['rss'] = RSSFeedDownload(self.configuration, self.message_dao)

    def traiter_transaction(self, ch, method, properties, body):
        # self._traitement_lecture.callbackAvecAck(ch, method, properties, body)
        pass

    def get_nom_queue(self):
        nom_millegrille = self.configuration.nom_millegrille
        nom_queue_senseurspassifs = 'mg.%s.mgdomaines.web.WebPoll' % nom_millegrille
        return nom_queue_senseurspassifs

    ''' Traite les evenements sur cedule. '''
    def traiter_cedule(self, evenement):
        indicateurs = evenement['indicateurs']
        self._logger.debug("Cedule webPoll: %s" % str(indicateurs))

        document_configuration = self.get_document_configuration()

        # Faire la liste des cedules a declencher
        timestamp = evenement['timestamp']['UTC']
        heure_utc = timestamp[3]
        minute_utc = timestamp[4]
        cedules = ['minute']  # Le ceduleur est declenche a toutes les minutes, c'est implicite

        if 'heure' in indicateurs:  # Cas special, on n'a pas l'indicateur de timezone pour l'heure
            cedules.append('heure')

        # Ajouter les indicateurs speciaux
        if 'Canada/Eastern' in indicateurs:
            indicateurs_speciaux = ['heure', 'jour', 'mois', 'annee']
            for indicateur in indicateurs_speciaux:
                if indicateur not in cedules and indicateur in indicateurs:
                    cedules.append(indicateur)

        # Cedules minute%2, minute%3, etc.
        liste_steps = [2, 3, 4, 5, 6, 10, 12, 15, 20, 30]
        for step in liste_steps:
            if minute_utc % step == 0:
                cedules.append('minute%%%d' % step)
            if 'heure' in cedules and heure_utc % step == 0:
                cedules.append('heure%%%d' % step)

        for cedule in cedules:
            try:
                self._logger.debug("Voir si on a des taches pour cedule: %s" % cedule)
                taches_cedule = document_configuration.get(cedule)
                if taches_cedule is not None:
                    self.traiter_taches_cedule(document_configuration, taches_cedule)
            except Exception as e:
                self._logger.exception("Erreur traitement taches cedule %s: %s" % (cedule, str(e)))

    def traiter_taches_cedule(self, document_configuration, taches):
        for tache in taches:
            try:
                description_tache = document_configuration['taches'][tache]
                self.telecharger(description_tache)
            except Exception as e:
                self._logger.exception('Erreur traitement tache "%s" dans cedule: %s' % (tache, str(e)))

    def telecharger(self, parametres):
        type_transaction = parametres.get('type')
        if type_transaction is None:
            type_transaction = 'page'
        url = parametres['url']
        domaine = parametres.get('domaine')

        self._logger.debug("Telecharger url=%s, type=%s" % (url, type_transaction))

        downloader = self._downloaders[type_transaction]

        if domaine is not None:
            downloader.produire_transaction(url, domaine)
        else:
            downloader.produire_transaction(url)

    def get_document_configuration(self):
        collection_webpoll = self.document_dao.get_collection(WebPollConstantes.COLLECTION_NOM)

        # Trouver le document de configuration
        document_configuration = collection_webpoll.find_one(
            {Constantes.DOCUMENT_INFODOC_LIBELLE: 'configuration'}
        )

        return document_configuration


class TraitementMessageWebPoll(BaseCallback):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire.configuration)
        self._gestionnaire = gestionnaire

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get("evenements")

        if evenement == Constantes.EVENEMENT_CEDULEUR:
            self._gestionnaire.traiter_cedule(message_dict)
        elif evenement == Constantes.EVENEMENT_TRANSACTION_PERSISTEE:
            # On envoit la transaction au processus par defaut
            processus = "mgdomaines_web_WebPoll:ProcessusTransactionDownloadPageWeb"
            self._gestionnaire.demarrer_processus(processus, message_dict)
        else:
            # Type d'evenement inconnu, on lance une exception
            raise ValueError("Type d'evenement inconnu: %s" % evenement)


class WebPageDownload:
    """ Classe qui permet de telecharger une page web et la transmettre comme nouvelle transaction. """

    TRANSACTION_VALEUR_DOMAINE = 'mgdomaines.web.WebPoll.WebPageDownload'

    def __init__(self, configuration, message_dao, limit_bytes=50*1024):
        self._generateur_transaction = GenerateurTransaction(configuration, message_dao)
        # self._configuration = configuration
        # self._message_dao = message_dao
        self._limit_bytes = limit_bytes  # Taille limite du download

        self.url = None
        self.contenu = None
        self.domaine = None

        self._logger = logging.getLogger("%s.WebPageDownload" % __name__)

    def produire_transaction(self, url, domaine=TRANSACTION_VALEUR_DOMAINE):
        self.url = url
        self.domaine = domaine
        self.contenu = self.telecharger(url)
        self._logger.debug("Contenu telecharge: %s" % str(self.contenu))
        if len(self.contenu) > self._limit_bytes:
            raise ValueError("Contenu telecharge est trop grand (%d bytes > limite %d bytes)" %
                             (len(self.contenu), self._limit_bytes))

        contenu_dict = self.traiter_contenu(self.contenu)
        self._generateur_transaction.soumettre_transaction(contenu_dict, domaine)

    def telecharger(self, url):
        self._logger.debug("certifi: Certificats utilises pour telecharger: %s" % certifi.where())
        self._logger.debug("Telechargement du URL: %s" % url)
        with urllib.request.urlopen(url, cafile=certifi.where()) as response:
            contenu = response.read()
        return contenu

    def traiter_contenu(self, contenu):
        contenu_dict = {
            "url": self.url,
            "text": str(contenu)
        }
        return contenu_dict


# Classe qui va parser le contenu text en un dictionnaire Python
class RSSFeedDownload(WebPageDownload):

    TRANSACTION_VALEUR_DOMAINE = 'mgdomaines.web.WebPoll.RSS'

    def __init__(self, configuration, message_dao, limit_bytes=100*1024):
        super().__init__(configuration, message_dao, limit_bytes)

    def traiter_contenu(self, contenu):
        contenu_dict = super().traiter_contenu(contenu)

        # Parser le feed
        feed_content = feedparser.parse(contenu)
        contenu_dict['rss'] = feed_content
        del contenu_dict['text']  # On enleve le contenu purement string

        return contenu_dict

    def produire_transaction(self, url, domaine=TRANSACTION_VALEUR_DOMAINE):
        super().produire_transaction(url, domaine)


class ProcessusTransactionDownloadPageWeb(MGProcessusTransaction):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        # Rien a faire, on fait juste marquer la transaction comme completee (c'est fait automatiquement)
        self.set_etape_suivante()  # Va marquer la transaction comme complete

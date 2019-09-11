# Outil de publication de fichiers vers le web, associe a nginx

import time
import datetime
import pytz
import logging
import threading
import os
import shutil

from threading import Event, Thread
from pika.exceptions import ConnectionClosed, ChannelClosed
from delta import html

from millegrilles import Constantes
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.util.UtilScriptLigneCommande import ModeleConfiguration


class Publicateur(ModeleConfiguration):

    def __init__(self):
        super().__init__()
        self._stop_event = Event()
        self._stop_event.set()

        self.__channel = None
        self.__queue_reponse = None
        self._message_handler = None

        self._configuration = None

        self.logger = logging.getLogger('Publicateur')

    def initialiser(self, init_document=False, init_message=True, connecter=True):
        super().initialiser(init_document, init_message, connecter)

        nom_millegrille = self.contexte.configuration.nom_millegrille
        if nom_millegrille is None:
            raise ValueError("Il faut fournir le nom de la MilleGrille (MG_NOM_MILLEGRILLE)")

        webroot = self.args.webroot
        if webroot is None:
            webroot = '/opt/millegrilles/%s/mounts/nginx/www-public' % nom_millegrille

        self._configuration = {
            'nom_millegrille': nom_millegrille,
            'webroot': webroot,
        }

        # Configuration MQ
        self._message_handler = TraitementPublication(self.contexte)
        self.contexte.message_dao.register_channel_listener(self)

    def on_channel_open(self, channel):
        channel.add_on_close_callback(self.__on_channel_close)
        self.__channel = channel
        self.__channel.queue_declare(queue='', exclusive=True, callback=self.register_mq_hanlder)

    def register_mq_hanlder(self, queue):
        nom_queue = queue.method.queue
        exchange = Constantes.CONFIG_MQ_EXCHANGE_NOEUDS
        self.__queue_reponse = nom_queue
        self._logger.debug("Resultat creation queue: %s" % nom_queue)

        routing_keys = ['publicateur.#']

        for routing_key in routing_keys:
            self.__channel.queue_bind(queue=nom_queue, exchange=exchange, routing_key=routing_key, callback=None)

    def __on_channel_close(self, channel=None, code=None, reason=None):
        self.__channel = None
        self.deconnecter()

    def deconnecter(self):
        self._stop_event.set()
        super().deconnecter()

    def configurer_parser(self):
        super().configurer_parser()

        # self.parser.add_argument(
        #     '--debug', action="store_true", required=False,
        #     help="Active le debugging (logger)"
        # )

        self.parser.add_argument(
            '--webroot',
            type=str,
            required=True,
            help="Repertoire de base pour publier les fichiers"
        )

    def set_logging_level(self):
        super().set_logging_level()
        """ Utilise args pour ajuster le logging level (debug, info) """
        if self.args.debug:
            self._logger.setLevel(logging.DEBUG)
            # logging.getLogger('mgdomaines').setLevel(logging.DEBUG)
        elif self.args.info:
            self._logger.setLevel(logging.INFO)
            # logging.getLogger('mgdomaines').setLevel(logging.INFO)

    def executer(self):

        self._stop_event.clear()  # Pret a l'execution

        while not self._stop_event.is_set():
            self._stop_event.wait(30)

    @property
    def configuration(self):
        return self._configuration


class TraitementPublication(BaseCallback):
    """
    Handler pour la Q du publicateur. Execute les commandes de publication.
    """

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire.contexte)
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))
        self._gestionnaire = gestionnaire
        self._generateur = gestionnaire.contexte.generateur_transactions

    def traiter_message(self, ch, method, properties, body):
        routing_key = method.routing_key
        correlation_id = properties.correlation_id
        exchange = method.exchange

        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)
        enveloppe_certificat = self.contexte.verificateur_transaction.verifier(message_dict)

        if correlation_id is not None:
            # C'est une reponse
            pass
        elif routing_key is not None:
            if routing_key in ['publicateur.plume.ajouterDocument', 'publicateur.plume.modifierDocument']:
                exporteur = ExporterDeltaPlume(self._gestionnaire.configuration, message_dict)
                exporteur.exporter_html()
            elif routing_key in ['publicateur.plume.supprimerDocument', 'publicateur.plume.depublierDocument']:
                # Supprime un document Plume (ou le de-publie)
                exporteur = ExporterDeltaPlume(self._gestionnaire.configuration, message_dict)
                exporteur.supprimer_fichier()
            elif routing_key in ['publicateur.plume.catalogue']:
                # Mettre a jour le catalogue (index.html) des fichiers plume
                exporteur = PublierCataloguePlume(self._gestionnaire.configuration, message_dict)
                exporteur.exporter_catalogue()
            elif routing_key in ['publicateur.plume.categorie']:
                # Mettre a jour le catalogue d'une categorie plume
                exporteur = PublierCataloguePlume(self._gestionnaire.configuration, message_dict)
                exporteur.exporter_categorie()
            else:
                raise ValueError("Message routing inconnu: %s" % routing_key)
        else:
            raise ValueError("Message type inconnu")


class ExporterDeltaVersHtml:

    def __init__(self, configuration, message_publication):
        self._configuration = configuration
        self._message_publication = message_publication

    def exporter_html(self):
        """
        Sauvegarde le contenu HTML dans un fichier
        :param delta_html:
        :return:
        """

        # S'assurer que le repertoire existe
        repertoire = os.path.dirname(self._chemin_fichier())
        os.makedirs(repertoire, exist_ok=True)

        chemin_fichier = self._chemin_fichier()

        # Enregistrer fichier
        with open('%s.staging' % chemin_fichier, 'wb') as fichier:
            self.render_delta(fichier)

        # Aucune exception, on supprime l'ancien fichier et renomme .staging
        if os.path.exists(chemin_fichier):
            os.remove(chemin_fichier)
        os.rename('%s.staging' % chemin_fichier, chemin_fichier)

    def render_delta(self, fichier):
        raise NotImplementedError("Pas implemente")

    def identifier_grosfichiers(self):
        """
        Retourne une liste de grosfichiers a extraire
        :return: GrosFichiers a telecharger
        """
        # Faire la liste

        return []

    def supprimer_fichier(self):
        raise NotImplementedError("Pas implemente")

    def _creer_links(self):
        """ Met a jour les symlinks vers le fichier HTML """
        pass

    def _chemin_fichier(self):
        raise NotImplementedError("Pas implemente")


class ExporterDeltaPlume(ExporterDeltaVersHtml):

    def __init__(self, configuration, message_publication):
        super().__init__(configuration, message_publication)
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def render_delta(self, fichier):
        """ Genere le contenu HTML """
        delta = self._message_publication['quilldelta']
        delta_html = html.render(delta['ops'], pretty=True)

        fichier.write('<html><head>'.encode('utf-8'))
        fichier.write((
                '<title>%s</title>' % self._message_publication['titre']
            ).encode('utf-8'))
        fichier.write('</head><body>'.encode('utf-8'))
        fichier.write(delta_html.encode('utf-8'))
        fichier.write('</body></html>\n'.encode('utf-8'))

    def supprimer_fichier(self):
        webroot = self._configuration['webroot']
        uuid = self._message_publication['uuid']
        chemin = '%s/plume/%s' % (webroot, uuid)
        shutil.rmtree(chemin)

    def _chemin_fichier(self):
        webroot = self._configuration['webroot']
        uuid = self._message_publication['uuid']
        titre = self._message_publication['titre']
        chemin = '%s/plume/%s/%s.html' % (webroot, uuid, titre)
        return chemin


class PublierCataloguePlume:

    def __init__(self, configuration, message_publication):
        self._configuration = configuration
        self._message_publication = message_publication

    def exporter_catalogue(self):
        nom_fichier = self._chemin_fichier()
        nom_fichier_staging = '%s.staging' % nom_fichier

        with open(nom_fichier_staging, 'wb') as fichier:
            self.render_catalogue(fichier)

    def render_catalogue(self, fichier):
        fichier.write('<html>\n'.encode('utf-8'))
        fichier.write('<head><title>Plume</title></head>\n'.encode('utf-8'))
        fichier.write('<body>\n'.encode('utf-8'))
        fichier.write('<h1>Plume public</h1>\n'.encode('utf-8'))

        liste_documents = self._message_publication['documents']
        for document in liste_documents:
            titre = document['titre']
            uuid = document['uuid']
            categories = document['categories']
            date_modification = document['_mg-derniere-modification']

            fichier.write('<div>\n'.encode('utf-8'))

            fichier.write(('<a href="/plume/%s/%s.html">%s</a> ' % (uuid, titre, titre)).encode('utf-8'))
            fichier.write(' '.join(categories).encode('utf-8'))
            fichier.write(' <span>'.encode('utf-8'))
            fichier.write(str(date_modification).encode('utf-8'))
            fichier.write('</span>'.encode('utf-8'))

            fichier.write('</div>\n'.encode('utf-8'))

        fichier.write('</body>\n</html>\n'.encode('utf-8'))

    def exporter_categorie(self):
        pass

    def render_categorie(self):
        pass

    def _chemin_fichier(self):
        webroot = self._configuration['webroot']
        return '%s/plume/index.html' % webroot


class PublierGrosFichiers:
    """
    Telecharge et sauvegarde un gros fichiers.

    Les fichiers vont sous /grosfichiers/YYYY/MM/DD/HH/mm/uuid-v4.dat  (public par definition, donc .dat)
    Les symlinks sont generes sous /images/...rep.../NOM_IMAGE.jpg, /video/...rep.../NOM_VIDEO.XXX ou /fichiers/...rep.../NOM_FICHIER.XXX
    """

    def __init__(self):
        pass

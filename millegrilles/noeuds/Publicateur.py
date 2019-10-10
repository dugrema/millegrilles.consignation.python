# Outil de publication de fichiers vers le web, associe a nginx

import time
import datetime
import pytz
import logging
import threading
import os
import shutil
import urllib
import re

from threading import Event, Thread
from pika.exceptions import ConnectionClosed, ChannelClosed
from delta import html
from distutils import dir_util

from millegrilles import Constantes
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.util.UtilScriptLigneCommande import ModeleConfiguration
from millegrilles.SecuritePKI import ConstantesSecurityPki, EnveloppeCertificat
from millegrilles.domaines.Pki import ConstantesPki


class ConstantesPublicateur:

    PATH_FICHIER_MAIN = 'templates/main.template.html'
    PATH_FICHIER_ACCUEIL = 'templates/accueil.content.html'
    MARQUEUR_CONTENU = '<!-- MARQUEUR - Contenu de la page - MARQUEUR -->'

    MENUCLASS_ACTIF = 'w3-white'
    MENUCLASS_INACTIF = 'w3-hide-small w3-hover-white'

    RESSOURCES_CSS = 'stylesheets'
    RESSOURCES_JS = 'js'
    RESSOURCES_FONTS = 'fonts'


class Publicateur(ModeleConfiguration):

    def __init__(self):
        super().__init__()
        self._stop_event = Event()
        self._stop_event.set()

        self.__channel = None
        self.__queue_reponse = None
        self._message_handler = None

        self._webroot = None
        self._template_path = None

        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

        # Flags pour elements qu'on veut s'assurer de charger au demarrage
        self.flag_certs_ca = False

    def initialiser(self, init_document=False, init_message=True, connecter=True):
        super().initialiser(init_document, init_message, connecter)

        nom_millegrille = self.contexte.configuration.nom_millegrille
        if nom_millegrille is None:
            raise ValueError("Il faut fournir le nom de la MilleGrille (MG_NOM_MILLEGRILLE)")

        self._webroot = self.args.webroot
        if self._webroot is None:
            self._webroot = '/opt/millegrilles/%s/mounts/nginx' % nom_millegrille

        self._template_path = self.args.templates
        if self._template_path is None:
            self._template_path = './html'

        # Configuration MQ
        self._message_handler = TraitementPublication(self)
        self.contexte.message_dao.register_channel_listener(self)

        # Copier les ressources statiques
        if not self.args.noinit:
            self._copier_ressources_statiques()

    def _copier_ressources_statiques(self):
        """
        Faire une copie initiale des ressources statiques
        :return:
        """
        exporteur_index = ExporterPageHtml(self, ConstantesPublicateur.PATH_FICHIER_ACCUEIL, 'index.html')
        exporteur_ressources = PublierRessourcesStatiques(self)

        exporteur_index.exporter_html('ACCUEIL')
        exporteur_ressources.copier_ressources()

    def on_channel_open(self, channel):
        channel.add_on_close_callback(self.__on_channel_close)
        self.__channel = channel
        self.__channel.queue_declare(queue='', exclusive=True, callback=self.register_mq_hanlder)

    def register_mq_hanlder(self, queue):
        nom_queue = queue.method.queue
        exchange = self.contexte.configuration.exchange_noeuds
        self.__queue_reponse = nom_queue
        self._logger.debug("Resultat creation queue: %s" % nom_queue)

        routing_keys = ['publicateur.#', 'commande.publicateur.#']

        for routing_key in routing_keys:
            self.__channel.queue_bind(queue=nom_queue, exchange=exchange, routing_key=routing_key, callback=None)

        self.__channel.basic_consume(self._message_handler.callbackAvecAck, queue=nom_queue, no_ack=False)

    def requete_certs_ca(self, nom_queue):
        """
        Demander les certificats CA a PKI.
        :param nom_queue: 
        :return: 
        """
        self._logger.debug("Requete certificats CA pour la millegrille")
        requete = {}
        self.contexte.generateur_transactions.transmettre_requete(
            requete,
            ConstantesPki.REQUETE_LISTE_CA,
            'certs.ca',
            reply_to=nom_queue,
            domaine_direct=True
        )

    def __on_channel_close(self, channel=None, code=None, reason=None):
        self.__channel = None
        self.deconnecter()

    def deconnecter(self):
        self._stop_event.set()
        super().deconnecter()

    def configurer_parser(self):
        super().configurer_parser()

        self.parser.add_argument(
            '--noinit', action="store_true", required=False,
            help="Desactive la copie des templates/ressources vers webroot au demarrage"
        )

        self.parser.add_argument(
            '--webroot',
            type=str,
            required=False,
            help="Repertoire de base pour publier les fichiers"
        )

        self.parser.add_argument(
            '--templates',
            type=str,
            required=False,
            help="Repertoire pour les modeles (templates) html et autres ressources"
        )

    def set_logging_level(self):
        super().set_logging_level()
        """ Utilise args pour ajuster le logging level (debug, info) """
        if self.args.debug:
            self._logger.setLevel(logging.DEBUG)
            logging.getLogger('millegrilles.noeuds').setLevel(logging.DEBUG)
        elif self.args.info:
            self._logger.setLevel(logging.INFO)
            logging.getLogger('millegrilles.noeuds').setLevel(logging.INFO)

    def executer(self):

        self._stop_event.clear()  # Pret a l'execution

        while not self._stop_event.is_set():

            if not self.flag_certs_ca:
                self.requete_certs_ca(self.__queue_reponse)

            self._stop_event.wait(30)


    @property
    def webroot(self):
        return self._webroot

    @property
    def template_path(self):
        return self._template_path


class TraitementPublication(BaseCallback):
    """
    Handler pour la Q du publicateur. Execute les commandes de publication.
    """

    def __init__(self, publicateur):
        super().__init__(publicateur.contexte)
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))
        self._publicateur = publicateur
        self._generateur = self.contexte.generateur_transactions

    def traiter_message(self, ch, method, properties, body):
        routing_key = method.routing_key
        correlation_id = properties.correlation_id

        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)

        if correlation_id == 'certs.ca':
            # Sauvegarder liste des certificats ca
            exporteur = PublierCertificatCA(self._publicateur, message_dict)
            exporteur.exporter()
            self._publicateur.flag_certs_ca = True
        elif routing_key is not None:
            if routing_key in ['publicateur.plume.publierDocument']:
                exporteur = ExporterPlume(self._publicateur, message_dict)
                exporteur.exporter_html()
            elif routing_key in ['publicateur.plume.supprimerDocument', 'publicateur.plume.depublierDocument']:
                # Supprime un document Plume (ou le de-publie)
                exporteur = ExporterPlume(self._publicateur, message_dict)
                exporteur.supprimer_fichier()
            elif routing_key in ['publicateur.plume.catalogue']:
                # Mettre a jour le catalogue (index.html) des fichiers plume
                exporteur = PublierCataloguePlume(self._publicateur, message_dict)
                exporteur.exporter_html()
            elif routing_key in ['publicateur.plume.categorie']:
                # Mettre a jour le catalogue d'une categorie plume
                exporteur = PublierCataloguePlume(self._publicateur, message_dict)
                exporteur.exporter_categorie()
            elif routing_key == 'commande.publicateur.publierCertificat':
                exporteur = PublierCertificat(self._publicateur, message_dict)
                exporteur.exporter()
            elif routing_key == 'commande.publicateur.publierCA':
                exporteur = PublierCertificatCA(self._publicateur, message_dict)
                exporteur.exporter()
            else:
                raise ValueError("Message routing inconnu: %s" % routing_key)
        else:
            raise ValueError("Message type inconnu")


class PublierRessourcesStatiques:

    def __init__(self, publicateur):
        self._publicateur = publicateur
        self._liste_ressources = [
            ConstantesPublicateur.RESSOURCES_CSS,
            ConstantesPublicateur.RESSOURCES_JS,
            ConstantesPublicateur.RESSOURCES_FONTS,
        ]

        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def copier_ressources(self):
        webroot = self._publicateur.webroot
        self.__logger.debug("Copie des ressources sous %s vers %s" % (str(self._liste_ressources), webroot))

        for res in self._liste_ressources:
            path_res = '%s/%s' % (self._publicateur.template_path, res)
            dir_util.copy_tree(path_res, '%s/%s' % (webroot, res))


class ExporterVersHtml:

    def __init__(self, publicateur):
        self._publicateur = publicateur

        self._nom_template = '%s/%s' % (self._publicateur.template_path, ConstantesPublicateur.PATH_FICHIER_MAIN)
        self._template_split = None
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def exporter_html(self, nom_section: str = 'ACCUEIL'):
        """
        Sauvegarde le contenu HTML dans un fichier
        :param nom_section:
        :return:
        """

        # S'assurer que le repertoire existe
        repertoire = os.path.dirname(self._chemin_fichier())
        os.makedirs(repertoire, exist_ok=True)

        chemin_fichier = self._chemin_fichier()

        self._template_split = self.preparer_template(nom_section)

        # Enregistrer fichier
        with open('%s.staging' % chemin_fichier, 'wb') as fichier:
            fichier.write(self._template_split[0].encode('utf-8'))
            self.render(fichier)
            fichier.write(self._template_split[1].encode('utf-8'))

        # Aucune exception, on supprime l'ancien fichier et renomme .staging
        if os.path.exists(chemin_fichier):
            os.remove(chemin_fichier)
        os.rename('%s.staging' % chemin_fichier, chemin_fichier)

        self.__logger.info("Fichier exporte: %s" % chemin_fichier)

    def preparer_template(self, nom_section: str = 'ACCUEIL'):
        """
        Le template contient des variables a remplacer et un marqueur de contenu utiliser pour separer l'output.
        :param nom_section: Le nom de la section, utilise pour gerer le menu (${MENUCLASS_NOMSECTION} devient actif)
        :return:
        """
        with open(self._nom_template, 'r') as fichier:
            template_complet = fichier.read()

        # Effectuer les remplacements
        # Inserer le nom de la millegrille
        nom_millegrille = self._publicateur.contexte.configuration.nom_millegrille
        template_complet = template_complet.replace('${MG_NOM_MILLEGRILLE}', nom_millegrille)
        self.__logger.debug("Template complet: %s" % template_complet)

        # Activer l'item courant dans le menu, desactiver les autres
        template_complet = template_complet.replace('${MENUCLASS_%s}' % nom_section.upper(), ConstantesPublicateur.MENUCLASS_ACTIF)

        classes = re.search('(\\$\\{MENUCLASS_[A-Z]+\\})', template_complet)
        for menu in classes.groups():
            template_complet = template_complet.replace(menu, ConstantesPublicateur.MENUCLASS_INACTIF)
        self.__logger.debug("Classes tags trouves: %s" % str(classes))

        # Faire un split entre avant et apres le marqueur de contenu
        return template_complet.split(ConstantesPublicateur.MARQUEUR_CONTENU)

    def render(self, fichier):
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


class ExporterPageHtml(ExporterVersHtml):

    def __init__(self, publicateur, nom_fichier_contenu, destination):
        super().__init__(publicateur)
        self._nom_fichier_contenu = nom_fichier_contenu
        self._destination = destination
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def render(self, fichier):
        nom_fichier = '%s/%s' % (self._publicateur.template_path, self._nom_fichier_contenu)
        self.__logger.debug("Ouverture fichier contenu %s" % nom_fichier)
        nom_millegrille = self._publicateur.contexte.configuration.nom_millegrille
        with open(nom_fichier, 'rb') as fichier_contenu:
            contenu = fichier_contenu.read().decode('utf-8')
            contenu = contenu.replace('${MG_NOM_MILLEGRILLE}', nom_millegrille)
            fichier.write(contenu.encode('utf-8'))

    def supprimer_fichier(self):
        webroot = self._publicateur.webroot
        chemin = '%s/%s' % (webroot, self._destination)
        os.remove(chemin)

    def _chemin_fichier(self):
        webroot = self._publicateur.webroot
        chemin = '%s/%s' % (webroot, self._destination)
        return chemin


class ExporterPlume(ExporterVersHtml):

    def __init__(self, publicateur, message_publication):
        super().__init__(publicateur)
        self._message_publication = message_publication
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def exporter_html(self, nom_section: str = 'PLUME'):
        super().exporter_html(nom_section)

    def render(self, fichier):
        """ Genere le contenu HTML """
        delta = self._message_publication['quilldelta']
        delta_html = html.render(delta['ops'], pretty=True)

        # fichier.write('<html><head>'.encode('utf-8'))
        # fichier.write('<meta charset="UTF-8">\n'.encode('utf-8'))
        # fichier.write((
        #         '<title>%s</title>' % self._message_publication['titre']
        #     ).encode('utf-8'))
        # fichier.write('</head><body>'.encode('utf-8'))
        fichier.write(delta_html.encode('utf-8'))
        # fichier.write('</body></html>\n'.encode('utf-8'))

    def supprimer_fichier(self):
        webroot = self._publicateur.webroot
        uuid = self._message_publication['uuid']
        chemin = '%s/plume/%s' % (webroot, uuid)
        shutil.rmtree(chemin)

    def _chemin_fichier(self):
        webroot = self._publicateur.webroot
        uuid = self._message_publication['uuid']
        titre = self._message_publication['titre']
        chemin = '%s/plume/%s/%s.html' % (webroot, uuid, titre)
        return chemin


class PublierCataloguePlume(ExporterVersHtml):

    def __init__(self, publicateur, message_publication):
        super().__init__(publicateur)
        self._publicateur = publicateur
        self._message_publication = message_publication
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def exporter_html(self, nom_section: str = 'PLUME'):
        super().exporter_html(nom_section)

    # def exporter_catalogue(self):
    #     nom_fichier = self._chemin_fichier()
    #     nom_fichier_staging = '%s.staging' % nom_fichier
    #
    #     with open(nom_fichier_staging, 'wb') as fichier:
    #         self.render_catalogue(fichier)
    #
    #     # Aucune erreur lancee, on renomme le fichier
    #     if os.path.exists(nom_fichier):
    #         os.remove(nom_fichier)
    #     os.rename(nom_fichier_staging, nom_fichier)
    #
    #     self.__logger.info("Fichier catalogue cree: %s" % nom_fichier)

    def render(self, fichier):
        # fichier.write('<html>\n'.encode('utf-8'))
        # fichier.write('<head><title>Plume</title>\n'.encode('utf-8'))
        # fichier.write('<meta charset="UTF-8">\n'.encode('utf-8'))
        # fichier.write('</head>\n<body>\n'.encode('utf-8'))
        fichier.write('<h1>Plume public</h1>\n'.encode('utf-8'))

        fichier.write('<div class="w3-col m12 w3-row-padding">'.encode('utf-8'))

        liste_documents = self._message_publication['documents']
        for uuid in liste_documents:
            document = liste_documents[uuid]
            titre = document['titre']
            titre_urlsafe = urllib.parse.quote(titre)
            categories = document['categories']
            date_modification = document['_mg-derniere-modification']
            date_modification = time.ctime(date_modification)

            fichier.write('<div class="w3-col m6">\n'.encode('utf-8'))
            fichier.write(('<a href="/plume/%s/%s.html">%s</a> ' % (uuid, titre_urlsafe, titre)).encode('utf-8'))
            fichier.write('</div>\n<div class="w3-col m3">'.encode('utf-8'))
            fichier.write(' '.join(categories).encode('utf-8'))
            fichier.write('</div>\n<div class="w3-col m3">'.encode('utf-8'))
            fichier.write(str(date_modification).encode('utf-8'))
            fichier.write('</div>\n'.encode('utf-8'))

        fichier.write('</div>\n'.encode('utf-8'))

        # fichier.write('</body>\n</html>\n'.encode('utf-8'))

    def exporter_categorie(self):
        pass

    def render_categorie(self):
        pass

    def _chemin_fichier(self):
        webroot = self._publicateur.webroot
        return '%s/plume/index.html' % webroot

    def supprimer_fichier(self):
        chemin = self._chemin_fichier()
        os.remove(chemin)


class PublierGrosFichiers:
    """
    Telecharge et sauvegarde un gros fichiers.

    Les fichiers vont sous /grosfichiers/YYYY/MM/DD/HH/mm/uuid-v4.dat  (public par definition, donc .dat)
    Les symlinks sont generes sous /images/...rep.../NOM_IMAGE.jpg, /video/...rep.../NOM_VIDEO.XXX ou /fichiers/...rep.../NOM_FICHIER.XXX
    """

    def __init__(self):
        pass


class PublierCertificat:

    def __init__(self, publicateur, message_publication):
        super().__init__()
        self._publicateur = publicateur
        self._message_publication = message_publication
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def _chemin_fichier(self):
        webroot = self._publicateur.webroot
        return '%s/certs' % webroot

    def _get_pem(self):
        cert_pem = self._message_publication[ConstantesSecurityPki.LIBELLE_CERTIFICAT_PEM]
        enveloppe = EnveloppeCertificat(certificat_pem=cert_pem)
        cn = enveloppe.subject_common_name
        ou = enveloppe.subject_organizational_unit_name
        org = enveloppe.subject_organization_name

        nom_fichier = '%s.%s.%s.cert.pem' % (cn, ou, org)
        return cert_pem, nom_fichier

    def exporter(self):
        cert_pem, nom_fichier = self._get_pem()
        dir_fichier = self._chemin_fichier()
        path_fichier = os.path.join(self._chemin_fichier(), nom_fichier)
        os.makedirs(dir_fichier, exist_ok=True)
        with open(path_fichier, 'w') as fichier:
            fichier.write(cert_pem)


class PublierCertificatCA(PublierCertificat):

    def _get_pem(self):
        cert_pem = self._message_publication[ConstantesSecurityPki.LIBELLE_CHAINE_PEM]
        enveloppe = EnveloppeCertificat(certificat_pem=cert_pem)
        org = enveloppe.subject_organization_name

        nom_fichier = '%s.CA.cert.pem' % org
        return cert_pem, nom_fichier

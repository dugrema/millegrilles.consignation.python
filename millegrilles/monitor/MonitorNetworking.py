import logging
import os
import datetime

from os import path
from base64 import b64decode
from threading import Event

from millegrilles import Constantes
from millegrilles.SecuritePKI import EnveloppeCertificat
from millegrilles.monitor import MonitorConstantes


class GestionnaireWeb:
    """
    S'occupe de la configuration des applications web, specifiquement nginx (via conf.d/modules)
    """
    def __init__(self, service_monitor, mode_dev=False):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__service_monitor = service_monitor
        self.__mode_dev = mode_dev
        self.__docker_client = service_monitor.gestionnaire_docker

        self.__init_complete = False
        self.__repertoire_modules = path.join('/var/opt/millegrilles/nginx/modules')
        self.__repertoire_data = path.join('/var/opt/millegrilles/nginx/data')
        self.__repertoire_html = path.join('/var/opt/millegrilles/nginx/html')
        self.__repertoire_ext = path.join('/var/opt/millegrilles/nginx/ext')

        self.__intervalle_entretien = datetime.timedelta(minutes=15)
        self.__prochain_entretien = datetime.datetime.utcnow()

    def entretien(self):
        if not self.__init_complete:
            self.__creer_repertoires()
            self.__init_complete = True

        now = datetime.datetime.utcnow()

        if self.__prochain_entretien < now:
            self.__prochain_entretien = now + self.__intervalle_entretien

            try:
                securite_monitor = self.__service_monitor.securite
            except NotImplementedError:
                # En cours d'installation, la securite n'est pas definie
                securite_monitor = None

            if securite_monitor is not None and securite_monitor != Constantes.SECURITE_PROTEGE:
                try:
                    config_mq = self.__service_monitor.get_info_connexion_mq(nowait=True)
                    hostname = config_mq['MQ_HOST']
                except KeyError:
                    try:
                        hostname = os.environ['MG_MQ_HOST']
                    except KeyError:
                        hostname = None

                if hostname is not None:
                    try:
                        self.__maj_proxypass_fichiers(hostname)
                    except AttributeError:
                        self.__logger.exception("Erreur configuration proxypass_fichiers")

            try:
                if not self.__service_monitor.is_dev_mode:

                    try:
                        info_acme = self.__service_monitor.get_certificat_acme()
                    except KeyError:
                        pass
                    else:
                        cert_acme_bytes = info_acme['chain']
                        key_bytes = info_acme['cle']
                        enveloppe_acme = EnveloppeCertificat(certificat_pem=cert_acme_bytes)

                        # Comparer certificat avec le plus recent dans docker
                        gestionnaire_docker = self.__service_monitor.gestionnaire_docker
                        cert_actuel_docker = gestionnaire_docker.charger_config_recente('pki.web.cert')
                        cert_actuel = b64decode(cert_actuel_docker['config'].attrs['Spec']['Data'].encode('utf-8'))
                        enveloppe_actuel = EnveloppeCertificat(certificat_pem=cert_actuel)

                        # Comparer les deux certificats via fingerprints
                        if enveloppe_acme.fingerprint != enveloppe_actuel.fingerprint:
                            self.__logger.info("Ajouter un nouveau certificat ACME a docker")
                            date_courante = datetime.datetime.utcnow().strftime(MonitorConstantes.DOCKER_LABEL_TIME)
                            gestionnaire_docker.sauvegarder_config('pki.web.cert.%s' % date_courante, cert_acme_bytes)
                            gestionnaire_docker.sauvegarder_secret('pki.web.key.%s' % date_courante, key_bytes)

                        # S'assurer d'utiliser les certificats les plus recents avec NGINX
                        gestionnaire_docker.maj_services_avec_certificat('web')

            except IndexError:
                self.__logger.info("entretien web : NGINX n'est pas demarre")
            except Exception:
                self.__logger.exception("Erreur entretien certificats web")

    def regenerer_configuration(self, mode_installe):
        self.__generer_fichiers_configuration(mode_installe=mode_installe)

        if mode_installe is True:
            # Si on est sur un noeud prive ou public, s'assurer de supprimer le certificat self-signed nginx
            securite_noeud = self.__service_monitor.securite
            if securite_noeud in [Constantes.SECURITE_PRIVE, Constantes.SECURITE_PUBLIC]:
                try:
                    gestionnaire_docker = self.__service_monitor.gestionnaire_docker
                    event_attente = Event()
                    self.__logger.info("Attente suppression service NGINX pour retirer cert/cle nginx")
                    for i in range(0, 5):
                        try:
                            gestionnaire_docker.supprimer_service('nginx')
                            event_attente.wait(5)
                        except IndexError:
                            break  # Ok, service retire
                    gestionnaire_docker.supprimer_config('pki.nginx.cert')
                    gestionnaire_docker.supprimer_secret('pki.nginx.key')
                except Exception:
                    self.__logger.exception("Erreur suppression pki.nginx.cert")

    def __creer_repertoires(self):
        # Verifier si les repertoires existent
        try:
            os.makedirs(self.__repertoire_modules, mode=0o770)
            self.__generer_fichiers_configuration()
        except FileExistsError:
            self.__logger.debug("Repertoire %s existe, ok" % self.__repertoire_modules)

        reps = [self.__repertoire_data, self.__repertoire_html, self.__repertoire_ext]
        for rep in reps:
            try:
                os.makedirs(rep, mode=0o775)
            except FileExistsError:
                self.__logger.debug("Repertoire %s existe, ok" % self.__repertoire_modules)

    def __maj_proxypass_fichiers(self, hostname: str = 'fichiers', port: str = '443'):
        """
        Compare et met a jour le fichiers proxypass_fichiers au besoin. Redemarre nginx s'il y a un changement.
        :param hostname:
        :param port:
        :return:
        """
        with open(path.join(self.__repertoire_modules, 'proxypass_fichiers.include'), 'r') as fichier:
            contenu_courant = fichier.read()

        config_proxypass = 'https://%s:%s' % (hostname, port)
        if config_proxypass not in contenu_courant:
            self.__logger.info("Reconfigurer proxypass_fichiers avec %s" % config_proxypass)
            configuration = """
set $upstream_fichiers %s; 
proxy_pass $upstream_fichiers;
            """ % config_proxypass
            with open(path.join(self.__repertoire_modules, 'proxypass_fichiers.include'), 'w') as fichier:
                fichier.write(configuration)
            self.redemarrer_nginx()

    def __generer_fichiers_configuration(self, mode_installe=False):
        """
        Genere et conserve la configuration courante
        :return:
        """
        nodename = self.__service_monitor.nodename
        hostname = self.__docker_client.hostname

        params = {
            'nodename': nodename,
            'hostname': hostname,
        }

        # server_content = """
        #     resolver 127.0.0.11 valid=30s;
        #     server_name {nodename}.local {nodename};
        # """.format(**params)
        # with open(path.join(self.__repertoire_modules, 'server_name.include'), 'w') as fichier:
        #     fichier.write(server_content)

        error_pages = """
error_page 401 = @error401;

# If the user is not logged in, redirect them to the login URL
location @error401 {
  return 307 https://{hostname}/millegrilles;
}
        """
        error_pages = error_pages.replace('{hostname}', params['hostname'])
        with open(path.join(self.__repertoire_modules, 'error_page.conf.include'), 'w') as fichier:
            fichier.write(error_pages)

        proxypass = """
set $upstream_protege https://web_protege:443; 
proxy_pass $upstream_protege;
        """
        with open(path.join(self.__repertoire_modules, 'proxypass.include'), 'w') as fichier:
            fichier.write(proxypass)

        proxypass_fichiers = """
set $upstream_fichiers https://fichiers:443; 
proxy_pass $upstream_fichiers;
"""
        with open(path.join(self.__repertoire_modules, 'proxypass_fichiers.include'), 'w') as fichier:
            fichier.write(proxypass_fichiers)

        app_coupdoeil = """
location /coupdoeil {
    set $upstream_coupdoeil https://coupdoeil:443;
    proxy_pass $upstream_coupdoeil;

    include /etc/nginx/conf.d/component_base_auth.include;
}
"""
        with open(path.join(self.__repertoire_modules, 'coupdoeil.app.location'), 'w') as fichier:
            fichier.write(app_coupdoeil)

        domaine_installeur = 'monitor'
        if self.__mode_dev:
            domaine_installeur = self.__service_monitor.nodename

        proxypass_installation = """
set $upstream_installation http://%s:8280;
proxy_pass $upstream_installation;
        """ % domaine_installeur
        with open(path.join(self.__repertoire_modules, 'proxypass_installation.include'), 'w') as fichier:
            fichier.write(proxypass_installation)

        resolver = """
resolver 127.0.0.11 valid=30s;
        """

        try:
            securite = self.__service_monitor.securite
        except NotImplementedError:
            # En cours d'installation
            securite = None

        if securite is not None and securite not in [Constantes.SECURITE_PUBLIC, Constantes.SECURITE_PRIVE]:
            # Mode prive ou protege - on ajoute les certs SSL client en option
            ssl_certs_content = """
ssl_certificate       /run/secrets/webcert.pem;
ssl_certificate_key   /run/secrets/webkey.pem;
ssl_stapling          on;
ssl_stapling_verify   on;

ssl_client_certificate /usr/share/nginx/files/certs/millegrille.cert.pem;
ssl_verify_client      optional;
ssl_verify_depth       1;
            """
        else:
            # Pas de certificat client SSL pour noeud public ou prive
            ssl_certs_content = """
ssl_certificate       /run/secrets/webcert.pem;
ssl_certificate_key   /run/secrets/webkey.pem;
ssl_stapling          on;
ssl_stapling_verify   on;
            """

        cache_content = """
# Configuration du cache NGINX pour les fichiers
proxy_cache_path /cache 
                 levels=1:2 
                 keys_zone=cache_fichiers:2m 
                 max_size=2g
                 inactive=4320m
                 use_temp_path=off;
        """

        if securite == Constantes.SECURITE_PUBLIC:
            # Noeud public, rediriger vers vitrine
            redirect_defaut = 'vitrine'
        elif self.__service_monitor.idmg or mode_installe:
            # Noeud prive ou protege, rediriger vers portail local millegrilles
            redirect_defaut = 'millegrilles'
        else:
            # Nouvelle installation, defaut vers installeur
            redirect_defaut = 'installation'

        # Sauvegarder les fichiers de configuration prets
        with open(path.join(self.__repertoire_modules, 'ssl_certs.conf.include'), 'w') as fichier:
            fichier.write(ssl_certs_content)
        with open(path.join(self.__repertoire_modules, 'resolver.conf'), 'w') as fichier:
            fichier.write(resolver)
        with open(path.join(self.__repertoire_modules, 'cache.conf.include'), 'w') as fichier:
            fichier.write(cache_content)

        # Redirection temporaire (307) vers le site approprie
        location_redirect_installation = """
location = / {
  return 307 https://$http_host/%s;
}
        """ % redirect_defaut

        location_fichiers_public = """
# Agit comme reverse-proxy pour distribuer les fichiers
location /fichiers {
  rewrite ^/fichiers/(.*)$ /fichiers_transfert/$1 last;
}

# Cache/proxy vers le noeud protege.
location /fichiers_transfert {
  slice 5m;
  proxy_cache       cache_fichiers;
  proxy_cache_lock  on;
  proxy_cache_background_update on;
  proxy_cache_use_stale error timeout updating
                        http_500 http_502 http_503 http_504;

  proxy_cache_key   $uri$is_args$args$slice_range;
  proxy_set_header  Range $slice_range;
  proxy_cache_valid 200 201 206 30d;
  proxy_cache_valid 401 403 404 500 502 503 504 1m;

  proxy_headers_hash_bucket_size 64;

  include /etc/nginx/conf.d/modules/proxypass_fichiers.include;

  # Mapping certificat client pour connexion consignation fichiers
  proxy_ssl_certificate         /run/secrets/nginx.cert.pem;
  proxy_ssl_certificate_key     /run/secrets/nginx.key.pem;
  proxy_ssl_trusted_certificate /usr/share/nginx/files/certs/millegrille.cert.pem;

  # NGINX protege utilise un certificat web (Let's Encrypt) - il faudrait mettre le cert SSL racine LE ici...
  #proxy_ssl_verify       on;
  #proxy_ssl_verify_depth 1;

  include /etc/nginx/conf.d/auth_public.include;
  include /etc/nginx/conf.d/component_base.include;
  include /etc/nginx/conf.d/component_cors.include;
}
        """

        with open(path.join(self.__repertoire_modules, 'fichiers_public.include'), 'w') as fichier:
            fichier.write(location_fichiers_public)

        location_fichiers_protege = """
location /fichiers {
  slice 5m;
  proxy_cache       cache_fichiers;
  proxy_cache_lock  on;
  proxy_cache_background_update on;
  proxy_cache_use_stale error timeout updating
                        http_500 http_502 http_503 http_504;

  proxy_cache_key   $uri$is_args$args$slice_range;
  proxy_set_header  Range $slice_range;
  proxy_cache_valid 200 201 206 30d;
  proxy_cache_valid 401 403 404 500 502 503 504 1m;

  proxy_headers_hash_bucket_size 64;

  include /etc/nginx/conf.d/modules/proxypass_fichiers.include;

  # Mapping certificat client pour connexion consignation fichiers
  proxy_ssl_certificate         /run/secrets/nginx.cert.pem;
  proxy_ssl_certificate_key     /run/secrets/nginx.key.pem;
  proxy_ssl_trusted_certificate /usr/share/nginx/files/certs/millegrille.cert.pem;

  proxy_ssl_verify       on;
  proxy_ssl_verify_depth 1;

  include /etc/nginx/conf.d/auth_public.include;
  include /etc/nginx/conf.d/component_base.include;
  include /etc/nginx/conf.d/component_cors.include;
}

# Configuration de transfert de fichiers entre systemes (verif client SSL seulement)
location /fichiers_transfert {
  include /etc/nginx/conf.d/modules/proxypass_fichiers.include;

  # Mapping certificat client pour connexion consignation fichiers
  proxy_ssl_certificate         /run/secrets/nginx.cert.pem;
  proxy_ssl_certificate_key     /run/secrets/nginx.key.pem;
  proxy_ssl_trusted_certificate /usr/share/nginx/files/certs/millegrille.cert.pem;
  proxy_ssl_verify              on;
  proxy_ssl_verify_depth        1;

  include /etc/nginx/conf.d/component_base.include;  # Active validation SSL client nginx, passe resultat dans headers
  include /etc/nginx/conf.d/component_cors.include;
}
        """
        with open(path.join(self.__repertoire_modules, 'fichiers_protege.include'), 'w') as fichier:
            fichier.write(location_fichiers_protege)

        # On a plusieurs options - une configuration par type de noeud (exclusif) et une qui permet
        # de rediriger les requetes sous /public vers un serveur tiers (e.g. AWS CloudFront)
        location_fichiers = "# include /etc/nginx/conf.d/modules/fichiers_rediriges.include;\n"
        if securite in [Constantes.SECURITE_PUBLIC, Constantes.SECURITE_PRIVE]:
            location_fichiers = location_fichiers + "include /etc/nginx/conf.d/modules/fichiers_public.include;"
        elif securite is not None:
            location_fichiers = location_fichiers + "include /etc/nginx/conf.d/modules/fichiers_protege.include;"

        location_installation_component = """
location %s {
    include /etc/nginx/conf.d/modules/proxypass_installation.include;
    include /etc/nginx/conf.d/component_base.include;
}
        """

        location_installation_paths = [
            "/installation",
            "/administration",
        ]

        certificats = """
location /certs {
  root /usr/share/nginx/files;
  include /etc/nginx/conf.d/component_cors.include;
}
        """

        locations_list = list()

        locations_list.append(location_redirect_installation)
        locations_list.append(location_fichiers)
        locations_list.append(certificats)
        locations_list.extend([location_installation_component % loc for loc in location_installation_paths])

        locations_content = '\n'.join(locations_list)
        with open(path.join(self.__repertoire_modules, 'locations.include'), 'w') as fichier:
            fichier.write(locations_content)

        # Fichier qui relie la configuration de tous les modules
        modules_includes_content = """
include /etc/nginx/conf.d/modules/cache.conf.include;
include /etc/nginx/conf.d/server.include;
        """
        with open(path.join(self.__repertoire_modules, 'modules_include.conf'), 'w') as fichier:
            fichier.write(modules_includes_content)

        try:
            # Supprimer nginx - docker va recreer les certs/cles pki.nginx et redeployer nginx automatiquement
            self.redeployer_nginx()
        except IndexError:
            pass  # OK, nginx n'est juste pas configure (pas de service, probablement en cours d'initialisation)

    def redemarrer_nginx(self):
        """
        Redemarre le service nginx
        :return:
        """
        try:
            self.__service_monitor.gestionnaire_docker.force_update_service('nginx')
        except AttributeError:
            self.__logger.warning("Redemarrage nginx - Aucuns services configures")

    def redeployer_nginx(self, force_update=False):
        """
        Met a jour la configuration de nginx (e.g. nouveau certificat web)
        Le service va etre redemarre si la configuration a change ou si le param force_update est True
        :param force_update: Si True, force le redemarrage du service - permet de recharger fichiers .conf des modules
        :return:
        """
        try:
            docker_nginx = self.__service_monitor.gestionnaire_docker.reconfigurer_service('nginx')

            if force_update:
                docker_nginx.force_update()
        except IndexError:
            self.__logger.warning("Reconfiguration nginx - le service n'est pas configure")

    def supprimer_nginx(self):
        docker_nginx = self.__service_monitor.gestionnaire_docker.get_service('nginx')
        docker_nginx.remove()

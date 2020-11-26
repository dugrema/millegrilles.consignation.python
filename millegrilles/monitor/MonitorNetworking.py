import logging
import os
import datetime

from os import path
# from typing import Union

from millegrilles import Constantes
# from millegrilles.monitor.ServiceMonitor import ServiceMonitor, ServiceMonitorDependant, ServiceMonitorPrincipal


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
                if not self.__service_monitor.is_dev_mode:
                    # S'assurer d'utiliser les certificats les plus recents avec NGINX
                    self.redeployer_nginx()

            except IndexError:
                self.__logger.info("entretien web : NGINX n'est pas demarre")

    def regenerer_configuration(self, mode_installe):
        self.__generer_fichiers_configuration(mode_installe=mode_installe)

    def __creer_repertoires(self):
        # Verifier si les repertoires existent
        try:
            os.makedirs(self.__repertoire_modules, mode=0o770)
            self.__generer_fichiers_configuration()
        except FileExistsError:
            self.__logger.debug("Repertoire %s existe, ok" % self.__repertoire_modules)

        reps = [self.__repertoire_data, self.__repertoire_html]
        for rep in reps:
            try:
                os.makedirs(rep, mode=0o775)
            except FileExistsError:
                self.__logger.debug("Repertoire %s existe, ok" % self.__repertoire_modules)

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

        domaine_installeur = 'monitor'
        if self.__mode_dev:
            domaine_installeur = self.__service_monitor.nodename

        proxypass_installation = """
set $upstream_installation http://%s:8080;
proxy_pass $upstream_installation;
        """ % domaine_installeur
        with open(path.join(self.__repertoire_modules, 'proxypass_installation.include'), 'w') as fichier:
            fichier.write(proxypass_installation)

        proxypass_vitrine = """
set $upstream_vitrine https://vitrine:443;
proxy_pass $upstream_vitrine;
        """
        with open(path.join(self.__repertoire_modules, 'proxypass_vitrine.include'), 'w') as fichier:
                fichier.write(proxypass_vitrine)

        resolver = """
resolver 127.0.0.11 valid=30s;
        """
        with open(path.join(self.__repertoire_modules, 'resolver.conf'), 'w') as fichier:
            fichier.write(resolver)

        ssl_certs_content = """
ssl_certificate       /run/secrets/webcert.pem;
ssl_certificate_key   /run/secrets/webkey.pem;
ssl_stapling          on;
ssl_stapling_verify   on;

ssl_client_certificate /usr/share/nginx/files/certs/millegrille.cert.pem;
ssl_verify_client      optional;
ssl_verify_depth       1;
        """
        with open(path.join(self.__repertoire_modules, 'ssl_certs.conf.include'), 'w') as fichier:
            fichier.write(ssl_certs_content)

        cache_content = """
# Configuration du cache NGINX pour les fichiers
proxy_cache_path /cache 
                 levels=1:2 
                 keys_zone=cache_fichiers:2m 
                 max_size=2g
                 inactive=4320m
                 use_temp_path=off;
        """
        with open(path.join(self.__repertoire_modules, 'cache.conf.include'), 'w') as fichier:
            fichier.write(cache_content)

        if self.__service_monitor.securite == Constantes.SECURITE_PUBLIC:
            # Noeud public, rediriger vers vitrine
            redirect_defaut = 'vitrine'
        elif self.__service_monitor.idmg or mode_installe:
            # Noeud prive ou protege, rediriger vers portail local millegrilles
            redirect_defaut = 'millegrilles'
        else:
            # Nouvelle installation, defaut vers installeur
            redirect_defaut = 'installation'

        # Redirection temporaire (307) vers le site approprie
        location_redirect_installation = """
location = / {
  return 307 https://$http_host/%s;
}
        """ % redirect_defaut

        location_data_vitrine = """
location /vitrine/sites {
  alias /var/opt/millegrilles/nginx/data/vitrine/sites;
}
location /vitrine/posts {
  alias /var/opt/millegrilles/nginx/data/vitrine/posts;
}
location /vitrine/collections {
  alias /var/opt/millegrilles/nginx/data/vitrine/collections;
}
        """

        location_fichiers = """
location /fichiers {
  proxy_cache       cache_fichiers;
  proxy_cache_lock  on;
  proxy_cache_background_update on;
  proxy_cache_use_stale error timeout updating
                        http_500 http_502 http_503 http_504;

  proxy_headers_hash_bucket_size 64;

  set $upstream_fichiers https://fichiers:443;
  proxy_pass $upstream_fichiers;

  # Mapping certificat client pour connexion consignation fichiers
  proxy_ssl_certificate         /run/secrets/nginx.cert.pem;
  proxy_ssl_certificate_key     /run/secrets/nginx.key.pem;
  proxy_ssl_trusted_certificate /usr/share/nginx/files/certs/millegrille.cert.pem;

  proxy_ssl_verify       on;
  proxy_ssl_verify_depth 1;

  include /etc/nginx/conf.d/auth_public.include;
  include /etc/nginx/conf.d/component_base.include;
}
        """

        location_public_component = """
location %s {
    include /etc/nginx/conf.d/modules/proxypass_vitrine.include;
    include /etc/nginx/conf.d/component_base.include;
}
        """
        location_priv_prot_component = """
location %s {
    include /etc/nginx/conf.d/modules/proxypass.include;
    include /etc/nginx/conf.d/component_base_auth.include;
}
        """
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
        location_public_paths = [
            "/vitrine",
        ]
        location_priv_prot_paths = [
            "/coupdoeil",
            "/senseurspassifs",
            "/grosfichiers",
            "/publication",
        ]

        certificats = """
location /certs {
  root /usr/share/nginx/files;
}
        """

        locations_list = list()
        locations_list.append(location_redirect_installation)
        locations_list.append(location_data_vitrine)
        locations_list.append(location_fichiers)
        locations_list.append(certificats)
        locations_list.extend([location_public_component % loc for loc in location_public_paths])
        locations_list.extend([location_priv_prot_component % loc for loc in location_priv_prot_paths])
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
        docker_nginx = self.__service_monitor.gestionnaire_docker.reconfigurer_service('nginx')

        if force_update:
            docker_nginx.force_update()

    def supprimer_nginx(self):
        docker_nginx = self.__service_monitor.gestionnaire_docker.get_service('nginx')
        docker_nginx.remove()

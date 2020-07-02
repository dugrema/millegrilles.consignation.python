import logging
import os
from os import path
# from typing import Union

# from millegrilles.monitor.ServiceMonitor import ServiceMonitor, ServiceMonitorDependant, ServiceMonitorPrincipal


class GestionnaireWeb:
    """
    S'occupe de la configuration des applications web, specifiquement nginx (via conf.d/modules)
    """

    #def __init__(self, idmg: str, service_monitor: Union[ServiceMonitor, ServiceMonitorDependant, ServiceMonitorPrincipal]):
    def __init__(self, idmg: str, service_monitor):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__idmg = idmg
        self.__service_monitor = service_monitor
        self.__docker_client = service_monitor.gestionnaire_docker

        self.__init_complete = False
        self.__repertoire_modules = path.join('/var/opt/millegrilles', self.__idmg, 'mounts/nginx/conf.d/modules')
        self.__repertoire_data = path.join('/var/opt/millegrilles', self.__idmg, 'mounts/nginx/data')

    def entretien(self):
        if not self.__init_complete:
            self.__creer_repertoires()
            self.__init_complete = True

    def __creer_repertoires(self):
        # Verifier si les repertoires existent
        try:
            os.makedirs(self.__repertoire_modules, mode=0o770)
            self.__generer_fichiers_configuration()
        except FileExistsError:
            self.__logger.debug("Repertoire %s existe, ok" % self.__repertoire_modules)

        try:
            os.makedirs(self.__repertoire_data, mode=0o775)
        except FileExistsError:
            self.__logger.debug("Repertoire %s existe, ok" % self.__repertoire_modules)

    def __generer_fichiers_configuration(self):
        """
        Genere et conserve la configuration courante
        :return:
        """
        nodename = self.__service_monitor.nodename

        params = {
            'nodename': nodename,
        }

        server_content = """
            resolver 127.0.0.11 valid=30s;
            server_name {nodename}.local {nodename};
        """.format(**params)
        with open(path.join(self.__repertoire_modules, 'server_name.include'), 'w') as fichier:
            fichier.write(server_content)

        proxypass = "set $upstream https://web_protege:443; proxy_pass $upstream;"
        with open(path.join(self.__repertoire_modules, 'proxypass.include'), 'w') as fichier:
            fichier.write(proxypass)

        ssl_certs_content = """
            ssl_certificate       /run/secrets/webcert.pem;
            ssl_certificate_key   /run/secrets/webkey.pem;
            ssl_stapling          on;
            ssl_stapling_verify   on;
        """
        with open(path.join(self.__repertoire_modules, 'ssl_certs.conf.include'), 'w') as fichier:
            fichier.write(ssl_certs_content)

        location_data_vitrine = """
            location /vitrine/data {
                alias /var/opt/millegrilles/%s/mounts/nginx/data;
            }
        """ % self.__idmg

        location_public_component = """
            location %s {
                include /etc/nginx/conf.d/modules/proxypass.include;
                include /etc/nginx/conf.d/component_base.include;
            }
        """
        location_priv_prot_component = """
            location %s {
                include /etc/nginx/conf.d/modules/proxypass.include;
                include /etc/nginx/conf.d/component_base_auth.include;
            }
        """
        location_public_paths = [
            "/vitrine",
        ]
        location_priv_prot_paths = [
            "/coupdoeil",
            "/posteur",
            "/messagerie",
        ]

        locations_list = list()
        locations_list.append(location_data_vitrine)
        locations_list.extend([location_public_component % loc for loc in location_public_paths])
        locations_list.extend([location_priv_prot_component % loc for loc in location_priv_prot_paths])

        locations_content = '\n'.join(locations_list)

        with open(path.join(self.__repertoire_modules, 'locations.include'), 'w') as fichier:
            fichier.write(locations_content)

        # Fichier qui relie la configuration de tous les modules
        modules_includes_content = """
            include /etc/nginx/conf.d/server.include;
        """
        with open(path.join(self.__repertoire_modules, 'modules_include.conf'), 'w') as fichier:
            fichier.write(modules_includes_content)

        self.__redemarrer_nginx()

    def __redemarrer_nginx(self):
        """
        Redemarre le service nginx
        :return:
        """
        self.__service_monitor.gestionnaire_docker.force_update_service('nginx')
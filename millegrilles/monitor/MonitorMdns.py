# Module mdns pour exposer services et recevoir events de presence
from zeroconf import ServiceInfo, ServiceBrowser, Zeroconf, IPVersion, ServiceListener
from typing import Optional
import socket
import logging
import json

from millegrilles.util.IpUtils import get_local_ips


class MdnsGestionnaire:

    def __init__(self, monitor):
        self.__monitor = monitor
        self.__browser = MdnsBrowser(monitor)

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def get_service(self, idmg: str, type_service: str = None) -> list:
        idmg_info = self.__browser.listener.service_par_idmg.get(idmg)
        if idmg_info:
            if type_service:
                return [serv for serv in idmg_info.values() if serv['type'].startswith(type_service)]
            else:
                return idmg_info.values()
        else:
            self.__logger.debug("Aucun service mdns pour idmg : %s" % idmg)

        return list()

    def fermer(self):
        # self.__service.fermer()
        self.__browser.fermer()


# class MdnsService:
#     """
#     Permet d'exposer des services via mdns. Supporte ipv4 et ipv6.
#     """
#
#     def __init__(self, monitor):
#         self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
#         self.services_exposes = dict()
#         self.ipv4: Optional[str] = None
#         self.ipv6: Optional[str] = None
#         self.hostname: Optional[str] = None
#         self.zeroconf_ipv4: Optional[Zeroconf] = None
#         self.zeroconf_ipv6: Optional[Zeroconf] = None
#
#         self.monitor = monitor
#
#         self.__detecter_adresses()
#
#         self.desc = dict()
#         if self.monitor.idmg:
#             self.desc['idmg'] = self.monitor.idmg
#
#         if self.ipv4:
#             self.__logger.info("Initialisation de services zeroconf sur ipv4: %s" % self.ipv4)
#             self.zeroconf_ipv4 = Zeroconf(ip_version=IPVersion.V4Only)
#
#         if self.ipv6:
#             self.__logger.info("Initialisation de services zeroconf sur ipv6: %s" % self.ipv6)
#             self.zeroconf_ipv6 = Zeroconf(ip_version=IPVersion.V6Only)
#
#     def __detecter_adresses(self):
#         ips = get_local_ips()
#         self.ipv4 = ips.get('ipv4')
#         self.ipv6 = ips.get('ipv6')
#         self.hostname = socket.gethostname()
#
#     def ajouter_service(self, nom_service: str, type_service: str, port: int, properties: dict = None):
#         if self.ipv4:
#             service_ipv4 = self.__creer_service(socket.AF_INET, nom_service, type_service, port)
#             self.zeroconf_ipv4.register_service(service_ipv4)
#
#         if self.ipv6:
#             service_ipv6 = self.__creer_service(socket.AF_INET6, nom_service, type_service, port)
#             self.zeroconf_ipv6.register_service(service_ipv6)
#
#     def __creer_service(self, type_ip: int, nom_service: str, type_service: str, port: int, properties: dict = None):
#         if type_ip == socket.AF_INET:
#             adresse_ip = self.ipv4
#         elif type_ip == socket.AF_INET6:
#             adresse_ip = self.ipv6
#         else:
#             raise ValueError("Type ip invalide : %d" % type_ip)
#
#         if not properties:
#             properties = dict()
#         properties.update(self.desc)
#
#         info = ServiceInfo(
#             type_service,
#             nom_service + "." + type_service,
#             parsed_addresses=[adresse_ip],
#             port=port,
#             properties=properties,
#             # server=self.hostname,
#         )
#
#         return info
#
#     def fermer(self):
#         if self.zeroconf_ipv4:
#             self.zeroconf_ipv4.unregister_all_services()
#             self.zeroconf_ipv4.close()
#         if self.zeroconf_ipv6:
#             self.zeroconf_ipv6.unregister_all_services()
#             self.zeroconf_ipv6.close()


class MdnsBrowser:

    def __init__(self, monitor):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.zeroconf: Optional[Zeroconf] = None

        service_types = [
            '_mghttps._tcp.local.',
            '_mgamqps._tcp.local.',
        ]
        self.listener = MdnsListener(monitor)

        # Activer zeroconf avec IPv4 et IPv6 (all)
        try:
            self.zeroconf = Zeroconf(ip_version=IPVersion.All)
            self.browser = ServiceBrowser(self.zeroconf, service_types, listener=self.listener)
        except OSError:
            self.__logger.warning("Erreur chargement mdns avec IPv4 et IPv6, tenter de charger avec IPv4 uniquement")
            self.zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
            self.browser = ServiceBrowser(self.zeroconf, service_types, listener=self.listener)

    def fermer(self):
        self.zeroconf.unregister_all_services()
        self.zeroconf.close()


class MdnsListener(ServiceListener):

    def __init__(self, monitor):
        self.monitor = monitor
        self.service_par_idmg = dict()
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def remove_service(self, zeroconf, type, name):
        self.__logger.debug("Service %s removed" % (name,))

        info = zeroconf.get_service_info(type, name)
        texte_dict = info.properties

        try:
            idmg = texte_dict[b'idmg'].decode('utf-8')
            info_service = self.service_par_idmg.get(idmg)

            if info_service:
                service_name = info.name
                del info_service[service_name]
        except KeyError:
            pass

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        self.__logger.debug("Service %s added, service info: %s" % (name, info))

        if info:
            self._maj_entree(zeroconf, type, name, info)

    def update_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        self.__logger.debug("Service %s updated, service info: %s" % (name, info))

        if info:
            self._maj_entree(zeroconf, type, name, info)

    def _maj_entree(self, zeroconf, type, name, info):
        texte_dict = info.properties
        idmg_b = texte_dict.get(b'idmg')
        est_millegrilles = texte_dict.get(b'millegrilles')

        # Verifier que ce n'est pas une adresse locale (avahi n'en tien pas compte)
        addresses = [socket.inet_ntoa(addr) for addr in info.addresses]
        addresses = [addr for addr in addresses if not addr.startswith('127.') and not addr.startswith('172.')]

        if not idmg_b and est_millegrilles:
            idmg_b = b'nouveau'

        if len(addresses) and idmg_b:
            idmg = idmg_b.decode('utf-8')
            info_service = self.service_par_idmg.get(idmg)
            if not info_service:
                info_service = dict()
                self.service_par_idmg[idmg] = info_service

            service_name = info.name
            server = info.server
            port = info.port

            information_service = {
                'idmg': idmg,
                'name': service_name,
                'type': type,
                'server': server,
                'port': port,
                'addresses': addresses,
            }

            info_service[service_name] = information_service

            # addresses = [socket.inet_ntoa(addr) for addr in info.addresses]
            self.__logger.debug("Entree monitor, idmg: %s, name: %s, server: %s, addresses: %s, port: %d" % (idmg, service_name, server, addresses, port))

            print("Liste services totales:\n%s" % json.dumps(self.service_par_idmg, indent=2))

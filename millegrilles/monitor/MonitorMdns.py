# Module mdns pour exposer services et recevoir events de presence
from zeroconf import ServiceInfo, ServiceBrowser, Zeroconf, IPVersion
from typing import Optional
import socket
import logging

from millegrilles.util.IpUtils import get_local_ips


class MdnsGestionnaire:

    def __init__(self, monitor):
        self.__monitor = monitor
        self.__service = MdnsService(monitor)
        self.__browser = MdnsBrowser(monitor)

    def ajouter_service(self, nom_service: str, type_service: str, port: int, properties: dict = None):
        self.__service.ajouter_service(nom_service, type_service, port, properties)

    def fermer(self):
        self.__service.fermer()
        self.__browser.fermer()


class MdnsService:
    """
    Permet d'exposer des services via mdns. Supporte ipv4 et ipv6.
    """

    def __init__(self, monitor):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.services_exposes = dict()
        self.ipv4: Optional[str] = None
        self.ipv6: Optional[str] = None
        self.hostname: Optional[str] = None
        self.zeroconf_ipv4: Optional[Zeroconf] = None
        self.zeroconf_ipv6: Optional[Zeroconf] = None

        self.monitor = monitor

        self.__detecter_adresses()

        self.desc = dict()
        if self.monitor.idmg:
            self.desc['idmg'] = self.monitor.idmg

        if self.ipv4:
            self.__logger.info("Initialisation de services zeroconf sur ipv4: %s" % self.ipv4)
            self.zeroconf_ipv4 = Zeroconf(ip_version=IPVersion.V4Only)

        if self.ipv6:
            self.__logger.info("Initialisation de services zeroconf sur ipv6: %s" % self.ipv6)
            self.zeroconf_ipv6 = Zeroconf(ip_version=IPVersion.V6Only)

    def __detecter_adresses(self):
        ips = get_local_ips()
        self.ipv4 = ips.get('ipv4')
        self.ipv6 = ips.get('ipv6')
        self.hostname = socket.gethostname()

    def ajouter_service(self, nom_service: str, type_service: str, port: int, properties: dict = None):
        if self.ipv4:
            service_ipv4 = self.__creer_service(socket.AF_INET, nom_service, type_service, port)
            self.zeroconf_ipv4.register_service(service_ipv4)

        if self.ipv6:
            service_ipv6 = self.__creer_service(socket.AF_INET6, nom_service, type_service, port)
            self.zeroconf_ipv6.register_service(service_ipv6)

    def __creer_service(self, type_ip: int, nom_service: str, type_service: str, port: int, properties: dict = None):
        if type_ip == socket.AF_INET:
            adresse_ip = self.ipv4
        elif type_ip == socket.AF_INET6:
            adresse_ip = self.ipv6
        else:
            raise ValueError("Type ip invalide : %d" % type_ip)

        if not properties:
            properties = dict()
        properties.update(self.desc)

        info = ServiceInfo(
            type_service,
            nom_service + "." + type_service,
            parsed_addresses=[adresse_ip],
            port=port,
            properties=properties,
            # server=self.hostname,
        )

        return info

    def fermer(self):
        if self.zeroconf_ipv4:
            self.zeroconf_ipv4.unregister_all_services()
            self.zeroconf_ipv4.close()
        if self.zeroconf_ipv6:
            self.zeroconf_ipv6.unregister_all_services()
            self.zeroconf_ipv6.close()


class MdnsBrowser:

    def __init__(self, monitor):
        # Activer zeroconf avec IPv4 et IPv6 (all)
        self.zeroconf = Zeroconf(ip_version=IPVersion.All)

        service_types = [
            '_mgmonitor._tcp.local.',
            '_amqps._tcp.local.',
        ]

        self.listener = MdnsListener(monitor)
        self.browser = ServiceBrowser(self.zeroconf, service_types, self.listener)

    def fermer(self):
        self.zeroconf.unregister_all_services()
        self.zeroconf.close()


class MdnsListener:

    def __init__(self, monitor):
        self.monitor = monitor

    def remove_service(self, zeroconf, type, name):
        print("Service %s removed" % (name,))

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        print("Service %s added, service info: %s" % (name, info))
        if name.startswith('millegrilles.monitor'):
            self.traiter_monitor(zeroconf, type, name)

    def update_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        print("Service %s updated, service info: %s" % (name, info))
        if name.startswith('millegrilles.monitor'):
            self.traiter_monitor(zeroconf, type, name)

    def traiter_monitor(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        texte_dict = info.properties
        idmg = texte_dict[b'idmg'].decode('utf-8')
        server = info.server
        port = info.port
        addresses = [socket.inet_ntoa(addr) for addr in info.addresses]
        print("Entree monitor, idmg: %s, server: %s, addresses: %s, port: %d" % (idmg, server, addresses, port))

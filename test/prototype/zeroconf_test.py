from zeroconf import ServiceInfo, ServiceBrowser, Zeroconf, IPVersion
import socket

from millegrilles.util.IpUtils import get_local_ips

ips = get_local_ips()
print(ips)


class MyInfo:

    def __init__(self):
        # hostname = socket.gethostname()

        self.ip_addresses = get_local_ips()
        self.desc = {'idmg': 'ABCD1234'}
        self.service_type = '_amqps._tcp.local.'

        self.info_v4 = None
        self.info_v6 = None
        self.info_all = None

    def register_v4(self, zeroconf):
        self.info_v4 = ServiceInfo(
            self.service_type,
            "millegrilles." + self.service_type,
            # addresses=[socket.inet_aton(ip_addresses[0])],
            parsed_addresses=[self.ip_addresses['ipv4']],
            port=8080,
            properties=self.desc,
            # server=hostname,
        )
        zeroconf.register_service(self.info_v4)

    def register_v6(self, zeroconf):
        self.info_v6 = ServiceInfo(
            self.service_type,
            "millegrilles." + self.service_type,
            # addresses=[socket.inet_aton(ip_addresses[0])],
            parsed_addresses=[self.ip_addresses['ipv6']],
            port=8080,
            properties=self.desc,
            # server=hostname,
        )
        zeroconf.register_service(self.info_v6)


class MyListener:

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


zeroconf = Zeroconf(ip_version=IPVersion.All)
zeroconf_v4 = Zeroconf(ip_version=IPVersion.V4Only)
zeroconf_v6 = Zeroconf(ip_version=IPVersion.V6Only)

listener = MyListener()
my_info = MyInfo()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)

try:
    my_info.register_v4(zeroconf_v4)
    my_info.register_v6(zeroconf_v6)
    input("Press enter to exit...\n\n")
finally:
    zeroconf.unregister_all_services()
    zeroconf_v4.unregister_all_services()
    zeroconf_v6.unregister_all_services()
    zeroconf.close()
    zeroconf_v4.close()
    zeroconf_v6.close()


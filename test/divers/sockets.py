import socket
from millegrilles.util import IpUtils

#adresse = socket.gethostbyname('www.maple.millegrilles.mdugre.info')
#print(str(adresse))

print("Hostname : " + socket.gethostname())
print("IP: %s" % socket.gethostbyname(socket.gethostname()))

local_ips = IpUtils.get_local_ips()
print("Local ips : %s" % str(local_ips))

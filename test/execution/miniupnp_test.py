import miniupnpc
import time
import inspect

print('miniupnpc - %s' % str(miniupnpc))

# Information
# https://github.com/miniupnp/miniupnp/blob/master/miniupnpc/testupnpigd.py

upnp = miniupnpc.UPnP()

members = inspect.getmembers(upnp, predicate=inspect.ismethod)
print("Inspect members of UPnP:\n%s" % str(members))

upnp.discoverdelay = 10
upnp.discover()

upnp.selectigd()

port1 = 43210

print("Ouverture %d" % port1)
# addportmapping(external-port, protocol, internal-host, internal-port, description, remote-host)
# upnp.addportmapping(port, 'TCP', upnp.lanaddr, port, 'testing', '')
# resultat_ajout = upnp.addportmapping(5122, 'TCP', upnp.lanaddr, 22, 'ssh dev2', '')
# print('Ajout port 5122: %s' % str(resultat_ajout))

# resultat_ajout = upnp.addportmapping(5163, 'TCP', upnp.lanaddr, 5163, 'MQ', '')
# print('Ajout port 5163: %s' % str(resultat_ajout))
# resultat_ajout = upnp.addportmapping(80, 'TCP', upnp.lanaddr, 80, 'http', '')
# print('Ajout port 80: %s' % str(resultat_ajout))
# resultat_ajout = upnp.addportmapping(443, 'TCP', upnp.lanaddr, 443, 'https', '')
# print('Ajout port 443: %s' % str(resultat_ajout))


print("Port %d ouvert?" % port1)

# display information about the IGD and the internet connection
print('local ip address : %s' % upnp.lanaddr)
externalipaddress = upnp.externalipaddress()
print('external ip address %s:' % externalipaddress)
print('Status info: %s, %s' % (upnp.statusinfo(), upnp.connectiontype()))

port = 0
proto = 'UDP'

print('list the redirections :')
i = 0
while True:
    p = upnp.getgenericportmapping(i)
    if p is None:
        break
    print('%s %s' % (i, p))
    i = i + 1

    mapping = {
        'port_ext': p[0],
        'protocol': p[1],
        'ip_int': p[2][0],
        'port_int': p[2][1],
        'nom': p[3],
    }

    print(str(mapping))

# print('%s' % upnp.getspecificportmapping(port, proto))
# try:
#     print('%s' % upnp.getportmappingnumberofentries())
# except Exception as e:
#   print('GetPortMappingNumberOfEntries() is not supported : %s' % e)
#
# fw_status = upnp.upnp_getfirewallstatus()
# print('%s' % fw_status)

# time.sleep(3)

print("Suppression mappings")

resultat_delete = upnp.deleteportmapping(80, 'TCP')   # NoSuchEntryInArray
resultat_delete = upnp.deleteportmapping(443, 'TCP')   # NoSuchEntryInArray
# resultat_delete = upnp.deleteportmapping(5173, 'TCP')   # NoSuchEntryInArray


# upnp.deleteportmapping(port1, 'TCP')
resultat_delete = upnp.deleteportmapping(5163, 'TCP')   # NoSuchEntryInArray
print('Delete: %s' % str(resultat_delete))
# resultat_delete = upnp.deleteportmapping(443, 'TCP')   # NoSuchEntryInArray
# print('Delete: %s' % str(resultat_delete))



print("Termine")

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
# upnp.addportmapping(5122, 'TCP', upnp.lanaddr, 22, 'ssh dev2', '')

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
# upnp.deleteportmapping(port1, 'TCP')
upnp.deleteportmapping(5122, 'TCP')

print("Termine")

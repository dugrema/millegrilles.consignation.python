import miniupnpc
import time

# Information
# https://github.com/miniupnp/miniupnp/blob/master/miniupnpc/testupnpigd.py

upnp = miniupnpc.UPnP()

upnp.discoverdelay = 10
upnp.discover()

upnp.selectigd()

port = 43210

print("Ouverture %d" % port)
# addportmapping(external-port, protocol, internal-host, internal-port, description, remote-host)
upnp.addportmapping(port, 'TCP', upnp.lanaddr, port, 'testing', '')
upnp.addportmapping(5122, 'TCP', upnp.lanaddr, 22, 'ssh dev2', '')

print("Port %d ouvert?" % port)

# display information about the IGD and the internet connection
print('local ip address : %s' % upnp.lanaddr)
externalipaddress = upnp.externalipaddress()
print('external ip address %s:' % externalipaddress)
print('%s, %s' % (upnp.statusinfo(), upnp.connectiontype()))

time.sleep(60)

print("Suppression mappings")
upnp.deleteportmapping(port, 'TCP')
upnp.deleteportmapping(5122, 'TCP')

print("Termine")

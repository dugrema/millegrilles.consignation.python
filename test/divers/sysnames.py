import os
import socket

print(str(os.uname()))

print('uname.nodename: %s' % os.uname().nodename)
print('socket.gethostname(): %s' % socket.gethostname())

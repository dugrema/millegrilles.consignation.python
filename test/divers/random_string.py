import os
import binascii

test = os.urandom(4)

print(str(test))

test = binascii.hexlify(test)

print(test.decode('utf8'))
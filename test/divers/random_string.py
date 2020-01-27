import os
import binascii

test = os.urandom(4)

print(str(test))

test = binascii.hexlify(test)

test_string = test.decode('utf8')

print(test_string)

test_back = binascii.unhexlify(test_string.encode('utf8'))

print(test_back)


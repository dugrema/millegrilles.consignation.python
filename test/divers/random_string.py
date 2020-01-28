import os
import binascii
import struct

test = os.urandom(3)
print(str(test))
test = binascii.hexlify(test)
test_string = test.decode('utf8')
print(test_string)
test_back = binascii.unhexlify(test_string.encode('utf8'))
print(test_back)

result = bytes(b'\x00\x00') + test_back + bytes(3)
print(binascii.hexlify(result))

print("Resultat unpack : %s " % hex(struct.unpack('Q', result)[0]))


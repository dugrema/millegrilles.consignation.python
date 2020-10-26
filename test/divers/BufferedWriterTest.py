from io import BufferedWriter, RawIOBase
import lzma

from typing import Optional


class MonWriter(RawIOBase):

    def __init__(self):
        super().__init__()
        self.__output = open('/tmp/output.xz', 'wb')

    def write(self, __b) -> Optional[int]:
        print(__b)
        return self.__output.write(__b)

    def close(self):
        print("Fermer")
        self.__output.close()


if __name__ == '__main__':
    writer = MonWriter()
    with lzma.open(writer, 'w') as xz:
        xz.write(b'allo_toi')
        xz.write(b'encore')


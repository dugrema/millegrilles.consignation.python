import logging

from typing import Optional
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger('__main__')
logger.setLevel(logging.DEBUG)


class Generer:

    def __init__(self):
        self.keypair: Optional[ed25519.Ed25519PrivateKey] = None

    def generer_keypair(self):
        logger.debug("Generer keypair")
        self.keypair = ed25519.Ed25519PrivateKey.generate()
        logger.debug("Keypair genere : %s" % str(self.keypair))

    def exporter_keypair(self):
        private_bytes = self.keypair.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        )
        logger.debug("Private Key SSH:\n%s" % private_bytes.decode('utf-8'))

        public_key = self.keypair.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        )
        logger.debug("Public Key\n%s mathieu@serveur1" % public_bytes.decode('utf-8'))

if __name__ == '__main__':
    logging.basicConfig()
    generer = Generer()
    generer.generer_keypair()
    generer.exporter_keypair()

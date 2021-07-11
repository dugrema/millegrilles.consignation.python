import multibase
import secrets

from cryptography.hazmat.primitives.serialization import load_pem_public_key

from fido2.client import ClientData
from fido2.ctap2 import AuthenticatorData, AttestedCredentialData
from fido2.server import Fido2Server
from fido2.cose import ES256, RS256  #, EdDSA

from fido2.webauthn import PublicKeyCredentialRpEntity


CRYPTOGRAPHY_COSE_ALGO_MATCH = {
    'secp256r1': ES256,  # -7
    'rs256': RS256,      # -257
    # '??edd25519': EdDSA,  # -8
}


class Webauthn:

    def __init__(self, idmg: str):
        self.idmg = idmg

    def generer_challenge_auth(self, url_site: str, creds: list):
        """
        Genere un challenge d'authentification pour le site specifie avec les creds d'un compte usager.
        :param url_site: Site qui demande la verification
        :param creds: Partie "webauthn" du compte usager (MaitreDesComptes/usagers)
        :return:
        """
        # Generer un challenge aleatoire.
        # Va etre utilise pour verifier que la signature est bien une reponse au challenge.
        challenge_bytes = secrets.token_bytes(128)

        creds_ajuste = list()
        for cred in creds:
            cred_ajuste = {
                'id': cred['credId'],
                'type': cred['type'],
            }
            creds_ajuste.append(cred_ajuste)

        challenge = {
            'challenge': multibase.encode('base64', challenge_bytes).decode('utf-8'),
            'timeout': 60000,
            'rpId': url_site,
            'userVerification': 'preferred',
            'allowCredentials': creds_ajuste,
            'hostname': url_site,
        }

        return challenge

    def authenticate_complete(self, url_site: str, assertions: dict, auth_response: dict, user_webauthn: list):
        # data = cbor.decode(request.get_data())

        credentials = []

        for cred in user_webauthn:
            cred_bytes = multibase.decode(cred['credId'])
            aaguid = bytes(16)  # Dummy
            cred_id = cred_bytes
            pk_str = cred['publicKeyPem']

            # Charger cle public avec cryptography
            pk = load_pem_public_key(pk_str.encode('utf-8'))
            public_numbers = pk.public_numbers()
            try:
                algo_name = public_numbers.curve.name
            except AttributeError:
                # Pas une courbe elliptique
                try:
                    public_numbers.n
                    algo_name = 'rs256'
                except AttributeError:
                    raise Exception('Algorithme cle publique inconnu : %s' % str(cred))

            # Convertir cle en format COSE pour la verification
            cls_cose = CRYPTOGRAPHY_COSE_ALGO_MATCH[algo_name]
            pk = cls_cose.from_cryptography_key(pk)

            cred_ajuste = AttestedCredentialData.create(aaguid, cred_id, pk)
            credentials.append(cred_ajuste)

        challenge_data = {
            'challenge': assertions['challenge'][1:],
            'rpId': assertions['rpId'],
            'user_verification': 'preferred',
        }

        rp = PublicKeyCredentialRpEntity(url_site, self.idmg)
        server = Fido2Server(rp)

        credential_id = multibase.decode(auth_response["id64"])
        response = auth_response['response']
        client_data = ClientData(multibase.decode(response["clientDataJSON"]))
        auth_data = AuthenticatorData(multibase.decode(response["authenticatorData"]))
        signature = multibase.decode(response["signature"])

        print("clientData", client_data)
        print("AuthenticatorData", auth_data)

        server.authenticate_complete(
            challenge_data,
            credentials,
            credential_id,
            client_data,
            auth_data,
            signature,
        )

        print("Authentication OK!")

        return True

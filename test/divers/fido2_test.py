import json
import multibase

from fido2.webauthn import PublicKeyCredentialRpEntity
from fido2.client import ClientData
from fido2.server import Fido2Server
from fido2.ctap2 import AttestationObject, AuthenticatorData
from fido2 import cbor

from millegrilles.util.Webauthn import Webauthn


rp = PublicKeyCredentialRpEntity("localhost", "Demo server")
server = Fido2Server(rp)

dummy_credentials = [
    {
        "credId": "mld9rxDrmQSa5uTGdhd7tcG5lsyNZ1J2EgG0F3bTJ9K70ei5cWXK5WUdKO+DZfH5ehtFAcs5f6pyIVa1qB9rUHvlZOyCeYAMVjxQvb/RyDC+PvbpY94xbhCHP0yPHY3iY",
        "counter": 0,
        "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKGJ7YllJiMF/qxeEsxtxzvG1p4fn\nVf1sMJNxW8vzgmLwin6W0OEIR5tzh1h1IEJxrkW2LhRYXxZwtqG/rlp2Iw==\n-----END PUBLIC KEY-----\n",
        "type": "public-key"
    },
    {
        "credId": "mSbarAWTp1e1VlOyoK1Ciux/yVTjKt49m738Xi4N6HvBWEQ0I0aCt0PNDFyU5V2vZxB6PM96ftQUv7RBj9eEF6vLhXIBcr7pU3MfjvZ0wxB1yGdj2AJ9PynAjydWIzSvd",
        "counter": 0,
        "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmJXfUtXfNWhqqomXoRmysulr0hdj\nTAlVCrrjQlSDlLwilpyTFpXmZZK70S2YlB30qdX4NqOGVKvcerz70m0TYg==\n-----END PUBLIC KEY-----\n",
        "type": "public-key"
    }
]

dummy_challenge = {
    "challenge": 'mN7+BUvC+QZL2Q+Xzxeb9w1gSK+t1GcCFcz/FZYOczmtXYbHKXnS/Oe6siWzWfZZZOl53CMSj2jfvz68CEB9OTJfaQ7FkCTpZB9F36fsFerJgUJAmzDloA48VlkrW6fqPvs87m6hudrVdxYyK04wAP3vudFrlyDZfFpRaKHW1hRA',
    "rpId": 'mg-dev4.maple.maceroc.com'
}

dummy_response = {
  "id64": 'mSbarAWTp1e1VlOyoK1Ciux/yVTjKt49m738Xi4N6HvBWEQ0I0aCt0PNDFyU5V2vZxB6PM96ftQUv7RBj9eEF6vLhXIBcr7pU3MfjvZ0wxB1yGdj2AJ9PynAjydWIzSvd',
  "response": {
    "authenticatorData": "mXlKhqDgMWprKE3rlMr02qmlCJFm/jp1XZO+iT4bTTDYBAAAdWA",
    "clientDataJSON": "meyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiTjctQlV2Qy1RWkwyUS1YenhlYjl3MWdTSy10MUdjQ0Zjel9GWllPY3ptdFhZYkhLWG5TX09lNnNpV3pXZlpaWk9sNTNDTVNqMmpmdno2OENFQjlPVEpmYVE3RmtDVHBaQjlGMzZmc0ZlckpnVUpBbXpEbG9BNDhWbGtyVzZmcVB2czg3bTZodWRyVmR4WXlLMDR3QVAzdnVkRnJseURaZkZwUmFLSFcxaFJBIiwib3JpZ2luIjoiaHR0cHM6Ly9tZy1kZXY0Lm1hcGxlLm1hY2Vyb2MuY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ",
    "signature": "mMEUCIQCZT/RZj/52SfBhSK9+FhjntXNCjtGLC50ez7psJg9kXQIgUEQo/sS5wyuV3uox3R/iHS2PbHJXMiPJr355ZYSJIkU",
    "userHandle": None
  },
  type: 'public-key'
}


# def register_begin():
#     registration_data, state = server.register_begin(
#         {
#             "id": b"user_id",
#             "name": "a_user",
#             "displayName": "A. User",
#             "icon": "https://example.com/image.png",
#         },
#         credentials,
#         user_verification="discouraged",
#         authenticator_attachment="cross-platform",
#     )
#
#     print("\n\n\n\n")
#     print(registration_data)
#     print("\n\n\n\n")
#     return cbor.encode(registration_data)


# def register_complete():
#     data = {'data': False}
#     client_data = ClientData(data["clientDataJSON"])
#     att_obj = AttestationObject(data["attestationObject"])
#     print("clientData", client_data)
#     print("AttestationObject:", att_obj)
#
#     auth_data = server.register_complete(session["state"], client_data, att_obj)
#
#     credentials.append(auth_data.credential_data)
#     print("REGISTERED CREDENTIAL:", auth_data.credential_data)
#     return cbor.encode({"status": "OK"})


def authenticate_begin(credentials: list):
    # if not credentials:
    #     abort(404)

    url_site = 'mg-dev4.maple.maceroc.com'

    webauthn = Webauthn()
    challenge = webauthn.generer_challenge_auth(url_site, credentials)

    print("Challenge webauthn: %s" % json.dumps(challenge, indent=2))

    return challenge


def authenticate_complete():
    url_site = 'mg-dev4.maple.maceroc.com'

    webauthn = Webauthn()
    webauthn.authenticate_complete(url_site, dummy_challenge, dummy_response, dummy_credentials)


def main():
    # data = register_begin()
    authenticate_begin(dummy_credentials)
    # authenticate_complete()


if __name__ == '__main__':
    main()

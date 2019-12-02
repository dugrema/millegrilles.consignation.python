from torf import Torrent
import datetime

t = Torrent()
t.created_by = "create-torrent/MilleGrilles 1.16"
t.creation_date = datetime.datetime.utcnow().timestamp()
t.trackers = [
    'https://mg-dev3.local:3004/announce'
]
t.comment = 'Archive 11 octobre 2019 UTC'
t.metainfo['millegrilles'] = {
    "en-tete": {
        'millegrille': "371dabe45115a8fe7e594945190ee6cd6f81f890",  # Fingerprint SSRoot
        "certificat": "8f3e528bb8c7d489b6b296b07b16db2bf76fa729",  # Certificat verifiable contre SSRoot (chaine)
        "domaine": "millegrilles.domaines.GrosFichiers.torrent",
        "estampille": 1575149613,
        "hachage-contenu": "A7Y96fpsP8YNLLCrXO31qHLihY3CFUBgcjqiv+JVWho=",
        "uuid-transaction": "0e6d9632-13b9-11ea-afcd-00155d011f09",  # UUID du torrent/collection figee
        "version": 6
    },
    "securite": '1.public',  # Niveau de securite global du torrent
    'catalogue': {
        '11656060-0ba4-11ea-8f37-0dcce7873a80.dat': {  # version / nom fichier dans archive
            # Contenu equivalent a une transaction millegrilles.domaines.GrosFichiers.nouvelleVersion.metadata
            # La millegrille qui recoit ce torrent va agir de la meme facon quelle le ferait avec une nouvelle
            # transaction (qui sera extraite et soumise sur reception du torrent).
            'uuid': '9e589c55-e2ce-4ef1-9770-b0a9b58cc8b8',  # uuid fichier
            'fuuid': '11656060-0ba4-11ea-8f37-0dcce7873a80',  # fuuid version
            'nom': 'AmazonFreeTierEC2.pdf',
            'mimetype': 'application/pdf',
            "taille": 5478,
            'sha256': '9cb0e10c033a0e1bab62596d5dc68a7d3df4b558aa103b74e5b1b409a377b695',
        }
    },
    'commentaires': "J'aime bian les torrents",
}

# Signature de sha256, par cert key_fingerprint
t.metainfo['_signature'] = 'U6OVWPkPk7ojx0Kz1xQCX02pR3w/EJuFMzvGTY42/kdpVyNjlJ7d+irh2u/fgMO3MOLZieyCWgamkHOauydIk3dtzorBtHvIemtBID482tSC815TTDTDpN3A7pzfyh/dnimR98izMROcsCdUnU0yupJOgDR/Qz+OjNb7HeowdW01EWrKOMzTcdDn2MvyK29K6nEDAAiAeUbpX7PXvxi2XkvBfwrnXeW66OGErtSg0FzxKFWp+r008G4S4Y8sk6w5LlKKh+qp92KvkY2y3VdTz6okf1PCfe4LrWsj4PKQ+YR5/6DEtS7Ff2JhnmT94wG9s7+omnu5b4GIiMA1yS2S8A=='

# t.private = True

t.generate()
t.write('/home/mathieu/tmp/dev3_archive_20191011UTC.torrent')

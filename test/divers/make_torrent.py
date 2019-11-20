from torf import Torrent
import datetime

t = Torrent()
t.created_by = "MilleGrille dev3"
t.creation_date = datetime.datetime.utcnow().timestamp()
t.trackers = [
    'https://mg-dev3.local:3004/announce'
]
t.comment = 'Archive 11 octobre 2019 UTC'
t.metainfo['millegrilles'] = {
    'uuid': '9e589c55-e2ce-4ef1-9770-b0a9b58cc8b8',  # UUID du torrent
    "key_fingerprint": "371dabe45115a8fe7e594945190ee6cd6f81f890",  # Fingerprint du certificat
    "version": 1,  # Version de ce catalogue torrent
}
t.metainfo['catalogue'] = {
    '11656060-0ba4-11ea-8f37-0dcce7873a80.dat': {  # version / nom fichier dans archive
        'uuid': '9e589c55-e2ce-4ef1-9770-b0a9b58cc8b8',  # fuuid fichier
        'nom': 'AmazonFreeTierEC2.pdf',
        'date_version': 1574261441,
        'mimetype': 'application/pdf',
        'securite': '2.prive',
        'sha256': '9cb0e10c033a0e1bab62596d5dc68a7d3df4b558aa103b74e5b1b409a377b695'
    }
}
t.metainfo['sha256'] = 'ab90e10c033a0e1bab62596d5dc68a7d3df4b558aa103b74e5b1b409a377720c'  # Hash de metainfo
t.metainfo['_signature'] = 'abcdefgh...asfdsfsf'  # Signature de sha256, par cert key_fingerprint

# t.private = True

t.generate()
t.write('/home/mathieu/tmp/dev3_archive_20191011UTC.torrent')

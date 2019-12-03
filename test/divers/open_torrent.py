from torf import Torrent

import json

nom_torrent = '561ff56f-f7ab-4637-a699-ec2719781b64'

t = Torrent.read('/opt/millegrilles/dev3/mounts/consignation/torrents/%s.torrent.added' % nom_torrent)

print('----------------------------------')

print("Nom collection: %s" % t.name)
print("Commentaires: %s" % t.comment)
transaction = t.metainfo['info']['millegrilles']
print('MilleGrilles:\n%s' % json.dumps(transaction, indent=4))

print('----------------------------------')

print("Trackers: %s" % str(t.trackers))
print("Creation date: %s" % t.creation_date)
print("Piece size: %s" % t.piece_size)
print("Created by: %s" % t.created_by)

print('----------------------------------')

print("Files: ")
for file in t.metainfo['info']['files']:
    print(str(file))


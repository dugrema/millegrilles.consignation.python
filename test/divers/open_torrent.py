from torf import Torrent

import json

t = Torrent.read('/opt/millegrilles/dev3/mounts/consignation/torrents/ma_collection_figee.7fd1c894-0f15-11ea-bb74-00155d011f09.torrent')

print("Torrent name: %s" % t.name)
print("Trackers: %s" % str(t.trackers))
print("Creation date: %s" % t.creation_date)
print("Piece size: %s" % t.piece_size)
print("Created by: %s" % t.created_by)
print("Comment: %s" % t.comment)

print("Metainfo: %s" % str(t.metainfo))

transaction = t.metainfo['info']['millegrilles']
print('MilleGrilles:\n%s' % json.dumps(transaction, indent=4))

print("Files: ")
for file in t.metainfo['info']['files']:
    print(str(file))


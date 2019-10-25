from torf import Torrent
t = Torrent(path='/opt/millegrilles/dev3/mounts/consignation/local/2019/10/11',
            trackers=['https://mg-dev3.local:3004/announce'],
            comment='Archive 11 octobre 2019 UTC')
t.private = True
t.generate()
t.write('/home/mathieu/tmp/dev3_archive_20191011UTC.torrent')


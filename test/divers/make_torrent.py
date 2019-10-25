from torf import Torrent
t = Torrent(path='/home/mathieu/tmp/torrent_Test1',
            trackers=['https://mg-dev3.local:3004/announce'],
            comment='This is a comment')
t.private = True
t.generate()
t.write('/home/mathieu/tmp/UnTestTorrent.torrent')


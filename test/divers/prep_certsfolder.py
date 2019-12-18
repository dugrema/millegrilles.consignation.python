import os

folder = '/home/mathieu/mgdev/certs'

for file in os.listdir(folder):
    name_split = file.split('.')
    name_short = '.'.join(name_split[1:-1])

    try:
        os.symlink('%s/%s' % (folder, file), '%s/%s' % (folder, name_short))
    except:
        pass

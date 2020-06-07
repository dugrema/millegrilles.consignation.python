import os

folder = '/home/mathieu/mgdev/certs'

print("Working directory : " + str(os.getcwd()))

for file in os.listdir(folder):
    name_split = file.split('.')
    name_short = '.'.join(name_split[1:-1])

    try:
        # os.symlink('%s/%s' % (folder, file), '%s/%s' % (folder, name_short))
        path_dest = os.fspath(name_short)
        print(str(path_dest))
        os.symlink(file, path_dest)
    except Exception as e:
        print("Exception " + str(e))

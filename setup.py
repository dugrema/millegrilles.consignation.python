from setuptools import setup
import subprocess


def get_version():
    with open('build.txt', "r") as buildno_file:
        build_no = buildno_file.read()

    commande_git_version = ['git', 'name-rev', '--name-only', 'HEAD']
    output_process = subprocess.run(commande_git_version, stdout=subprocess.PIPE)
    version = output_process.stdout.decode('utf8').strip()
    print("Version: %s.%s" % (version, build_no))
    return version


setup(
    name='MilleGrilles.consignation.python',
    version='%s' % get_version(),
    packages=[
        'millegrilles',
        'millegrilles.dao',
        'millegrilles.domaines',
        'millegrilles.transaction',
        'millegrilles.util',
        'millegrilles.noeuds',
        'mgdomaines',
        'mgdomaines.appareils'
    ],
    url='',
    license='',
    author='Mathieu Dugre',
    author_email='mathieu.dugre@mdugre.info',
    description='Scripts Python de consignation pour MilleGrilles'
)

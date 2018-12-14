from setuptools import setup

setup(
    name='MilleGrilles.consignation.python',
    version='0.9.7',
    packages=[
        'millegrilles',
        'millegrilles.dao',
        'millegrilles.domaines',
        'millegrilles.processus',
        'millegrilles.transaction',
        'millegrilles.util',
        'mgdomaines',
        'mgdomaines.appareils',
        'mgdomaines.web'
    ],
    url='',
    license='',
    author='Mathieu Dugre',
    author_email='mathieu.dugre@mdugre.info',
    description='Scripts Python de consignation pour MilleGrilles'
)

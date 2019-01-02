from setuptools import setup

setup(
    name='MilleGrilles.consignation.python',
    version='1.2.2',
    packages=[
        'millegrilles',
        'millegrilles.dao',
        'millegrilles.domaines',
        'millegrilles.transaction',
        'millegrilles.util',
        'mgdomaines',
        'mgdomaines.appareils'
    ],
    url='',
    license='',
    author='Mathieu Dugre',
    author_email='mathieu.dugre@mdugre.info',
    description='Scripts Python de consignation pour MilleGrilles'
)

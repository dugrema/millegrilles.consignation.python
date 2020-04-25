#!/usr/bin/python3
# Executer ce script pour demarrer le consignateur de transaction
import os

from millegrilles.Hebergement import HebergementDomaines


if __name__ == '__main__':
    consignateur = HebergementDomaines()
    consignateur.main()

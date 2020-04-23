#!/usr/bin/python3
# Executer ce script pour demarrer le consignateur de transaction
import os

from millegrilles.Hebergement import HebergementTransactions


if __name__ == '__main__':
    consignateur = HebergementTransactions()
    consignateur.main()

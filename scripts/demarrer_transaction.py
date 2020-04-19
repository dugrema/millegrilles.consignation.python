#!/usr/bin/python3
# Executer ce script pour demarrer le consignateur de transaction
from millegrilles.transaction.ConsignateurTransaction import ConsignateurTransaction


if __name__ == '__main__':
    ConsignateurTransaction.preparer_mongo_keycert()
    consignateur = ConsignateurTransaction()
    consignateur.main()

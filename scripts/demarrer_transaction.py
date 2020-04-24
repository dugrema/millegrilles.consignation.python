#!/usr/bin/python3
# Executer ce script pour demarrer le consignateur de transaction
import os

from millegrilles.transaction.ConsignateurTransaction import ConsignateurTransaction


if __name__ == '__main__':
    # keycert_file = ConsignateurTransaction.preparer_mongo_keycert()
    # try:
    #     consignateur = ConsignateurTransaction()
    #     consignateur.main()
    # finally:
    #     os.remove(keycert_file)

    consignateur = ConsignateurTransaction()
    consignateur.main()

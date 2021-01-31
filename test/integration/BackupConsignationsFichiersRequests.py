import requests
import logging
import json
import os
import lzma
import datetime
import pytz

from millegrilles.util.BaseTestMessages import DomaineTest


class PutCommands(DomaineTest):

    def __init__(self):
        super().__init__()
        self.__logger = logging.getLogger(self.__class__.__name__)

        self.url_consignationfichiers = 'https://fichiers:3021'
        self.certfile = self.configuration.pki_certfile
        self.keyfile = self.configuration.pki_keyfile

    def put_backup(self, nom_fichier_backup: str, catalogue: dict, transactions: bytes):
        with lzma.open('/tmp/fichier_catalogue.json.xz', 'wt') as fichier:
            json.dump(catalogue, fichier)
        with open('/tmp/fichier_transactions.txt', 'wb') as fichier:
            fichier.write(transactions)

        data = {'valeur': 1}

        with open('/tmp/fichier_catalogue.json.xz', 'rb') as fp_catalogue:
            with open('/tmp/fichier_transactions.txt', 'rb') as fp_transactions:
                files = {
                    'transactions': (nom_fichier_backup + '.jsonl.xz.mgs1', fp_transactions, 'application/x-xz'),
                    'catalogue': (nom_fichier_backup + '.json.xz', fp_catalogue, 'application/x-xz'),
                }

                r = requests.put(
                    '%s/backup/domaine/%s' % (self.url_consignationfichiers, nom_fichier_backup),
                    data=data,
                    files=files,
                    verify=self._contexte.configuration.mq_cafile,
                    cert=(self.certfile, self.keyfile)
                )

        os.unlink('/tmp/fichier_catalogue.json.xz')
        os.unlink('/tmp/fichier_transactions.txt')

        return r

    def put_test1(self):
        catalogue = {
            'domaine': 'domaine.test',
            'heure': int(datetime.datetime(year=2020, month=1, day=1, hour=0, tzinfo=pytz.UTC).timestamp()),
        }
        transactions = b'donnees pas rapport'
        r = self.put_backup('domaine.sousdomaine.202001010000', catalogue, transactions)
        self.__logger.debug("Resultat put : %d\n%s" % (r.status_code, r.json()))

    def executer(self):
        self.__logger.debug("Executer")
        self.put_test1()


class GetCommands(DomaineTest):

    def __init__(self):
        super().__init__()
        self.__logger = logging.getLogger(self.__class__.__name__)

        self.url_consignationfichiers = 'https://fichiers:3021'
        self.certfile = self.configuration.pki_certfile
        self.keyfile = self.configuration.pki_keyfile

    def get(self, requete, data: dict = None):
        r = requests.get(
            '%s/backup/%s' % (self.url_consignationfichiers, requete),
            data=data,
            verify=self._contexte.configuration.mq_cafile,
            cert=(self.certfile, self.keyfile)
        )

        return r

    def get_listedomaines(self):
        r = self.get('listedomaines')
        self.__logger.debug("Resultat get_listedomaines : %d\n%s" % (r.status_code, r.json()))

    def executer(self):
        self.__logger.debug("Executer")
        self.get_listedomaines()


# --- MAIN ---
if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger('millegrilles').setLevel(logging.DEBUG)
    logging.getLogger('PutCommands').setLevel(logging.DEBUG)
    logging.getLogger('GetCommands').setLevel(logging.DEBUG)
    # test = PutCommands()
    test = GetCommands()
    # TEST

    # FIN TEST
    test.event_recu.wait(10)
    test.deconnecter()

import requests
import logging
import json
import os
import lzma
import datetime
import pytz
import hashlib

from base64 import b64encode

from millegrilles.util.BaseTestMessages import DomaineTest


def calculer_fichier_SHA512(path_fichier):
    BUFFER_SIZE = 64*1024
    sha512 = hashlib.sha512()
    with open(path_fichier, 'rb') as fichier:
        buffer = fichier.read(BUFFER_SIZE)
        while buffer:
            sha512.update(buffer)
            buffer = fichier.read(BUFFER_SIZE)
    sha512_digest = 'sha512_b64:' + b64encode(sha512.digest()).decode('utf-8')
    return sha512_digest


class PutCommands(DomaineTest):

    def __init__(self):
        super().__init__()
        self.__logger = logging.getLogger(self.__class__.__name__)

        self.url_consignationfichiers = 'https://fichiers:3021'
        self.certfile = self.configuration.pki_certfile
        self.keyfile = self.configuration.pki_keyfile

    def put_backup(self, nom_fichier_backup: str, catalogue: dict, transactions: bytes, maitrecles: dict = None):

        path_transactions = '/tmp/fichier_transactions.txt'
        with open(path_transactions, 'wb') as fichier:
            fichier.write(transactions)
        hachage_transactions = calculer_fichier_SHA512(path_transactions)

        catalogue['hachage_transactions'] = hachage_transactions
        catalogue = self.contexte.generateur_transactions.preparer_enveloppe(catalogue, ajouter_certificats=True)
        path_catalogue = '/tmp/fichier_catalogue.json.xz'
        # catalogue['corrupu'] = True
        with lzma.open(path_catalogue, 'wt') as fichier:
            json.dump(catalogue, fichier)

        path_maitrecles = None
        if maitrecles is not None:
            maitrecles = self.contexte.generateur_transactions.preparer_enveloppe(
                maitrecles, 'MaitreDesCles.dadada', ajouter_certificats=True)
            # maitrecles['corrupu'] = True

            path_maitrecles = '/tmp/fichier_maitrecles.json.xz'
            with lzma.open(path_maitrecles, 'wt') as fichier:
                json.dump(maitrecles, fichier)

        with open(path_catalogue, 'rb') as fp_catalogue:
            with open(path_transactions, 'rb') as fp_transactions:
                files = {
                    'transactions': (nom_fichier_backup + '.jsonl.xz.mgs1', fp_transactions, 'application/x-xz'),
                    'catalogue': (nom_fichier_backup + '.json.xz', fp_catalogue, 'application/x-xz'),
                }
                if maitrecles is not None:
                    fp_cles = open(path_maitrecles, 'rb')
                    files['cles'] = ('maitrecles.json.xz', fp_cles, 'application/x-xz')

                r = requests.put(
                    '%s/backup/domaine/%s' % (self.url_consignationfichiers, nom_fichier_backup),
                    files=files,
                    verify=self._contexte.configuration.mq_cafile,
                    cert=(self.certfile, self.keyfile)
                )

                if maitrecles is not None:
                    fp_cles.close()

        resultat = r.json()
        if r.status_code != 200:
            self.__logger.error("Erreur processing backup (%d): %s" % (r.status_code, resultat['err']))
        else:
            hachage_transactions_recu = r.json()[nom_fichier_backup + '.jsonl.xz.mgs1']
            if hachage_transactions_recu != hachage_transactions:
                raise ValueError("Hachage transactions incorrect")
            else:
                self.__logger.info("Hachage transaction OK")

        os.unlink(path_catalogue)
        os.unlink(path_transactions)
        if maitrecles is not None:
            os.unlink(path_maitrecles)

        return r

    def put_test1(self):
        catalogue = {
            'domaine': 'domaine.test',
            'heure': int(datetime.datetime(year=2020, month=1, day=1, hour=0, tzinfo=pytz.UTC).timestamp()),
        }
        transactions = b'donnees pas rapport'
        r = self.put_backup('domaine.sousdomaine.202001010000', catalogue, transactions)
        self.__logger.debug("Resultat put : %d\n%s" % (r.status_code, r.json()))

    def put_test_protege(self):
        catalogue = {
            'domaine': 'domaine.test',
            'heure': int(datetime.datetime(year=2020, month=1, day=1, hour=1, tzinfo=pytz.UTC).timestamp()),
        }
        maitrecles = {
            'iv': 'Mon IV',
            'cles': {
                'hachage-1': 'cle-1'
            }
        }
        transactions = b'donnees pas rapport'
        r = self.put_backup('domaine.sousdomaine.202001010000', catalogue, transactions, maitrecles)
        self.__logger.debug("Resultat put_test_protege : %d\n%s" % (r.status_code, r.json()))

    def executer(self):
        self.__logger.debug("Executer")
        try:
            self.put_test1()
            # self.put_test_protege()
        finally:
            self.event_recu.set()


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
            cert=(self.certfile, self.keyfile),
            timeout=1,
            stream=True,
        )

        return r

    def get_listedomaines(self):
        try:
            r = self.get('listedomaines')
            self.__logger.debug("Resultat get_listedomaines : %d\n%s" % (r.status_code, r.json()))
        except requests.exceptions.RequestException:
            self.__logger.exception("Timeout")

    def get_catalogues(self, domaine='domaine.test'):
        r = self.get('catalogues/' + domaine)
        self.__logger.debug("Resultat get_catalogues : %d\nHeaders: %s" % (r.status_code, r.headers))
        # self.__logger.debug("Response\n%s" % r.text)

        compteur = 0
        for line in r.iter_lines(chunk_size=5*1024*1024):
            # self.__logger.info("Catalogue : %s" % line)
            try:
                self.__logger.info("Catalogue %d\n%s" % (compteur, json.dumps(json.loads(line), indent=2)))
                compteur = compteur + 1
            except json.decoder.JSONDecodeError:
                pass

    def get_liste_fichiers(self, domaine='domaine.test'):
        r = self.get('listeFichiers/' + domaine)
        self.__logger.debug("Resultat get_liste_fichiers : %d\nHeaders: %s" % (r.status_code, r.headers))
        self.__logger.debug(r.text)

    def get_fichier(self, domaine='domaine.test', fichier='horaire/domaine.sousdomaine.202001010000.json.xz'):
        r = self.get('fichier/' + domaine + '/' + fichier)
        self.__logger.debug("Resultat get_fichier : %d\nHeaders: %s" % (r.status_code, r.headers))
        content = r.content
        self.__logger.debug("Taille contenu fichier : %d" % len(content))

    def executer(self):
        self.__logger.debug("Executer")
        try:
            # self.get_listedomaines()
            # self.get_catalogues()
            self.get_catalogues("MaitreDesComptes")
            # self.get_liste_fichiers("sample5")
            # self.get_liste_fichiers("MaitreDesComptes")
            # self.get_fichier()
            # self.get_fichier('sample4', 'domaine.test_2020.tar')
            # self.get_fichier('mathieu.main', 'snapshot/test.txt')
        except:
            self.__logger.exception("Erreur")
        finally:
            self.event_recu.set()


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
    test.event_recu.wait(120)
    test.deconnecter()

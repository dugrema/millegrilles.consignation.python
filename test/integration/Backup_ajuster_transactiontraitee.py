# Script de test pour transmettre une requete MongoDB

from millegrilles import Constantes
from millegrilles.dao.ConfigurationDocument import ContexteRessourcesDocumentsMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction

import datetime
from threading import Thread


# class TestCallback(BaseCallback):
#
#     def __init__(self, contexte, classe_requete):
#         super().__init__(contexte)
#         self.classe_requete = classe_requete
#
#     def traiter_message(self, ch, method, properties, body):
#         print("Reponse recue: %s" % body)
#         self.reponse = body


class ModifierDateTransaction:

    def __init__(self, contexte, offset: datetime.timedelta, domaines: list = None):
        # self.callback = TestCallback(contexte, self)
        self.__contexte = contexte
        self.__domaines = domaines or ['GrosFichiers']
        self.__offset = offset

    def appliquer(self):
        for domaine in self.__domaines:
            self.traiter_transaction(domaine)

    def traiter_transaction(self, domaine):
        collection = self.__contexte.document_dao.get_collection(domaine)
        print("Collection chargee")

        filtre = {
            '_evenements.transaction_complete': True
        }
        curseur = collection.find(filtre)

        for doc in curseur:
            filtre = {'_id': doc['_id']}
            date_transaction = doc['_evenements']['signature_verifiee']
            nouvelle_date = date_transaction + self.__offset
            set_ops = {
                '_evenements.backup_flag': False,
                '_evenements.transaction_traitee': nouvelle_date,
            }
            ops = {
                '$set': set_ops,
                '$unset': {'_evenements.backup_horaire': True}
            }
            collection.update_one(filtre, ops)


class TestRequetesMatchBackup:

    def __init__(self, contexte, nom_collection: str, domaine: str):
        self.__contexte = contexte
        self.__nom_collection = nom_collection
        self.__domaine = domaine

    def requete_horaire(self, heure_max: datetime.datetime):
        sous_domaine_regex = '^' + self.__domaine.replace('.', '\\.') + '\\.'
        coltrans = self.__contexte.document_dao.get_collection(self.__nom_collection)
        label_tran = '%s.%s' % (
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_TRANSACTION_COMPLETE)
        label_backup = '%s.%s' % (
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_TRANSACTION_BACKUP_FLAG)
        filtre = {
            label_tran: True,
            label_backup: False,
            'en-tete.domaine': {'$regex': sous_domaine_regex},
        }

        if heure_max:
            filtre['_evenements.transaction_traitee'] = {'$lt': heure_max}
            # heure_max_ts = int(heure_max.timestamp())
            # filtre['en-tete.estampille'] = {'$lt': heure_max_ts}

        sort = [
            ('_evenements.transaction_traitee', 1)
        ]
        hint = [
            (label_tran, 1),
            (label_backup, 1),
        ]
        curseur = coltrans.find(filtre, sort=sort, hint=hint)

        for doc in curseur:
            print(doc)


def reset_dates_moins2heures(contexte, domaines):
    offset = datetime.timedelta(hours=-2)
    modificateur = ModifierDateTransaction(contexte, offset, domaines)
    modificateur.appliquer()


def reset_dates_moins1semaine(contexte):
    offset = datetime.timedelta(days=-7)
    modificateur = ModifierDateTransaction(contexte, offset)
    modificateur.appliquer()


def reset_dates_moins2ans(contexte):
    offset = datetime.timedelta(days=-720)
    modificateur = ModifierDateTransaction(contexte, offset)
    modificateur.appliquer()


def requete_transactions_moinsuneheure(contexte, nom_collection, domaine):
    test = TestRequetesMatchBackup(contexte, nom_collection, domaine)
    heure_max = datetime.datetime.utcnow() + datetime.timedelta(hours=-31)
    test.requete_horaire(heure_max)


# --- MAIN ---

def main():
    contexte = ContexteRessourcesDocumentsMilleGrilles()
    contexte.initialiser(init_document=True)

    reset_dates_moins2heures(contexte, ['MaitreDesCles'])
    # reset_dates_moins1semaine(contexte)
    # reset_dates_moins2ans(contexte)

    # requete_transactions_moinsuneheure(contexte, 'MaitreDesCles', 'MaitreDesCles')


# TEST
if __name__ == '__main__':
    main()

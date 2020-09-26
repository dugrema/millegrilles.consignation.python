# Script de test pour transmettre une requete MongoDB

from millegrilles import Constantes
from millegrilles.dao.ConfigurationDocument import ContexteRessourcesDocumentsMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles.Constantes import ConstantesBackup

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

    def __init__(self, contexte, nom_collection: str):
        # self.callback = TestCallback(contexte, self)
        self.__contexte = contexte
        self.__nom_collection = nom_collection

    def requete(self):
        curseur = self._effectuer_requete_domaine(datetime.datetime.utcnow())

        for res in curseur:
            print(res)

    def _effectuer_requete_domaine(self, heure: datetime.datetime):
        # Verifier s'il y a des transactions qui n'ont pas ete traitees avant la periode actuelle

        filtre_verif_transactions_anterieures = {
            '_evenements.transaction_complete': True,
            '_evenements.%s' % Constantes.EVENEMENT_TRANSACTION_BACKUP_FLAG: False,
            '_evenements.transaction_traitee': {'$lt': heure},
        }
        regroupement_periode = {
            'year': {'$year': '$_evenements.transaction_traitee'},
            'month': {'$month': '$_evenements.transaction_traitee'},
            'day': {'$dayOfMonth': '$_evenements.transaction_traitee'},
            'hour': {'$hour': '$_evenements.transaction_traitee'},
        }

        # Regroupeemnt par date et par domaine/sous-domaine (l'action est retiree du domaine pour grouper)
        regroupement = {
            '_id': {
                'timestamp': {
                    '$dateFromParts': regroupement_periode
                },
            },
            'sousdomaine': {
                '$addToSet': {
                    '$slice': [
                        {'$split': ['$en-tete.domaine', '.']},
                        {'$add': [{'$size': {'$split': ['$en-tete.domaine', '.']}}, -1]}
                    ]
                }
            }
        }
        sort = {
            '_id.timestamp': 1,
            # 'sousdomaine': 1
        }
        operation = [
            {'$match': filtre_verif_transactions_anterieures},
            {'$group': regroupement},
            {'$sort': sort},
        ]
        hint = {
            '_evenements.transaction_complete': 1,
            '_evenements.%s' % Constantes.EVENEMENT_TRANSACTION_BACKUP_FLAG: 1,
        }
        collection_transactions = self.__contexte.document_dao.get_collection(self.__nom_collection)

        return collection_transactions.aggregate(operation, hint=hint)


class RequeteBackupQuotidiens:

    def __init__(self, contexte, domaine: str):
        # self.callback = TestCallback(contexte, self)
        self.__contexte = contexte
        self.__domaine = domaine

    def requete_backup_quotidien(self):
        collection_transactions = self.__contexte.document_dao.get_collection('Backup/documents')

        filtre_backups_quotidiens_dirty = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesBackup.LIBVAL_CATALOGUE_QUOTIDIEN,
            ConstantesBackup.LIBELLE_DOMAINE: {'$regex': '^' + self.__domaine},
            ConstantesBackup.LIBELLE_DIRTY_FLAG: True,
            ConstantesBackup.LIBELLE_JOUR: {'$lt': datetime.datetime.utcnow()}
        }

        curseur = collection_transactions.find(filtre_backups_quotidiens_dirty)

        for doc in curseur:
            print(doc)


def requete_agg_backup(contexte):
    modificateur = ModifierDateTransaction(contexte, 'MaitreDesCles')
    modificateur.requete()


def requete_quotidien(contexte):
    modificateur = RequeteBackupQuotidiens(contexte, 'MaitreDesCles')
    modificateur.requete_backup_quotidien()


# --- MAIN ---

def main():
    contexte = ContexteRessourcesDocumentsMilleGrilles()
    contexte.initialiser(init_document=True)

    # requete_agg_backup(contexte)
    requete_quotidien(contexte)

# TEST
if __name__ == '__main__':
    main()

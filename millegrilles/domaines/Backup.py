import logging
import datetime
import json

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesBackup
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementMessageDomaineRequete
from millegrilles.MGProcessus import MGProcessusTransaction


class TraitementRequetesProtegees(TraitementMessageDomaineRequete):

    def traiter_requete(self, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        domaine_routing_key = method.routing_key.replace('requete.', '')


class TraitementRequetesPubliques(TraitementMessageDomaineRequete):

    def traiter_requete(self, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        domaine_routing_key = method.routing_key.replace('requete.', '')


class GestionnaireBackup(GestionnaireDomaineStandard):
    """
    Gestionnaire du domaine de backup
    """

    def __init__(self, contexte):
        super().__init__(contexte)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.__handler_requetes_noeuds = {
            Constantes.SECURITE_PUBLIC: TraitementRequetesPubliques(self),
            Constantes.SECURITE_PROTEGE: TraitementRequetesProtegees(self),
        }

    def configurer(self):
        super().configurer()

        collection_documents = self.document_dao.get_collection(ConstantesBackup.COLLECTION_DOCUMENTS_NOM)
        # Index noeud, _mg-libelle
        collection_documents.create_index(
            [
                (ConstantesBackup.LIBELLE_DIRTY_FLAG, 1),
                (Constantes.DOCUMENT_INFODOC_LIBELLE, 1),
                (Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION, 1),
            ],
            name='dirty-backups'
        )


    def demarrer(self):
        super().demarrer()
        # self.initialiser_document(ConstantesPki.LIBVAL_CONFIGURATION, ConstantesPki.DOCUMENT_DEFAUT)

    def get_queue_configuration(self):
        configuration = super().get_queue_configuration()

        return configuration

    def traiter_cedule(self, evenement):
        super().traiter_cedule(evenement)

    def get_nom_queue(self):
        return ConstantesBackup.QUEUE_NOM

    def get_nom_queue_certificats(self):
        return ConstantesBackup.QUEUE_NOM

    def get_nom_collection(self):
        return ConstantesBackup.COLLECTION_DOCUMENTS_NOM

    def get_collection_transaction_nom(self):
        return ConstantesBackup.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesBackup.COLLECTION_PROCESSUS_NOM

    def get_nom_domaine(self):
        return ConstantesBackup.DOMAINE_NOM

    def identifier_processus(self, domaine_transaction):
        if domaine_transaction == ConstantesBackup.TRANSACTION_CATALOGUE_HORAIRE:
            processus = "millegrilles_domaines_Backup:ProcessusAjouterCatalogueHoraire"
        else:
            processus = super().identifier_processus(domaine_transaction)

        return processus


class ProcessusAjouterCatalogueHoraire(MGProcessusTransaction):

    def __init__(self, controleur, evenement, transaction_mapper=None):
        super().__init__(controleur, evenement, transaction_mapper)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        transaction = self.charger_transaction()
        self.__logger.info("Transaction recue: %s" % str(transaction))
        heure_backup = datetime.datetime.fromtimestamp(
            transaction[ConstantesBackup.LIBELLE_HEURE],
            tz=datetime.timezone.utc
        )

        jour_backup = datetime.datetime(year=heure_backup.year, month=heure_backup.month, day=heure_backup.day)

        champs_fichier = [
            ConstantesBackup.LIBELLE_TRANSACTIONS_NOMFICHIER,
            ConstantesBackup.LIBELLE_TRANSACTIONS_SHA512,
            ConstantesBackup.LIBELLE_CATALOGUE_NOMFICHIER
        ]

        set_ops = {
            ConstantesBackup.LIBELLE_DIRTY_FLAG: True,
        }

        for champ in champs_fichier:
            set_ops['%s.%s.%s' % (ConstantesBackup.LIBELLE_FICHIERS_HORAIRE, str(heure_backup.hour), champ)] = \
                transaction[champ]

        # Placer les fuuid de chaque fichier pour faire un update individuel
        for fuuid, info_fichier in transaction[ConstantesBackup.LIBELLE_FUUID_GROSFICHIERS].items():
            set_ops['%s.%s' % (ConstantesBackup.LIBELLE_FUUID_GROSFICHIERS, fuuid)] = info_fichier

        # Ces valeurs doivent etre agregees commes si elles etaient des sets()
        sets_a_copier = [
            ConstantesBackup.LIBELLE_CERTS_RACINE,
            ConstantesBackup.LIBELLE_CERTS_INTERMEDIAIRES,
            ConstantesBackup.LIBELLE_CERTS,
        ]
        add_to_sets = dict()
        for champ in sets_a_copier:
            add_to_sets[champ] = {'$each': transaction[champ]}

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesBackup.LIBVAL_CATALOGUE_QUOTIDIEN,
            ConstantesBackup.LIBELLE_SECURITE: transaction[ConstantesBackup.LIBELLE_SECURITE],
            ConstantesBackup.LIBELLE_DOMAINE: transaction[ConstantesBackup.LIBELLE_DOMAINE],
            ConstantesBackup.LIBELLE_JOUR: jour_backup,
        }
        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
        }
        set_on_insert.update(filtre)  # On utilise les memes valeurs que le filtre lors de l'insertion

        ops = {
            '$setOnInsert': set_on_insert,
            '$set': set_ops,
            '$addToSet': add_to_sets,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }

        collection_backup = self.document_dao.get_collection(ConstantesBackup.COLLECTION_DOCUMENTS_NOM)
        collection_backup.update_one(filtre, ops, upsert=True)

        self.set_etape_suivante()  # Termine

import logging
import datetime

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesBackup
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementRequetesProtegees, TraitementMessageDomaineRequete
from millegrilles.MGProcessus import MGProcessusTransaction


class TraitementRequetesBackupProtegees(TraitementRequetesProtegees):

    def traiter_requete(self, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        domaine_routing_key = method.routing_key.replace('requete.', '')

        if domaine_routing_key == ConstantesBackup.REQUETE_BACKUP_DERNIERHORAIRE:
            reponse = self.gestionnaire.requete_backup_dernier_horaire(message_dict)
        else:
            return super().traiter_requete(ch, method, properties, body, message_dict)

        if reponse is not None:
            self.gestionnaire.generateur_transactions.transmettre_reponse(
                reponse, replying_to=properties.reply_to, correlation_id=properties.correlation_id)


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
            Constantes.SECURITE_PROTEGE: TraitementRequetesBackupProtegees(self),
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

    def get_handler_requetes(self) -> dict:
        return self.__handler_requetes_noeuds

    def identifier_processus(self, domaine_transaction):
        if domaine_transaction == ConstantesBackup.TRANSACTION_CATALOGUE_HORAIRE:
            processus = "millegrilles_domaines_Backup:ProcessusAjouterCatalogueHoraire"
        elif domaine_transaction == ConstantesBackup.TRANSACTION_CATALOGUE_HORAIRE_HACHAGE:
            processus = "millegrilles_domaines_Backup:ProcessusAjouterCatalogueHoraireSHA512"
        elif domaine_transaction == ConstantesBackup.TRANSACTION_CATALOGUE_HORAIRE_HACHAGE_ENTETE:
            processus = "millegrilles_domaines_Backup:ProcessusAjouterCatalogueHoraireSHAEntete"
        elif domaine_transaction == ConstantesBackup.TRANSACTION_CATALOGUE_QUOTIDIEN:
            processus = "millegrilles_domaines_Backup:ProcessusFinaliserCatalogueQuotidien"
        elif domaine_transaction == ConstantesBackup.TRANSACTION_ARCHIVE_QUOTIDIENNE_INFO:
            processus = "millegrilles_domaines_Backup:ProcessusInformationArchiveQuotidienne"
        elif domaine_transaction == ConstantesBackup.TRANSACTION_CATALOGUE_ANNUEL:
            processus = "millegrilles_domaines_Backup:ProcessusFinaliserCatalogueAnnuel"
        elif domaine_transaction == ConstantesBackup.TRANSACTION_ARCHIVE_ANNUELLE_INFO:
            processus = "millegrilles_domaines_Backup:ProcessusInformationArchiveAnnuelle"
        elif domaine_transaction == ConstantesBackup.TRANSACTION_RAPPORT_RESTAURATION:
            processus = "millegrilles_domaines_Backup:ProcessusRapportRestauration"
        elif domaine_transaction == ConstantesBackup.TRANSACTION_CATALOGUE_APPLICATION:
            processus = "millegrilles_domaines_Backup:ProcessusAjouterCatalogueApplication"

        else:
            processus = super().identifier_processus(domaine_transaction)

        return processus

    def requete_backup_dernier_horaire(self, requete):
        """
        Identifie le plus recent backup horaire pour domaine/securite
        :param requete:
        :return:
        """

        securite = requete.get(ConstantesBackup.LIBELLE_SECURITE)
        domaine = requete[ConstantesBackup.LIBELLE_DOMAINE]

        filtre = {
            ConstantesBackup.LIBELLE_DOMAINE: domaine,
        }
        if securite:
            filtre[ConstantesBackup.LIBELLE_SECURITE] = securite
        sort = [
            (ConstantesBackup.LIBELLE_HEURE, -1),
        ]

        collection_backup = self.document_dao.get_collection(ConstantesBackup.COLLECTION_TRANSACTIONS_NOM)
        dernier_backup = collection_backup.find_one(filtre, sort=sort)

        info_dernier_backup = None
        if dernier_backup:
            info_dernier_backup = dernier_backup[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]

        return {'dernier_backup': info_dernier_backup}

    def reset_backup(self, message_dict):
        super().reset_backup(message_dict)

        # Suppression des documents et transactions de backup
        backup_domaines = [
            ConstantesBackup.TRANSACTION_CATALOGUE_HORAIRE,
            ConstantesBackup.TRANSACTION_CATALOGUE_QUOTIDIEN,
            ConstantesBackup.TRANSACTION_CATALOGUE_ANNUEL,
            ConstantesBackup.TRANSACTION_CATALOGUE_HORAIRE_HACHAGE,
            ConstantesBackup.TRANSACTION_CATALOGUE_HORAIRE_HACHAGE_ENTETE,
            ConstantesBackup.TRANSACTION_ARCHIVE_QUOTIDIENNE_INFO,
            ConstantesBackup.TRANSACTION_ARCHIVE_QUOTIDIENNE_INFO,
            ConstantesBackup.TRANSACTION_ARCHIVE_MENSUELLE_INFO,
        ]
        filtre_transactions = {
            '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE, Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE): {'$in': backup_domaines}
        }
        collection_transactions = self.document_dao.get_collection(ConstantesBackup.COLLECTION_TRANSACTIONS_NOM)
        collection_transactions.delete_many(filtre_transactions)

        backup_libval = [
            ConstantesBackup.LIBVAL_CATALOGUE_HORAIRE,
            ConstantesBackup.LIBVAL_CATALOGUE_QUOTIDIEN,
            ConstantesBackup.LIBVAL_CATALOGUE_ANNUEL,
        ]
        filtre_documents = {
           Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': backup_libval}
        }
        collection_documents = self.document_dao.get_collection(ConstantesBackup.COLLECTION_DOCUMENTS_NOM)
        collection_documents.delete_many(filtre_documents)

    def maj_rapport_restauration(self, rapport):
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesBackup.LIBVAL_RAPPORT_RESTAURATION,
        }
        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
        }
        set_on_insert.update(filtre)

        date_rapport = rapport[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_ESTAMPILLE]
        date_rapport = datetime.datetime.utcfromtimestamp(date_rapport)

        set_ops = dict()
        comptes = rapport['comptes']
        for info_domaine in comptes:
            info_domaine['date'] = date_rapport
            domaine = info_domaine['domaine']
            domaine = domaine.replace('.', '/')  # Pour supporter sous-domaines
            del info_domaine['domaine']
            set_ops[domaine] = info_domaine

        ops = {
            '$set': set_ops,
            '$setOnInsert': set_on_insert,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }

        collection = self.document_dao.get_collection(ConstantesBackup.COLLECTION_DOCUMENTS_NOM)
        resultat = collection.update_one(filtre, ops, upsert=True)

        if resultat.upserted_id is None and resultat.matched_count != 1:
            raise Exception("Erreur maj rapport restauration")


class ProcessusAjouterCatalogueHoraire(MGProcessusTransaction):

    def __init__(self, controleur, evenement, transaction_mapper=None):
        super().__init__(controleur, evenement, transaction_mapper)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        transaction = self.charger_transaction()
        self.__logger.debug("Transaction recue: %s" % str(transaction))
        heure_backup = datetime.datetime.fromtimestamp(
            transaction[ConstantesBackup.LIBELLE_HEURE],
            tz=datetime.timezone.utc
        )

        jour_backup = datetime.datetime(year=heure_backup.year, month=heure_backup.month, day=heure_backup.day)

        champs_fichier = [
            ConstantesBackup.LIBELLE_TRANSACTIONS_NOMFICHIER,
            ConstantesBackup.LIBELLE_TRANSACTIONS_HACHAGE,
            ConstantesBackup.LIBELLE_CATALOGUE_NOMFICHIER,
            ConstantesBackup.LIBELLE_CATALOGUE_HACHAGE,
        ]

        set_ops = {
            ConstantesBackup.LIBELLE_DIRTY_FLAG: True,
            Constantes.DOCUMENT_INFODOC_SECURITE: transaction[Constantes.DOCUMENT_INFODOC_SECURITE],
        }

        for champ in champs_fichier:
            set_ops['%s.%s.%s' % (ConstantesBackup.LIBELLE_FICHIERS_HORAIRE, str(heure_backup.hour), champ)] = \
                transaction[champ]

        # Placer les fuuid de chaque fichier pour faire un update individuel
        for fuuid, info_fichier in transaction[ConstantesBackup.LIBELLE_FUUID_GROSFICHIERS].items():
            set_ops['%s.%s' % (ConstantesBackup.LIBELLE_FUUID_GROSFICHIERS, fuuid)] = info_fichier

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesBackup.LIBVAL_CATALOGUE_QUOTIDIEN,
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
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }

        collection_backup = self.document_dao.get_collection(ConstantesBackup.COLLECTION_DOCUMENTS_NOM)
        collection_backup.update_one(filtre, ops, upsert=True)

        self.verifier_presence_cle()

        self.set_etape_suivante()  # Termine

    def verifier_presence_cle(self):
        transaction = self.charger_transaction()
        if transaction.get('iv'):
            iv = transaction['iv']
            cles = transaction.get('cles')
            if cles is None and transaction.get('cle'):
                # On a seulement la cle de millegrille
                enveloppe_millegrille = self._controleur._contexte.signateur_transactions.get_enveloppe_millegrille()
                fingerprint_b64 = enveloppe_millegrille.fingerprint_b64
                cles = {fingerprint_b64: transaction['cle']}

            transactions_nomfichier = transaction[ConstantesBackup.LIBELLE_TRANSACTIONS_NOMFICHIER]

            commande_sauvegarder_cle = {
                'domaine': transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE],
                Constantes.ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS: {
                    ConstantesBackup.LIBELLE_TRANSACTIONS_NOMFICHIER: transactions_nomfichier,
                },
                "cles": cles,
                "iv": iv,
                'domaine_action_transaction': Constantes.ConstantesMaitreDesCles.TRANSACTION_NOUVELLE_CLE_BACKUPTRANSACTIONS,
                'securite': transaction[Constantes.DOCUMENT_INFODOC_SECURITE],
            }

            self.controleur.generateur_transactions.transmettre_commande(
                commande_sauvegarder_cle,
                'commande.MaitreDesCles.%s' % Constantes.ConstantesMaitreDesCles.COMMANDE_SAUVEGARDER_CLE,
                exchange=Constantes.SECURITE_SECURE,
            )


class ProcessusAjouterCatalogueHoraireSHA512(MGProcessusTransaction):

    def __init__(self, controleur, evenement, transaction_mapper=None):
        super().__init__(controleur, evenement, transaction_mapper)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        transaction = self.charger_transaction()

        self.__logger.debug("Transaction catalogue SHA512 : %s" % str(transaction))
        heure_backup = datetime.datetime.fromtimestamp(
            transaction[ConstantesBackup.LIBELLE_HEURE],
            tz=datetime.timezone.utc
        )

        jour_backup = datetime.datetime(year=heure_backup.year, month=heure_backup.month, day=heure_backup.day)

        champs_fichier = [
            ConstantesBackup.LIBELLE_CATALOGUE_HACHAGE,
            ConstantesBackup.LIBELLE_HACHAGE_ENTETE,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID,
        ]

        set_ops = {
            ConstantesBackup.LIBELLE_DIRTY_FLAG: True,
        }

        for champ in champs_fichier:
            set_ops['%s.%s.%s' % (ConstantesBackup.LIBELLE_FICHIERS_HORAIRE, str(heure_backup.hour), champ)] = \
                transaction[champ]

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesBackup.LIBVAL_CATALOGUE_QUOTIDIEN,
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
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }

        collection_backup = self.document_dao.get_collection(ConstantesBackup.COLLECTION_DOCUMENTS_NOM)
        collection_backup.update_one(filtre, ops, upsert=True)

        self.set_etape_suivante()  # Termine


class ProcessusFinaliserCatalogueQuotidien(MGProcessusTransaction):

    def __init__(self, controleur, evenement, transaction_mapper=None):
        super().__init__(controleur, evenement, transaction_mapper)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        self.__finaliser_catalogue_quotidien()
        self.set_etape_suivante()  # Termine

    def __finaliser_catalogue_quotidien(self):
        transaction = self.charger_transaction()

        self.__logger.debug("Transaction catalogue quotidien : %s" % str(transaction))
        jour_backup = datetime.datetime.fromtimestamp(
            transaction[ConstantesBackup.LIBELLE_JOUR],
            tz=datetime.timezone.utc
        )

        jour_backup = datetime.datetime(year=jour_backup.year, month=jour_backup.month, day=jour_backup.day)

        champs_copier = [
            ConstantesBackup.LIBELLE_FICHIERS_HORAIRE,
            ConstantesBackup.LIBELLE_FUUID_GROSFICHIERS,
            Constantes.DOCUMENT_INFODOC_SECURITE,
        ]

        set_ops = {
            ConstantesBackup.LIBELLE_DIRTY_FLAG: False,
        }

        for champ in champs_copier:
            try:
                set_ops[champ] = transaction[champ]
            except KeyError:
                pass

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesBackup.LIBVAL_CATALOGUE_QUOTIDIEN,
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
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }

        collection_backup = self.document_dao.get_collection(ConstantesBackup.COLLECTION_DOCUMENTS_NOM)
        collection_backup.update_one(filtre, ops, upsert=True)


class ProcessusInformationArchiveQuotidienne(MGProcessusTransaction):
    """
    Sauvegarder les informations de l'archive quotidienne dans le catalogue mensuel.
    """

    def __init__(self, controleur, evenement, transaction_mapper=None):
        super().__init__(controleur, evenement, transaction_mapper)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        transaction = self.charger_transaction()

        # self.__logger.debug("Transaction information archive quotidienne : %s" % str(transaction))
        jour_backup = datetime.datetime.fromtimestamp(
            transaction[ConstantesBackup.LIBELLE_JOUR],
            tz=datetime.timezone.utc
        )

        annee_backup = datetime.datetime(year=jour_backup.year, month=1, day=1)

        jour_formatte = jour_backup.strftime('%m%d')

        set_ops = {
            ConstantesBackup.LIBELLE_DIRTY_FLAG: True,
            '%s.%s' % (ConstantesBackup.LIBELLE_FICHIERS_QUOTIDIEN, jour_formatte): {
                ConstantesBackup.LIBELLE_ARCHIVE_HACHAGE: transaction[ConstantesBackup.LIBELLE_ARCHIVE_HACHAGE],
                ConstantesBackup.LIBELLE_ARCHIVE_NOMFICHIER: transaction[ConstantesBackup.LIBELLE_ARCHIVE_NOMFICHIER],
            }
        }

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesBackup.LIBVAL_CATALOGUE_ANNUEL,
            ConstantesBackup.LIBELLE_DOMAINE: transaction[ConstantesBackup.LIBELLE_DOMAINE],
            ConstantesBackup.LIBELLE_ANNEE: annee_backup,
        }
        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
            Constantes.DOCUMENT_INFODOC_SECURITE: transaction[Constantes.DOCUMENT_INFODOC_SECURITE]
        }
        set_on_insert.update(filtre)  # On utilise les memes valeurs que le filtre lors de l'insertion

        ops = {
            '$setOnInsert': set_on_insert,
            '$set': set_ops,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }

        collection_backup = self.document_dao.get_collection(ConstantesBackup.COLLECTION_DOCUMENTS_NOM)
        collection_backup.update_one(filtre, ops, upsert=True)

        self.set_etape_suivante()  # Termine


class ProcessusFinaliserCatalogueAnnuel(MGProcessusTransaction):

    def __init__(self, controleur, evenement, transaction_mapper=None):
        super().__init__(controleur, evenement, transaction_mapper)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        self.__finaliser_catalogue_annuel()
        self.set_etape_suivante()  # Termine

    def __finaliser_catalogue_annuel(self):
        transaction = self.charger_transaction()

        self.__logger.debug("Transaction catalogue mensuel : %s" % str(transaction))

        annee_backup = datetime.datetime.fromtimestamp(
            transaction[ConstantesBackup.LIBELLE_ANNEE],
            tz=datetime.timezone.utc
        )
        annee_backup = datetime.datetime(year=annee_backup.year, month=1, day=1)

        champs_copier = [
            ConstantesBackup.LIBELLE_FICHIERS_QUOTIDIEN,
        ]

        set_ops = {
            ConstantesBackup.LIBELLE_DIRTY_FLAG: False,
        }

        for champ in champs_copier:
            set_ops[champ] = transaction[champ]

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesBackup.LIBVAL_CATALOGUE_ANNUEL,
            ConstantesBackup.LIBELLE_SECURITE: transaction[ConstantesBackup.LIBELLE_SECURITE],
            ConstantesBackup.LIBELLE_DOMAINE: transaction[ConstantesBackup.LIBELLE_DOMAINE],
            ConstantesBackup.LIBELLE_ANNEE: annee_backup,
        }
        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
        }
        set_on_insert.update(filtre)  # On utilise les memes valeurs que le filtre lors de l'insertion

        ops = {
            '$setOnInsert': set_on_insert,
            '$set': set_ops,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }

        collection_backup = self.document_dao.get_collection(ConstantesBackup.COLLECTION_DOCUMENTS_NOM)
        collection_backup.update_one(filtre, ops, upsert=True)


class ProcessusInformationArchiveAnnuelle(MGProcessusTransaction):
    """
    Sauvegarder les informations de finalisation de l'archive annuelle.
    """

    def __init__(self, controleur, evenement, transaction_mapper=None):
        super().__init__(controleur, evenement, transaction_mapper)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        transaction = self.charger_transaction()

        self.__logger.debug("Transaction information archive annuelle : %s" % str(transaction))
        annee_backup = datetime.datetime.fromtimestamp(
            transaction[ConstantesBackup.LIBELLE_ANNEE],
            tz=datetime.timezone.utc
        )
        annee_backup = datetime.datetime(year=annee_backup.year, month=1, day=1)

        set_ops = {
            ConstantesBackup.LIBELLE_DIRTY_FLAG: False,
            ConstantesBackup.LIBELLE_ARCHIVE_HACHAGE: transaction[ConstantesBackup.LIBELLE_ARCHIVE_HACHAGE],
            ConstantesBackup.LIBELLE_ARCHIVE_NOMFICHIER: transaction[ConstantesBackup.LIBELLE_ARCHIVE_NOMFICHIER],
        }

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesBackup.LIBVAL_CATALOGUE_ANNUEL,
            ConstantesBackup.LIBELLE_DOMAINE: transaction[ConstantesBackup.LIBELLE_DOMAINE],
            ConstantesBackup.LIBELLE_ANNEE: annee_backup,
        }
        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
        }
        set_on_insert.update(filtre)  # On utilise les memes valeurs que le filtre lors de l'insertion

        ops = {
            '$setOnInsert': set_on_insert,
            '$set': set_ops,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }

        collection_backup = self.document_dao.get_collection(ConstantesBackup.COLLECTION_DOCUMENTS_NOM)
        collection_backup.update_one(filtre, ops, upsert=True)

        self.set_etape_suivante()  # Termine


class ProcessusRapportRestauration(MGProcessusTransaction):
    """
    Sauvegarder les informations de finalisation de l'archive annuelle.
    """

    def __init__(self, controleur, evenement, transaction_mapper=None):
        super().__init__(controleur, evenement, transaction_mapper)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        transaction = self.transaction
        self._controleur.gestionnaire.maj_rapport_restauration(transaction)
        self.set_etape_suivante()  # Termine


class ProcessusAjouterCatalogueApplication(MGProcessusTransaction):

    def __init__(self, controleur, evenement, transaction_mapper=None):
        super().__init__(controleur, evenement, transaction_mapper)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        transaction = self.charger_transaction()
        nom_application = transaction[ConstantesBackup.LIBELLE_APPLICATION]

        self.__logger.debug("Transaction recue: %s" % str(transaction))
        timestamp_backup = datetime.datetime.fromtimestamp(
            transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_ESTAMPILLE],
            tz=datetime.timezone.utc
        )

        champs_fichier = [
            ConstantesBackup.LIBELLE_ARCHIVE_NOMFICHIER,
            ConstantesBackup.LIBELLE_ARCHIVE_HACHAGE,
            ConstantesBackup.LIBELLE_CATALOGUE_NOMFICHIER,
            # ConstantesBackup.LIBELLE_CATALOGUE_HACHAGE,
        ]

        set_ops = {
            ConstantesBackup.LIBELLE_DIRTY_FLAG: True,
            Constantes.DOCUMENT_INFODOC_SECURITE: transaction[Constantes.DOCUMENT_INFODOC_SECURITE],
            '%s.%s.%s' % (ConstantesBackup.LIBELLE_APPLICATIONS, nom_application, Constantes.EVENEMENT_MESSAGE_EVENEMENT_TIMESTAMP): timestamp_backup,
        }

        for champ in champs_fichier:
            set_ops['%s.%s.%s' % (ConstantesBackup.LIBELLE_APPLICATIONS, nom_application, champ)] = transaction[champ]

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesBackup.LIBVAL_CATALOGUE_APPLICATIONS,
            ConstantesBackup.LIBELLE_DOMAINE: 'Applications',
        }
        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
        }
        set_on_insert.update(filtre)  # On utilise les memes valeurs que le filtre lors de l'insertion

        ops = {
            '$setOnInsert': set_on_insert,
            '$set': set_ops,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }

        collection_backup = self.document_dao.get_collection(ConstantesBackup.COLLECTION_DOCUMENTS_NOM)
        collection_backup.update_one(filtre, ops, upsert=True)

        self.verifier_presence_cle()

        self.set_etape_suivante()  # Termine

    def verifier_presence_cle(self):
        transaction = self.charger_transaction()
        if transaction.get('iv'):
            iv = transaction['iv']
            cles = transaction.get('cles')
            if cles is None and transaction.get('cle'):
                # On a seulement la cle de millegrille
                enveloppe_millegrille = self._controleur._contexte.signateur_transactions.get_enveloppe_millegrille()
                fingerprint_b64 = enveloppe_millegrille.fingerprint_b64
                cles = {fingerprint_b64: transaction['cle']}

            transactions_nomfichier = transaction[ConstantesBackup.LIBELLE_ARCHIVE_NOMFICHIER]

            commande_sauvegarder_cle = {
                'domaine': 'Applications',
                Constantes.ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS: {
                    ConstantesBackup.LIBELLE_ARCHIVE_NOMFICHIER: transactions_nomfichier,
                },
                "cles": cles,
                "iv": iv,
                'domaine_action_transaction': Constantes.ConstantesMaitreDesCles.TRANSACTION_NOUVELLE_CLE_BACKUPAPPLICATION,
                'securite': transaction[Constantes.DOCUMENT_INFODOC_SECURITE],
            }

            self.controleur.generateur_transactions.transmettre_commande(
                commande_sauvegarder_cle,
                'commande.MaitreDesCles.%s' % Constantes.ConstantesMaitreDesCles.COMMANDE_SAUVEGARDER_CLE,
                exchange=Constantes.SECURITE_SECURE,
            )

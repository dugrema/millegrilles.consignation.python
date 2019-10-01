# Module du domaine des taches.

from millegrilles import Constantes
from millegrilles.Domaines import GestionnaireDomaineStandard
from millegrilles.MGProcessus import MGProcessus, MGProcessusTransaction
from millegrilles.dao.EmailDAO import SmtpDAO
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction

from bson import ObjectId

import datetime
import json
import uuid
import logging


class TachesConstantes:

    DOMAINE_NOM = 'millegrilles.domaines.Taches'
    QUEUE_SUFFIXE = DOMAINE_NOM
    COLLECTION_TRANSACTIONS_NOM = QUEUE_SUFFIXE
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_TRANSACTIONS_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_TRANSACTIONS_NOM

    TRANSACTION_NOUVELLE_TACHE = '%s.nouvelle' % DOMAINE_NOM
    TRANSACTION_NOTIFICATION_TACHE = '%s.notification' % DOMAINE_NOM
    TRANSACTION_ACTION_TACHE_COMPLETEE = '%s.actionUsager.completee' % DOMAINE_NOM
    TRANSACTION_ACTION_TACHE_RAPPEL = '%s.actionUsager.rappel' % DOMAINE_NOM
    TRANSACTION_TACHE_ACTION_DUE = '%s.actionDue' % DOMAINE_NOM

    # Niveaux d'une notification de tache
    NIVEAU_SUIVI = 'suivi'                  # Niveau bas avec limite de temps
    NIVEAU_INFORMATION = 'information'      # Plus bas niveau sans limite de temps
    NIVEAU_AVERTISSEMENT = 'avertissement'  # Niveau par defaut / grave
    NIVEAU_ALERTE = 'alerte'                # Plus haut niveau / critique

    LIBVAL_NOTIFICATIONS = 'notifications'
    LIBVAL_TACHES_TABLEAU = 'taches_tableau'
    LIBVAL_TACHE_NOTIFICATION = 'tache_notification'

    # Action posee par l'usager sur la notification
    LIBELLE_ID_NOTIFICATION = 'id_notification'  # _id de la notification
    LIBELLE_NIVEAU_NOTIFICATION = 'niveau'  # Niveau d'urgence de la notification
    LIBELLE_COMPTEUR = 'compteur'  # Compte le nombre de fois que la notification est survenue
    LIBELLE_ACTION = 'action'  # Libelle (etiquette) de l'action a faire
    ACTION_VUE = 'vue'         # La notification a ete vue, pas d'autres action requise
    ACTION_RAPPEL = 'rappel'   # L'usager demande un rappel apres une periode de temps. Cachee en attendant.

    LIBELLE_DOMAINE = 'domaine'
    LIBELLE_SOURCE = 'source'
    LIBELLE_COLLATEUR = 'collateur'
    LIBELLE_VALEURS = 'valeurs'
    LIBELLE_DATE = 'date'
    LIBELLE_ACTIVITE = 'activite'
    LIBELLE_ETAT = 'etat_notification'
    LIBELLE_NOTIFICATIONS = 'notifications'
    LIBELLE_DERNIERE_ACTION = 'derniere_action'
    LIBELLE_PERIODE_ATTENTE = 'periode_attente'
    LIBELLE_DATE_ACTION = 'date_action'  # Date de prise d'action
    LIBELLE_DATE_ATTENTE_ACTION = 'date_attente_action'  # Date a partir de laquelle on fait un rappel, de-snooze, etc.
    LIBELLE_TACHES_ACTIVES = 'taches_actives'
    LIBELLE_UUID_TACHE = 'tache_uuid'
    LIBELLE_TITRE = 'titre'
    LIBELLE_ACTIONS_NOTIFICATION = 'actions_notifications'
    LIBELLE_ACTIONS_VISUALISER_DOC = 'inclure_visualiser_document'
    LIBELLE_ACTIONS_DOMAINES = 'actions_domaine'
    LIBELLE_ACTION_DOMAINE = 'action'
    LIBELLE_ACTION_LIBELLE = 'libelle'
    LIBELLE_TACHE_DATE_RAPPEL = 'rappel'
    LIBELLE_RAPPEL_TIMESTAMP = 'timestamp'

    ETAT_NOUVELLE = 'nouvelle'    # Nouvelle tache, notification non generee
    ETAT_ACTIVE = 'active'        # Notification active, pas encore actionee par l'usager
    ETAT_COMPLETEE = 'completee'  # La notification a ete actionnee par l'usager, plus rien a faire.
    ETAT_RAPPEL = 'rappel'        # En attente de rappel aupres de l'usager. Cachee en attendant.

    DOC_NOTIFICATIONS = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_NOTIFICATIONS,
        LIBELLE_NOTIFICATIONS: list(),
    }

    DOC_SUMMARY_NOTIFICATION = {
        LIBELLE_TITRE: None,
        LIBELLE_DATE: None,
        LIBELLE_UUID_TACHE: None,
        LIBELLE_NIVEAU_NOTIFICATION: None,
        LIBELLE_ACTIONS_NOTIFICATION: True,
    }

    DOC_TACHES_TABLEAU = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_TACHES_TABLEAU,
        LIBELLE_TACHES_ACTIVES: dict(),  # Docs type DOC_TACHE_TABLEAU_TEMPLATE
    }

    DOC_TACHE_TABLEAU_TEMPLATE = {
        LIBELLE_NIVEAU_NOTIFICATION: NIVEAU_INFORMATION,
        LIBELLE_DATE: None,  # Date plus recente activite
        LIBELLE_TITRE: None,  # Courte description de la tache (64 chars)
        LIBELLE_DOMAINE: None,
        LIBELLE_COLLATEUR: dict(),
        LIBELLE_UUID_TACHE: None,
        LIBELLE_ACTIONS_NOTIFICATION: True,    # Boutons: Vue, Rappel, Suivre
        LIBELLE_ACTIONS_VISUALISER_DOC: True,  # Bouton, redirige vers domaine doc d'origine

        # Ajoute au domaine, envoye en transaction (domaine.action). Notification est vue.
        # Objet DOC_ACTION_DOMAINE
        LIBELLE_ACTIONS_DOMAINES: list(),
    }

    DOC_ACTION_DOMAINE = {
        LIBELLE_ACTION_DOMAINE: None,
        LIBELLE_ACTION_LIBELLE: None,
    }


class GestionnaireTaches(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._traitement_message = None

    def configurer(self):
        super().configurer()

        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        collection_domaine.create_index([
            (TachesConstantes.LIBELLE_UUID_TACHE, 1),
            (Constantes.DOCUMENT_INFODOC_LIBELLE, 1)
        ], unique=True)

        collection_domaine.create_index([
            (TachesConstantes.LIBELLE_RAPPEL_TIMESTAMP, -1)
        ])

        collection_domaine.create_index([
            (TachesConstantes.LIBELLE_DOMAINE, 1),
            (Constantes.DOCUMENT_INFODOC_LIBELLE, 1)
        ])

    def demarrer(self):
        super().demarrer()
        self.initialiser_document(TachesConstantes.LIBVAL_NOTIFICATIONS, TachesConstantes.DOC_NOTIFICATIONS)
        self.initialiser_document(TachesConstantes.LIBVAL_TACHES_TABLEAU, TachesConstantes.DOC_TACHES_TABLEAU)

    def get_nom_queue(self):
        return TachesConstantes.QUEUE_SUFFIXE

    def get_nom_collection(self):
        return TachesConstantes.COLLECTION_DOCUMENTS_NOM

    def get_collection_transaction_nom(self):
        return TachesConstantes.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return TachesConstantes.COLLECTION_PROCESSUS_NOM

    def get_nom_domaine(self):
        return TachesConstantes.DOMAINE_NOM

    def traiter_cedule(self, message):
        timestamp_message = message['timestamp']['UTC']
        if timestamp_message[4] % 6 == 0:
            self._logger.debug("Traiter actions dues")
            # Declencher la verification des actions sur taches
            self.verifier_taches_actionsdues(message)

    def identifier_processus(self, domaine_transaction):
        if domaine_transaction == TachesConstantes.TRANSACTION_ACTION_TACHE_COMPLETEE:
            processus = "millegrilles_domaines_Taches:ProcessusActionCompletee"
        elif domaine_transaction == TachesConstantes.TRANSACTION_ACTION_TACHE_RAPPEL:
            processus = "millegrilles_domaines_Taches:ProcessusActionRappel"
        elif domaine_transaction == TachesConstantes.TRANSACTION_NOTIFICATION_TACHE:
            # Notification recue
            processus = "millegrilles_domaines_Taches:ProcessusNotificationRecue"
        elif domaine_transaction == TachesConstantes.TRANSACTION_TACHE_ACTION_DUE:
            processus = "millegrilles_domaines_Taches:ProcessusActionDue"
        else:
            processus = super().identifier_processus(domaine_transaction)

        return processus

    def verifier_taches_actionsdues(self, message):
        collection_taches = self.document_dao.get_collection(TachesConstantes.COLLECTION_DOCUMENTS_NOM)
        maintenant = datetime.datetime.utcnow()

        filtre = {
            TachesConstantes.LIBELLE_TACHE_DATE_RAPPEL: {'$lt': maintenant},
            Constantes.DOCUMENT_INFODOC_LIBELLE: TachesConstantes.LIBVAL_TACHE_NOTIFICATION,
        }

        generateur_transactions = self.generateur_transactions
        taches = collection_taches.find(filtre)
        for tache in taches:
            uuid_tache = tache[TachesConstantes.LIBELLE_UUID_TACHE]
            self._logger.debug("Tache due: %s" % uuid_tache)
            transaction = {
                TachesConstantes.LIBELLE_UUID_TACHE: uuid_tache
            }
            domaine = TachesConstantes.TRANSACTION_TACHE_ACTION_DUE
            generateur_transactions.soumettre_transaction(transaction, domaine)


class ProcessusTaches(MGProcessusTransaction):

    def get_collection_transaction_nom(self):
        return TachesConstantes.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return TachesConstantes.COLLECTION_PROCESSUS_NOM

    def supprimer_notification(self, collection, uuid_tache):
        notifications_ops = {
            '$pull': {
                TachesConstantes.LIBVAL_NOTIFICATIONS: {TachesConstantes.LIBELLE_UUID_TACHE: uuid_tache}
            }
        }
        notifications_filtre = {Constantes.DOCUMENT_INFODOC_LIBELLE: TachesConstantes.LIBVAL_NOTIFICATIONS}
        collection.update_one(notifications_filtre, notifications_ops)

    def supprimer_sur_tableau(self, collection, uuid_tache):
        tableau_ops = {
            "$unset": {"%s.%s" % (TachesConstantes.LIBELLE_TACHES_ACTIVES, uuid_tache): 1}
        }
        tableau_filtre = {Constantes.DOCUMENT_INFODOC_LIBELLE: TachesConstantes.LIBVAL_TACHES_TABLEAU}
        collection.update_one(tableau_filtre, tableau_ops)

    def ajouter_notification(self, tache):
        collection = self.document_dao.get_collection(TachesConstantes.COLLECTION_DOCUMENTS_NOM)

        titre = tache[TachesConstantes.LIBELLE_UUID_TACHE]
        uuid_tache = tache[TachesConstantes.LIBELLE_UUID_TACHE]
        niveau = tache[TachesConstantes.LIBELLE_NIVEAU_NOTIFICATION]
        date_activite = tache[TachesConstantes.LIBELLE_ACTIVITE][0][TachesConstantes.LIBELLE_DATE]

        # Ajouter notification dans mongo
        doc_notification = TachesConstantes.DOC_SUMMARY_NOTIFICATION.copy()
        doc_notification[TachesConstantes.LIBELLE_TITRE] = titre
        doc_notification[TachesConstantes.LIBELLE_DATE] = date_activite
        doc_notification[TachesConstantes.LIBELLE_UUID_TACHE] = uuid_tache
        doc_notification[TachesConstantes.LIBELLE_NIVEAU_NOTIFICATION] = niveau
        doc_notification[TachesConstantes.LIBELLE_ACTIONS_NOTIFICATION] = True
        ops = {
            '$push': {
                TachesConstantes.LIBELLE_NOTIFICATIONS: doc_notification
            },
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: TachesConstantes.LIBVAL_NOTIFICATIONS
        }

        collection.update_one(filtre, ops)


class ProcessusNotificationRecue(ProcessusTaches):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.transaction
        domaine = transaction[TachesConstantes.LIBELLE_DOMAINE]
        source = transaction[TachesConstantes.LIBELLE_SOURCE]
        collateur = transaction[TachesConstantes.LIBELLE_COLLATEUR]

        self._logger.debug("Traitement notification tache: %s" % str(transaction))
        collection = self.document_dao.get_collection(TachesConstantes.COLLECTION_DOCUMENTS_NOM)

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: Constantes.DOCUMENT_TACHE_NOTIFICATION,
            TachesConstantes.LIBELLE_DOMAINE: domaine,
            TachesConstantes.LIBELLE_COLLATEUR: collateur,
        }

        # Trouver document de tache
        taches_cursor = collection.find(filtre)
        taches = list()
        for tache in taches_cursor:
            taches.append(tache['_id'])

        if len(taches) == 0:
            # Tache n'existe pas, on va en creer une nouvelle
            etape_suivante = ProcessusNotificationRecue.creer_tache.__name__
        else:
            # On a plusieurs taches qui correspondent, on va traiter chaque tache individuellement
            etape_suivante = ProcessusNotificationRecue.traiter_plusieurs_taches.__name__

        self.set_etape_suivante(etape_suivante)

        titre = self.__formatter_titre_notification(transaction)

        return {
            'source': source,
            'domaine': domaine,
            'taches': taches,
            'collateur': collateur,
            'titre': titre,
        }

    def creer_tache(self):
        transaction = self.transaction
        domaine = transaction[TachesConstantes.LIBELLE_DOMAINE]
        collateur = transaction[TachesConstantes.LIBELLE_COLLATEUR]
        niveau = transaction[TachesConstantes.LIBELLE_NIVEAU_NOTIFICATION]

        entree_historique = self.__generer_entree_historique(transaction, self.parametres['titre'])

        push_op = {
            TachesConstantes.LIBELLE_ACTIVITE: entree_historique
        }

        on_insert_op = {
            TachesConstantes.LIBELLE_DOMAINE: domaine,
            Constantes.DOCUMENT_INFODOC_LIBELLE: Constantes.DOCUMENT_TACHE_NOTIFICATION,
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
            TachesConstantes.LIBELLE_NIVEAU_NOTIFICATION: niveau,
            TachesConstantes.LIBELLE_COLLATEUR: collateur,
            TachesConstantes.LIBELLE_UUID_TACHE: str(uuid.uuid4()),
            TachesConstantes.LIBELLE_ETAT: TachesConstantes.ETAT_NOUVELLE,
        }

        ops = {
            '$push': push_op,
            '$setOnInsert': on_insert_op,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }

        # Inserer par upsert
        collection = self.document_dao.get_collection(TachesConstantes.COLLECTION_DOCUMENTS_NOM)
        update_result = collection.update_one(filter=on_insert_op, update=ops, upsert=True)

        self.set_etape_suivante(ProcessusNotificationRecue.maj_dash_notifications.__name__)  # Termine

        return {
            'taches': [update_result.upserted_id],
            'date': entree_historique[TachesConstantes.LIBELLE_DATE],
        }

    def traiter_plusieurs_taches(self):
        transaction = self.transaction
        date_activite = datetime.datetime.utcfromtimestamp(transaction[TachesConstantes.LIBELLE_DATE])

        for tache_id in self.parametres['taches']:
            ops = {
                '$push': {
                    # Ajouter a la liste d'activite
                    # Trier en ordre decroissant, conserver uniquement les 100 dernieres entrees.
                    TachesConstantes.LIBELLE_ACTIVITE: {
                        '$each': [self.__generer_entree_historique(transaction, self.parametres['titre'])],
                        '$sort': {TachesConstantes.LIBELLE_DATE: -1},
                        '$slice': 100,
                    }
                },
                '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
            }

            filtre = {
                '_id': tache_id
            }

            # Inserer par upsert
            collection = self.document_dao.get_collection(TachesConstantes.COLLECTION_DOCUMENTS_NOM)
            collection.update_one(filter=filtre, update=ops, upsert=False)

        self.set_etape_suivante(ProcessusNotificationRecue.maj_dash_notifications.__name__)  # Termine

        return {
            'date': date_activite,
        }

    def maj_dash_notifications(self):
        collection = self.document_dao.get_collection(TachesConstantes.COLLECTION_DOCUMENTS_NOM)
        liste_tacheids = self.parametres['taches']
        taches = collection.find({'_id': {'$in': liste_tacheids}})

        liste_avertir_usager = list()
        for tache in taches:
            # Verifier si la tache est en mode suivi (snooze)
            etat = tache[TachesConstantes.LIBELLE_ETAT]
            uuid_tache = tache[TachesConstantes.LIBELLE_UUID_TACHE]

            dashboard_update = TachesConstantes.DOC_TACHE_TABLEAU_TEMPLATE.copy()
            dashboard_update[TachesConstantes.LIBELLE_DATE] = self.parametres['date']  # Date plus recente activite
            dashboard_update[TachesConstantes.LIBELLE_TITRE] = self.parametres['titre']  # Courte description de la tache (64 chars)
            dashboard_update[TachesConstantes.LIBELLE_DOMAINE] = tache[TachesConstantes.LIBELLE_DOMAINE]
            dashboard_update[TachesConstantes.LIBELLE_COLLATEUR] = tache[TachesConstantes.LIBELLE_COLLATEUR]
            dashboard_update[TachesConstantes.LIBELLE_UUID_TACHE] = uuid_tache
            dashboard_update[TachesConstantes.LIBELLE_ETAT] = etat
            dashboard_update[TachesConstantes.LIBELLE_ACTIONS_NOTIFICATION] = True    # Boutons: Vue, Rappel, Suivre
            dashboard_update[TachesConstantes.LIBELLE_ACTIONS_VISUALISER_DOC] = True  # Bouton, redirige vers domaine doc d'origine

            # Ajoute au domaine, envoye en transaction (domaine.action). Notification est vue.
            # Objet DOC_ACTION_DOMAINE
            dashboard_update[TachesConstantes.LIBELLE_ACTIONS_DOMAINES] = None

            generer_notification = False
            if etat in [TachesConstantes.ETAT_NOUVELLE, TachesConstantes.ETAT_COMPLETEE]:
                # On va faire un toggle de l'etat de la tache a actif, generer notification.
                generer_notification = True

                if etat == TachesConstantes.ETAT_COMPLETEE:
                    # On reactive la tache
                    filtre_tache = {"_id": tache['_id']}
                    ops_tache = {"$set": {TachesConstantes.LIBELLE_ETAT: TachesConstantes.ETAT_NOUVELLE}}
                    collection.update_one(filtre_tache, ops_tache)

            if generer_notification:
                liste_avertir_usager.append(dashboard_update)
                self.ajouter_notification(tache)

            # Mettre a jour dashboard
            ops_tableau = {
                '$set': {
                    '%s.%s' % (TachesConstantes.LIBELLE_TACHES_ACTIVES, uuid_tache): dashboard_update,
                },
                '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
            }
            filtre_tableau = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: TachesConstantes.LIBVAL_TACHES_TABLEAU
            }
            collection.update_one(filtre_tableau, ops_tableau)

        if len(liste_avertir_usager) > 0:
            self.set_etape_suivante(ProcessusNotificationRecue.avertir_usager.__name__)  # Termine
            return {
                'liste_avertir_usager': liste_avertir_usager
            }
        else:
            self.set_etape_suivante()  # Termine

    def avertir_usager(self):
        configuration = self._controleur.configuration

        sujet = "Notification %s" % configuration.nom_millegrille

        for notification in self.parametres['liste_avertir_usager']:
            contenu = "Nouvelle notification pour la MilleGrille %s\n\n%s" % (configuration.nom_millegrille, str(notification))
            self._logger.info("Transmission notifcation par courriel: %s" % sujet)
            self._logger.debug(contenu)

            # smtp_dao = SmtpDAO(self._controleur.configuration)
            # smtp_dao.envoyer_notification(sujet, contenu)

        self.set_etape_suivante()  # Termine le processus

    def __formatter_titre_notification(self, transaction):
        configuration = self._controleur.configuration
        domaine = transaction[TachesConstantes.LIBELLE_DOMAINE]
        valeurs = transaction[TachesConstantes.LIBELLE_VALEURS]

        niveau = transaction[TachesConstantes.LIBELLE_NIVEAU_NOTIFICATION]
        short_domaine = domaine.split('.')[-1]
        description = ', '.join(['%s=%s' % (key, value) for key, value in valeurs.items()])

        titre = '%s %s %s: %s' % (configuration.nom_millegrille, niveau, short_domaine, description)

        if len(titre) > 64:
            titre = titre[0:64]

        return titre

    def __generer_entree_historique(self, transaction, titre):
        source = transaction[TachesConstantes.LIBELLE_SOURCE]
        valeurs = transaction[TachesConstantes.LIBELLE_VALEURS]
        date_activite = datetime.datetime.utcfromtimestamp(transaction[TachesConstantes.LIBELLE_DATE])
        niveau = transaction[TachesConstantes.LIBELLE_NIVEAU_NOTIFICATION]

        entree_historique = {
            TachesConstantes.LIBELLE_SOURCE: source,
            TachesConstantes.LIBELLE_VALEURS: valeurs,
            TachesConstantes.LIBELLE_DATE: date_activite,
            TachesConstantes.LIBELLE_NIVEAU_NOTIFICATION: niveau,
            TachesConstantes.LIBELLE_TITRE: titre,
        }

        return entree_historique


class ProcessusActionCompletee(ProcessusTaches):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.transaction
        collection = self.document_dao.get_collection(TachesConstantes.COLLECTION_DOCUMENTS_NOM)
        uuid_tache = transaction[TachesConstantes.LIBELLE_UUID_TACHE]

        filtre = {TachesConstantes.LIBELLE_UUID_TACHE: uuid_tache}
        ops = {'$set': {TachesConstantes.LIBELLE_ETAT: TachesConstantes.ETAT_COMPLETEE}}
        resultat = collection.update_one(filtre, ops)

        # Nettoyer tableau et notifications
        self.supprimer_notification(collection, uuid_tache)
        self.supprimer_sur_tableau(collection, uuid_tache)

        if resultat.modified_count == 0:
            raise Exception("Erreur marquage tache %s comme vue = (0 document trouve)" % uuid_tache)

        self.set_etape_suivante()  # Termine


class ProcessusActionRappel(ProcessusTaches):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        collection = self.document_dao.get_collection(TachesConstantes.COLLECTION_DOCUMENTS_NOM)

        transaction = self.transaction
        uuid_tache = transaction[TachesConstantes.LIBELLE_UUID_TACHE]
        epoch_rappel = transaction[TachesConstantes.LIBELLE_RAPPEL_TIMESTAMP]
        date_rappel = datetime.datetime.fromtimestamp(epoch_rappel)

        # Modifier etat de la tache
        filtre = {TachesConstantes.LIBELLE_UUID_TACHE: uuid_tache}
        ops = {'$set': {
            TachesConstantes.LIBELLE_ETAT: TachesConstantes.ETAT_RAPPEL,
            TachesConstantes.LIBELLE_TACHE_DATE_RAPPEL: date_rappel,
        }}
        resultat = collection.update_one(filtre, ops)

        # Update tableau
        tableau_ops = {
            '$set': {
                '%s.%s.%s' % (TachesConstantes.LIBELLE_TACHES_ACTIVES, uuid_tache, TachesConstantes.LIBELLE_ETAT): TachesConstantes.ETAT_RAPPEL
            }
        }
        tableau_filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: TachesConstantes.LIBVAL_TACHES_TABLEAU
        }
        collection.update_one(tableau_filtre, tableau_ops)

        # Supprimer du document de notifications
        self.supprimer_notification(collection, uuid_tache)

        if resultat.modified_count == 0:
            raise Exception("Erreur marquage tache %s comme vue = (0 document trouve)" % uuid_tache)

        self.set_etape_suivante()  # Termine


class ProcessusActionDue(ProcessusTaches):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def initiale(self):
        transaction = self.transaction
        collection = self.document_dao.get_collection(TachesConstantes.COLLECTION_DOCUMENTS_NOM)
        uuid_tache = transaction[TachesConstantes.LIBELLE_UUID_TACHE]

        self.__logger.debug("Marquer tache comme expiree (due): %s" % uuid_tache)

        filtre = {TachesConstantes.LIBELLE_UUID_TACHE: uuid_tache}
        ops = {
            '$set': {
                TachesConstantes.LIBELLE_ETAT: TachesConstantes.ETAT_ACTIVE,
            },
            '$unset': {
                TachesConstantes.LIBELLE_TACHE_DATE_RAPPEL: 1,
            }
        }
        resultat = collection.update_one(filtre, ops)
        if resultat.matched_count == 0:
            raise Exception("Erreur marquage tache %s comme vue = (0 document trouve)" % uuid_tache)

        # Remettre notification
        tache = collection.find_one({TachesConstantes.LIBELLE_UUID_TACHE: uuid_tache})
        self.ajouter_notification(tache)

        self.set_etape_suivante()  # Termine

    def avertir_usager(self):
        pass


class FormatteurEvenementNotification:

    TEMPLATE_NOTIFICATION = {
        "domaine": None,

        "niveau": None,

        Constantes.EVENEMENT_MESSAGE_EVENEMENT: Constantes.EVENEMENT_NOTIFICATION,
        "source": {
            "collection": None,
        },

        # Le collateur de tache - permet d'identifier la tache de maniere unique dans le domaine
        "collateur": {
        },

        "valeurs": {
        },
    }

    def __init__(self, domaine: str, nom_collection: str, generateur_transactions: GenerateurTransaction):
        self._domaine = domaine
        self._collection = nom_collection
        self._generateur_transactions = generateur_transactions

        self._template = FormatteurEvenementNotification.TEMPLATE_NOTIFICATION.copy()
        self._template['domaine'] = domaine
        self._template['source']['collection'] = nom_collection

    def __formatter_notification(
            self, source: dict, collateur: dict, valeurs: dict, niveau: str):
        notification = self._template.copy()
        notification['niveau'] = niveau
        notification['source'].update(source)
        notification['collateur'] = collateur
        notification['valeurs'] = valeurs
        notification['date'] = int(datetime.datetime.utcnow().timestamp())

        return notification

    def emettre_notification_tache(
            self, source: dict, collateur: dict, valeurs: dict, niveau: str = TachesConstantes.NIVEAU_INFORMATION):
        """
        Emet une nouvelle notification pour une tache.

        :param source: Business key de la source
        :param collateur: Collateur de tache
        :param valeurs: Regles en cause avec leur valeurs
        :param niveau: Niveau de notification
        """

        notification = self.__formatter_notification(source, collateur, valeurs, niveau)
        routing = TachesConstantes.TRANSACTION_NOTIFICATION_TACHE
        self._generateur_transactions.soumettre_transaction(notification, routing)

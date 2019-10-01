# Module du domaine des taches.

from millegrilles import Constantes
from millegrilles.Domaines import GestionnaireDomaineStandard
from millegrilles.MGProcessus import MGProcessus, MGProcessusTransaction
from millegrilles.dao.EmailDAO import SmtpDAO

from bson import ObjectId

import datetime
import json


class TachesConstantes:

    DOMAINE_NOM = 'millegrilles.domaines.Taches'
    QUEUE_SUFFIXE = DOMAINE_NOM
    COLLECTION_TRANSACTIONS_NOM = QUEUE_SUFFIXE
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_TRANSACTIONS_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_TRANSACTIONS_NOM

    TRANSACTION_NOUVELLE_TACHE = 'millegrilles.domaines.Taches.nouvelle'
    TRANSACTION_ACTION_TACHE = 'millegrilles.domaines.Taches.actionUsager'

    # Niveaux d'une notification de tache
    SUIVI = 'suivi'                  # Niveau bas avec limite de temps
    INFORMATION = 'information'      # Plus bas niveau sans limite de temps
    AVERTISSEMENT = 'avertissement'  # Niveau par defaut / grave
    ALERTE = 'alerte'                # Plus haut niveau / critique

    # Action posee par l'usager sur la notification
    LIBELLE_ID_NOTIFICATION = 'id_notification'  # _id de la notification
    LIBELLE_NIVEAU_NOTIFICATION = 'niveau'  # Niveau d'urgence de la notification
    LIBELLE_COMPTEUR = 'compteur'  # Compte le nombre de fois que la notification est survenue
    LIBELLE_ACTION = 'action'  # Libelle (etiquette) de l'action a faire
    ACTION_VUE = 'vue'         # La notification a ete vue, pas d'autres action requise
    ACTION_RAPPEL = 'rappel'   # L'usager demande un rappel apres une periode de temps. Cachee en attendant.
    ACTION_SURVEILLE = 'surveille'  # L'usager demande de ne pas etre informe (cacher la notif) si l'evenement ne survient pas a nouveau

    LIBELLE_ETAT = 'etat_notification'
    LIBELLE_DERNIERE_ACTION = 'derniere_action'
    LIBELLE_PERIODE_ATTENTE = 'periode_attente'
    LIBELLE_DATE_ACTION = 'date_action'  # Date de prise d'action
    LIBELLE_DATE_ATTENTE_ACTION = 'date_attente_action'  # Date a partir de laquelle on fait un rappel, de-snooze, etc.
    ETAT_ACTIVE = 'active'        # Notification active, pas encore actionee par l'usager
    ETAT_COMPLETEE = 'completee'  # La notification a ete actionnee par l'usager, plus rien a faire.
    ETAT_RAPPEL = 'rappel'        # En attente de rappel aupres de l'usager. Cachee en attendant.
    ETAT_SURVEILLE = 'surveille'  # Notification surveille, va etre escaladee si survient a nouveau. Sinon elle se complete.


class GestionnaireTaches(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._traitement_message = None

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
        # Declencher la verification des actions sur taches
        self.verifier_taches_actionsdues(message)

    def identifier_processus(self, domaine_transaction):
        if domaine_transaction == TachesConstantes.TRANSACTION_ACTION_TACHE:
            processus = "millegrilles_domaines_Taches:ProcessusActionUsager"
        elif domaine_transaction == TachesConstantes.TRANSACTION_NOUVELLE_TACHE:
            # Notification recue
            processus = "millegrilles_domaines_Taches:ProcessusNotificationRecue"
        else:
            processus = super().identifier_processus(domaine_transaction)

        return processus

    def verifier_taches_actionsdues(self, message):
        collection_taches = self.document_dao.get_collection(TachesConstantes.COLLECTION_DOCUMENTS_NOM)

        filtre = {
            'date_attente_action': {'$lt': datetime.datetime.utcnow()}
        }
        curseur = collection_taches.find(filtre)

        operations_template = {
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True
            },
            '$unset': {
                TachesConstantes.LIBELLE_DATE_ATTENTE_ACTION: ''
            }
        }

        for taches in curseur:
            etat_tache = taches['etat_tache']

            if etat_tache == TachesConstantes.ETAT_SURVEILLE:
                # La notification est completee (aucun changement depuis qu'elle est en etat de surveillance)
                operations = operations_template.copy()
                operations['$set'] = {
                    TachesConstantes.LIBELLE_ETAT: TachesConstantes.ETAT_COMPLETEE
                }
                self._logger.debug("Completer tache (surveillee): %s" % str(taches))
                collection_taches.update_one({'_id': taches['_id']}, operations)

            elif etat_tache == TachesConstantes.ETAT_RAPPEL:
                # C'est l'heure du rappel. On remet la notification au mode actif.
                operations = operations_template.copy()
                operations['$set'] = {
                    TachesConstantes.LIBELLE_ETAT: TachesConstantes.ETAT_ACTIVE
                }
                self._logger.debug("Rappeler tache: %s" % str(taches))
                collection_taches.update_one({'_id': taches['_id']}, operations)


class ProcessusTaches(MGProcessusTransaction):

    def get_collection_transaction_nom(self):
        return TachesConstantes.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return TachesConstantes.COLLECTION_PROCESSUS_NOM


class ProcessusNotificationRecue(ProcessusTaches):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.transaction
        self._logger.debug("Traitement notification tache: %s" % str(transaction))
        collection = self.document_dao.get_collection(TachesConstantes.COLLECTION_DOCUMENTS_NOM)

        nouveaux_documents_notification = []

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: Constantes.DOCUMENT_NOTIFICATION_REGLESIMPLE
        }

        # Extraire la source en elements distincts, sinon Mongo compare le dict() en "ordre" (aleatoire)
        for source_val in transaction['source']:
            cle = 'source.%s' % source_val
            filtre[cle] = transaction['source'][source_val]

        # L'etape suivante est determine par l'etat des notifications (nouvelles, existantes, rappel, etc.)
        etape_suivante = 'finale'
        for regle in transaction['regles']:
            self._logger.debug("Traitement document %s regle %s" % (json.dumps(transaction['source'], indent=2), regle))
            filtre_regle = filtre.copy()
            for cle_regle in regle:
                cle_regle_mongo = 'regle.%s' % cle_regle
                elements_regle = regle[cle_regle]
                for cle_elem in elements_regle:
                    cle_elem_regle = '%s.%s' % (cle_regle_mongo, cle_elem)
                    filtre_regle[cle_elem_regle] = elements_regle[cle_elem]
                    if isinstance(filtre_regle[cle_elem_regle], list) or isinstance(filtre_regle[cle_elem_regle], dict):
                        raise ValueError(
                            "list/dict Pas encore supporte, il va falloir faire du code recursif pour debobiner"
                        )

            self._logger.debug("Verifier si document existe: %s" % str(filtre_regle))
            document_notification = collection.find_one(filtre_regle)

            if document_notification is None:
                id_doc = self._creer_nouveau_document_(collection, {'regle': regle})
                if id_doc is not None:
                    nouveaux_documents_notification.append(id_doc)
                etape_suivante = ProcessusNotificationRecue.avertir_usager.__name__
            else:
                self._logger.debug("Document existant: %s" % str(document_notification))
                resultat = self._traiter_notification_existante(collection, document_notification, regle)
                if 'notification_requise' in resultat:
                    self._logger.debug("Notification requise, on va envoyer courriel")
                    etape_suivante = ProcessusNotificationRecue.avertir_usager.__name__

        self.set_etape_suivante(etape_suivante)

        resultat_etape = dict()
        if len(nouveaux_documents_notification) > 0:
            resultat_etape['nouveaux_documents_notification'] = nouveaux_documents_notification

        return resultat_etape

    def avertir_usager(self):
        configuration = self._controleur.configuration

        sujet = "Notification %s" % configuration.nom_millegrille
        contenu = "Nouvelle notification pour MilleGrille %s" % configuration.nom_millegrille

        self._logger.info("Transmission notifcation par courriel: %s" % contenu)

        smtp_dao = SmtpDAO(self._controleur.configuration)
        smtp_dao.envoyer_notification(sujet, contenu)

        self.set_etape_suivante()  # Termine le processus

    def _creer_nouveau_document_(self, collection, filtre):
        parametres = self.parametres

        self._logger.debug("Document n'existe pas, on l'ajoute")
        date_creation = datetime.datetime.utcnow()
        document_notification = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: Constantes.DOCUMENT_NOTIFICATION_REGLESIMPLE,
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: date_creation,
            Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: date_creation,
            TachesConstantes.LIBELLE_ETAT: TachesConstantes.ETAT_ACTIVE,
            TachesConstantes.LIBELLE_NIVEAU_NOTIFICATION: TachesConstantes.INFORMATION,
            TachesConstantes.LIBELLE_COMPTEUR: 1,
            'derniere_notification': datetime.datetime.fromtimestamp(parametres['date']),
            'valeurs': parametres['valeurs'],
            'source': parametres['source']
        }
        document_notification.update(filtre)  # Copier les cles

        resultat = collection.insert(document_notification)
        self._logger.debug("Resultat insertion %s: %s" % (str(document_notification), str(resultat)))
        if resultat is None:
            self._logger.error("Erreur insertion notification: %s" % str(document_notification))

        return resultat

    def _traiter_notification_existante(self, collection, document_notification, regle):
        parametres = self.parametres

        resultats = dict()

        filtre = {'_id': document_notification['_id']}
        operations = {
            '$set': {
                'derniere_notification': datetime.datetime.fromtimestamp(parametres['date']),
                'valeurs': parametres['valeurs']
            },
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
            '$inc': {
                TachesConstantes.LIBELLE_COMPTEUR: 1
            }
        }
        resultat_update = collection.find_one_and_update(filtre, operations)
        self._logger.debug("Resultat update %s: %s" % (str(filtre), str(resultat_update)))

        if resultat_update is None:
            raise ValueError("Update notification inexistante: %s" % str(filtre))

        # Verifier si la notification a une action / regle, ou un workflow en cours
        # Pour etat complet, on reactive. Sinon rien a faire.
        etat_precedent = resultat_update[TachesConstantes.LIBELLE_ETAT]
        etats_reactive = [TachesConstantes.ETAT_COMPLETEE, TachesConstantes.ETAT_SURVEILLE]
        if etat_precedent in etats_reactive:
            operations_set = {
                TachesConstantes.LIBELLE_ETAT: TachesConstantes.ETAT_ACTIVE
            }
            if etat_precedent == TachesConstantes.ETAT_COMPLETEE:
                # Reset le compteur, la notification etait completee.
                operations_set[TachesConstantes.LIBELLE_COMPTEUR] = 1

            # On va reouvrir la notification
            collection.update_one(filtre, {
                '$set': operations_set,
                '$unset': {
                    TachesConstantes.LIBELLE_DATE_ATTENTE_ACTION: ''
                }
            })

            # Il faudrait aussi envoyer une notification a l'usager
            resultats['notification_requise'] = True

        return resultats


class ProcessusActionUsager(ProcessusTaches):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        parametres = self.parametres
        transaction = self.charger_transaction(TachesConstantes.COLLECTION_TRANSACTIONS_NOM)
        collection_notifications = self.document_dao.get_collection(TachesConstantes.COLLECTION_DOCUMENTS_NOM)

        self._logger.debug("Parametres de l'action usager: %s" % str(parametres))
        self._logger.debug("Message de l'action usager: %s" % str(transaction))
        id_notification = transaction[TachesConstantes.LIBELLE_ID_NOTIFICATION]
        action_usager = transaction[TachesConstantes.LIBELLE_ACTION]

        filtre_notification = {'_id': ObjectId(id_notification)}
        operations_set = {
            TachesConstantes.LIBELLE_DERNIERE_ACTION: action_usager
        }
        operations_unset = dict()
        operations = {
            '$set': operations_set,
            '$currentDate': {
                TachesConstantes.LIBELLE_DATE_ACTION: True,
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True
            }
        }

        if action_usager == TachesConstantes.ACTION_VUE:
            # Marquer la notification comme vue. A moins qu'une autre notification soit recue,
            # l'usager a fait ce qu'il avait a faire au sujet de cette notification.
            operations_set[TachesConstantes.LIBELLE_ETAT] = TachesConstantes.ETAT_COMPLETEE
            operations_unset[TachesConstantes.LIBELLE_DATE_ATTENTE_ACTION] = ''

        elif action_usager == TachesConstantes.ACTION_RAPPEL:
            # Calculer la date de rappel
            date_prochaine_action = self._calculer_periode_attente(transaction)
            operations_set[TachesConstantes.LIBELLE_DATE_ATTENTE_ACTION] = date_prochaine_action
            operations_set[TachesConstantes.LIBELLE_ETAT] = TachesConstantes.ETAT_RAPPEL

        elif action_usager == TachesConstantes.ACTION_SURVEILLE:
            # Calculer la date d'arret de surveillance
            date_prochaine_action = self._calculer_periode_attente(transaction)
            operations_set[TachesConstantes.LIBELLE_DATE_ATTENTE_ACTION] = date_prochaine_action
            operations_set[TachesConstantes.LIBELLE_ETAT] = TachesConstantes.ETAT_SURVEILLE

        if len(operations_unset) > 0:
            operations['$unset'] = operations_unset
        document_notification = collection_notifications.find_one_and_update(filtre_notification, operations)

        if document_notification is None:
            raise ValueError("Document notification _id:%s n'a pas ete trouve" % id_notification)

        # Selon la valeur precedente ou association a un workflow, il pourrait falloir prendre
        # differentss actions.
        self.set_etape_suivante()  # Termine

        return {"notification_precedente": document_notification}

    def _calculer_periode_attente(self, transaction):
        """ Calcule le delai d'attente pour une action. Utilise l'estampille de la transaction pour calculer
            le delai. """

        estampille = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION][Constantes.TRANSACTION_MESSAGE_LIBELLE_ESTAMPILLE]

        attente_secondes = transaction.get(TachesConstantes.LIBELLE_DATE_ATTENTE_ACTION)
        if attente_secondes is None:
            # Defaut 24h
            attente_secondes = 24 * 60 * 60

        prochaine_action = estampille + datetime.timedelta(seconds=attente_secondes)

        return prochaine_action


class FormatteurEvenementNotification:

    TEMPLATE_NOTIFICATION = {
        "domaine": None,
        Constantes.EVENEMENT_MESSAGE_EVENEMENT: Constantes.EVENEMENT_NOTIFICATION,
        "source": {
            "_collection": None,
            "_id": None
        },
        "regles": [],
        "valeurs": {}
    }

    def __init__(self, domaine, collection):
        self._domaine = domaine
        self._collection = collection

        self._template = FormatteurEvenementNotification.TEMPLATE_NOTIFICATION.copy()
        self._template['domaine'] = domaine
        self._template['source']['_collection'] = collection

    def formatter_notification(self, source: dict, regles: list, valeurs: dict):
        notification = self._template.copy()
        notification['source'] = source
        notification['valeurs'] = valeurs
        notification['date'] = int(datetime.datetime.utcnow().timestamp())

        if isinstance(regles, list):
            notification['regles'] = regles
        else:
            notification['regles'] = [regles]

        return notification

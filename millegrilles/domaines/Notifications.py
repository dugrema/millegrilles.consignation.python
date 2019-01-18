# Module du domaine des notifications.

from millegrilles import Constantes
from millegrilles.Domaines import GestionnaireDomaine
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.MGProcessus import MGProcessus, MGProcessusTransaction
from millegrilles.dao.EmailDAO import SmtpDAO

from bson import ObjectId

import datetime


class NotificationsConstantes:

    QUEUE_SUFFIXE = 'millegrilles.domaines.Notifications'
    COLLECTION_NOM = QUEUE_SUFFIXE
    COLLECTION_DONNEES_NOM = '%s/%s' % (COLLECTION_NOM, 'donnees')

    TRANSACTION_ACTION_NOTIFICATION = 'millegrilles.domaines.Notifications.actionUsager'

    # Niveaux d'une notification
    INFORMATION = 'information'      # Plus bas niveau
    AVERTISSEMENT = 'avertissement'  # Niveau par defaut
    ALERTE = 'alerte'                # Plus haut niveau

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


class GestionnaireNotifications(GestionnaireDomaine):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._traitement_message = None

    def get_nom_queue(self):
        return NotificationsConstantes.QUEUE_SUFFIXE

    def get_nom_collection(self):
        return NotificationsConstantes.COLLECTION_NOM

    def traiter_transaction(self, ch, method, properties, body):
        self._traitement_message.callbackAvecAck(ch, method, properties, body)

    def traiter_cedule(self, message):
        indicateurs = message['indicateurs']
        self._logger.debug("Cedule GestionnaireNotifications: %s" % str(indicateurs))
        # Declencher la verification des actions sur notifications
        self.verifier_notifications_actionsdues(message)

    def traiter_notification(self, notification):
        processus = "millegrilles_domaines_Notifications:ProcessusNotificationRecue"
        self.demarrer_processus(processus, notification)

    def configurer(self):
        super().configurer()
        self._traitement_message = TraitementMessageNotification(self)

        nom_queue_notification = self.get_nom_queue()

        # Configurer la Queue pour les notifications sur RabbitMQ
        self.message_dao.channel.queue_declare(
            queue=nom_queue_notification,
            durable=True)

        self.message_dao.channel.queue_bind(
            exchange=self.configuration.exchange_evenements,
            queue=nom_queue_notification,
            routing_key='notification.#'
        )

        self.message_dao.channel.queue_bind(
            exchange=self.configuration.exchange_evenements,
            queue=nom_queue_notification,
            routing_key='destinataire.domaine.%s.#' % NotificationsConstantes.QUEUE_SUFFIXE
        )

        self.message_dao.channel.queue_bind(
            exchange=self.configuration.exchange_evenements,
            queue=nom_queue_notification,
            routing_key='ceduleur.#'
        )

    def verifier_notifications_actionsdues(self, message):
        collection_notifications = self.document_dao.get_collection(NotificationsConstantes.COLLECTION_NOM)

        filtre = {
            'date_attente_action': {'$lt': datetime.datetime.utcnow()}
        }
        curseur = collection_notifications.find(filtre)

        operations_template = {
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True
            },
            '$unset': {
                NotificationsConstantes.LIBELLE_DATE_ATTENTE_ACTION: ''
            }
        }

        for notification in curseur:
            etat_notification = notification['etat_notification']

            if etat_notification == NotificationsConstantes.ETAT_SURVEILLE:
                # La notification est completee (aucun changement depuis qu'elle est en etat de surveillance)
                operations = operations_template.copy()
                operations['$set'] = {
                    NotificationsConstantes.LIBELLE_ETAT: NotificationsConstantes.ETAT_COMPLETEE
                }
                self._logger.debug("Completer notification (surveillee): %s" % str(notification))
                collection_notifications.update_one({'_id': notification['_id']}, operations)

            elif etat_notification == NotificationsConstantes.ETAT_RAPPEL:
                # C'est l'heure du rappel. On remet la notification au mode actif.
                operations = operations_template.copy()
                operations['$set'] = {
                    NotificationsConstantes.LIBELLE_ETAT: NotificationsConstantes.ETAT_ACTIVE
                }
                self._logger.debug("Rappeler notification: %s" % str(notification))
                collection_notifications.update_one({'_id': notification['_id']}, operations)


class TraitementMessageNotification(BaseCallback):
    """ Classe helper pour traiter les transactions de la queue de notifications """

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire.contexte)
        self._gestionnaire = gestionnaire

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)

        if evenement == Constantes.EVENEMENT_CEDULEUR:
            # Ceduleur, verifier si action requise
            self._gestionnaire.traiter_cedule(message_dict)
        elif evenement == Constantes.EVENEMENT_NOTIFICATION:
            # Notification recue
            self._gestionnaire.traiter_notification(message_dict)
        elif evenement == Constantes.EVENEMENT_TRANSACTION_PERSISTEE:
            # Verifier quel processus demarrer. On match la valeur dans la routing key.
            routing_key = method.routing_key
            routing_key_sansprefixe = routing_key.replace(
                'destinataire.domaine.',
                ''
            )
            if routing_key_sansprefixe == NotificationsConstantes.TRANSACTION_ACTION_NOTIFICATION:
                processus = "millegrilles_domaines_Notifications:ProcessusActionUsagerNotification"
                self._gestionnaire.demarrer_processus(processus, message_dict)
            else:
                # Type de transaction inconnue, on lance une exception
                raise ValueError("Type de transaction inconnue: routing: %s, message: %s" % (routing_key, evenement))
        else:
            # Type d'evenement inconnu, on lance une exception
            raise ValueError("Type d'evenement inconnu: %s" % evenement)


class ProcessusNotificationRecue(MGProcessus):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        parametres = self.parametres
        self._logger.debug("Traitement notification: %s" % str(parametres))

        # Verifier si on concatene l'information a un document existant ou si on cree un nouveau document
        self.set_etape_suivante(ProcessusNotificationRecue.sauvegarder_notification.__name__)

    def sauvegarder_notification(self):
        parametres = self.parametres
        self._logger.debug("sauvegarder_notification %s" % (str(parametres)))
        collection = self.document_dao().get_collection(NotificationsConstantes.COLLECTION_NOM)

        nouveaux_documents_notification = []

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: Constantes.DOCUMENT_NOTIFICATION_REGLESIMPLE
        }

        # Extraire la source en elements distincts, sinon Mongo compare le dict() en "ordre" (aleatoire)
        for source_val in parametres['source']:
            cle = 'source.%s' % source_val
            filtre[cle] = parametres['source'][source_val]

        # L'etape suivante est determine par l'etat des notifications (nouvelles, existantes, rappel, etc.)
        etape_suivante = 'finale'
        for regle in parametres['regles']:
            self._logger.debug("Traitement document %s regle %s" % (str(parametres['source']), str(regle)))
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
            NotificationsConstantes.LIBELLE_ETAT: NotificationsConstantes.ETAT_ACTIVE,
            NotificationsConstantes.LIBELLE_NIVEAU_NOTIFICATION: NotificationsConstantes.INFORMATION,
            NotificationsConstantes.LIBELLE_COMPTEUR: 1,
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
                NotificationsConstantes.LIBELLE_COMPTEUR: 1
            }
        }
        resultat_update = collection.find_one_and_update(filtre, operations)
        self._logger.debug("Resultat update %s: %s" % (str(filtre), str(resultat_update)))

        if resultat_update is None:
            raise ValueError("Update notification inexistante: %s" % str(filtre))

        # Verifier si la notification a une action / regle, ou un workflow en cours
        # Pour etat complet, on reactive. Sinon rien a faire.
        etat_precedent = resultat_update[NotificationsConstantes.LIBELLE_ETAT]
        etats_reactive = [NotificationsConstantes.ETAT_COMPLETEE, NotificationsConstantes.ETAT_SURVEILLE]
        if etat_precedent in etats_reactive:
            operations_set = {
                NotificationsConstantes.LIBELLE_ETAT: NotificationsConstantes.ETAT_ACTIVE
            }
            if etat_precedent == NotificationsConstantes.ETAT_COMPLETEE:
                # Reset le compteur, la notification etait completee.
                operations_set[NotificationsConstantes.LIBELLE_COMPTEUR] = 1

            # On va reouvrir la notification
            collection.update_one(filtre, {
                '$set': operations_set,
                '$unset': {
                    NotificationsConstantes.LIBELLE_DATE_ATTENTE_ACTION: ''
                }
            })

            # Il faudrait aussi envoyer une notification a l'usager
            resultats['notification_requise'] = True

        return resultats


class ProcessusActionUsagerNotification(MGProcessusTransaction):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        parametres = self.parametres
        transaction = self.charger_transaction()
        collection_notifications = self.document_dao().get_collection(NotificationsConstantes.COLLECTION_NOM)

        self._logger.debug("Parametres de l'action usager: %s" % str(parametres))
        self._logger.debug("Message de l'action usager: %s" % str(transaction))
        id_notification = transaction[NotificationsConstantes.LIBELLE_ID_NOTIFICATION]
        action_usager = transaction[NotificationsConstantes.LIBELLE_ACTION]

        filtre_notification = {'_id': ObjectId(id_notification)}
        operations_set = {
            NotificationsConstantes.LIBELLE_DERNIERE_ACTION: action_usager
        }
        operations_unset = dict()
        operations = {
            '$set': operations_set,
            '$currentDate': {
                NotificationsConstantes.LIBELLE_DATE_ACTION: True,
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True
            }
        }

        if action_usager == NotificationsConstantes.ACTION_VUE:
            # Marquer la notification comme vue. A moins qu'une autre notification soit recue,
            # l'usager a fait ce qu'il avait a faire au sujet de cette notification.
            operations_set[NotificationsConstantes.LIBELLE_ETAT] = NotificationsConstantes.ETAT_COMPLETEE
            operations_unset[NotificationsConstantes.LIBELLE_DATE_ATTENTE_ACTION] = ''

        elif action_usager == NotificationsConstantes.ACTION_RAPPEL:
            # Calculer la date de rappel
            date_prochaine_action = self._calculer_periode_attente(transaction)
            operations_set[NotificationsConstantes.LIBELLE_DATE_ATTENTE_ACTION] = date_prochaine_action
            operations_set[NotificationsConstantes.LIBELLE_ETAT] = NotificationsConstantes.ETAT_RAPPEL

        elif action_usager == NotificationsConstantes.ACTION_SURVEILLE:
            # Calculer la date d'arret de surveillance
            date_prochaine_action = self._calculer_periode_attente(transaction)
            operations_set[NotificationsConstantes.LIBELLE_DATE_ATTENTE_ACTION] = date_prochaine_action
            operations_set[NotificationsConstantes.LIBELLE_ETAT] = NotificationsConstantes.ETAT_SURVEILLE

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

        attente_secondes = transaction.get(NotificationsConstantes.LIBELLE_DATE_ATTENTE_ACTION)
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

    def formatter_notification(self, id_document, regles, valeurs):
        notification = self._template.copy()
        notification['source']['_id'] = str(id_document)
        notification['valeurs'] = valeurs
        notification['date'] = int(datetime.datetime.utcnow().timestamp())

        if isinstance(regles, list):
            notification['regles'] = regles
        else:
            notification['regles'] = [regles]

        return notification

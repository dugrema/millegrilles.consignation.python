# Module avec les classes de donnees, processus et gestionnaire de sous domaine mgdomaines.appareils.SenseursPassifs
import datetime
import socket
import logging

from millegrilles import Constantes
from millegrilles.Domaines import GestionnaireDomaine, MGPProcessusDemarreur
from millegrilles.processus.MGProcessus import MGProcessus, MGProcessusTransaction
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from bson.objectid import ObjectId


# Constantes pour SenseursPassifs
class SenseursPassifsConstantes:

    COLLECTION_NOM = 'mgdomaines_appareils_SenseursPassifs'
    DOMAINE_NOM = 'mgdomaines.appareils.SenseursPassifs'

    LIBELLE_DOCUMENT_SENSEUR = 'senseur.individuel'
    LIBELLE_DOCUMENT_NOEUD = 'noeud.individuel'
    LIBELLE_DOCUMENT_GROUPE = 'groupe.senseurs'

    TRANSACTION_NOEUD = 'noeud'
    TRANSACTION_ID_SENSEUR = 'senseur'
    TRANSACTION_DATE_LECTURE = 'temps_lecture'
    TRANSACTION_LOCATION = 'location'
    TRANSACTION_VALEUR_DOMAINE = '%s.lecture' % DOMAINE_NOM
    SENSEUR_REGLES_NOTIFICATIONS = 'regles_notifications'

    EVENEMENT_MAJ_HORAIRE = 'miseajour.horaire'
    EVENEMENT_MAJ_QUOTIDIENNE = 'miseajour.quotidienne'


# Gestionnaire pour le domaine mgdomaines.appareils.SenseursPassifs.
class GestionnaireSenseursPassifs(GestionnaireDomaine):

    def __init__(self, configuration, message_dao, document_dao):
        super().__init__(configuration, message_dao, document_dao)
        self._traitement_lecture = None
        self.traiter_transaction = None   # Override de la methode super().traiter_transaction
        self._traitement_backlog_lectures = None

        self._logger = logging.getLogger("%s.GestionnaireSenseursPassifs" % __name__)

    def configurer(self):
        super().configurer()

        self._traitement_lecture = TraitementMessageLecture(self)
        self.traiter_transaction = self._traitement_lecture.callbackAvecAck   # Transfert methode

        nom_millegrille = self.configuration.nom_millegrille
        nom_queue_senseurspassifs = self.get_nom_queue()

        # Configurer la Queue pour SenseursPassifs sur RabbitMQ
        self.message_dao.channel.queue_declare(
            queue=nom_queue_senseurspassifs,
            durable=True)

        # Si la Q existe deja, la purger. Le traitement du backlog est plus efficient via load du gestionnaire.
        self.message_dao.channel.queue_purge(
            queue=nom_queue_senseurspassifs
        )

        self.message_dao.channel.queue_bind(
            exchange=self.configuration.exchange_evenements,
            queue=nom_queue_senseurspassifs,
            routing_key='%s.destinataire.domaine.mgdomaines.appareils.SenseursPassifs.#' % nom_millegrille
        )

        self.message_dao.channel.queue_bind(
            exchange=self.configuration.exchange_evenements,
            queue=nom_queue_senseurspassifs,
            routing_key='%s.ceduleur.#' % nom_millegrille
        )

    def traiter_backlog(self):
        # Il faut trouver la transaction la plus recente pour chaque noeud/senseur et relancer une transaction
        # de persistance.
        # Toutes les autres transactions non-traitees de SenseursPassifs.Lecture peuvent etre marquees comme traitees.
        traitement_backlog_lectures = TraitementBacklogLecturesSenseursPassifs(self.message_dao, self.document_dao)
        liste_transactions = traitement_backlog_lectures.run_requete_plusrecentetransactionlecture_parsenseur()
        traitement_backlog_lectures.run_requete_genererdeclencheur_parsenseur(liste_transactions)

        # Ajouter messages declencheurs pour refaire les calculs horaires et quoditiens (moyennes, extremes)
        traitement_backlog_lectures.declencher_calculs()

    def traiter_transaction(self, ch, method, properties, body):
        # Note: Cette methode est remplacee dans la configuration (self.traiter_transaction = self._traitement...)
        raise NotImplementedError("N'est pas implemente")

    def get_nom_queue(self):
        nom_millegrille = self.configuration.nom_millegrille
        nom_queue_senseurspassifs = 'mg.%s.mgdomaines.appareils.SenseursPassifs' % nom_millegrille
        return nom_queue_senseurspassifs

    ''' Traite les evenements sur cedule. '''
    def traiter_cedule(self, evenement):
        indicateurs = evenement['indicateurs']

        try:
            self.traiter_cedule_minute(evenement)
        except Exception as e:
            self._logger.exception("Erreur traitement cedule minute: %s" % str(e))

        # Verifier si les indicateurs sont pour notre timezone
        if 'heure' in indicateurs:
            try:
                self.traiter_cedule_heure(evenement)
            except Exception as he:
                self._logger.exception("Erreur traitement cedule horaire: %s" % str(he))

            # Verifier si on a l'indicateur jour pour notre TZ (pas interesse par minuit UTC)
            if 'Canada/Eastern' in indicateurs:
                if 'jour' in indicateurs:
                    try:
                        self.traiter_cedule_quotidienne(evenement)
                    except Exception as de:
                        self._logger.exception("Erreur traitement cedule quotidienne: %s" % str(de))

    def traiter_cedule_minute(self, evenement):
        pass

    def traiter_cedule_heure(self, evenement):

        # Declencher l'aggregation horaire des lectures
        domaine = '%s.MAJHoraire' % SenseursPassifsConstantes.DOMAINE_NOM
        dict_message = {
            'evenements': SenseursPassifsConstantes.EVENEMENT_MAJ_HORAIRE,
            'timestamp': datetime.datetime.utcnow().isoformat()
        }
        self.transmettre_declencheur_domaine(domaine, dict_message)

    def traiter_cedule_quotidienne(self, evenement):

        # Declencher l'aggregation quotidienne des lectures
        domaine = '%s.MAJQuotidienne' % SenseursPassifsConstantes.DOMAINE_NOM
        dict_message = {
            'evenements': SenseursPassifsConstantes.EVENEMENT_MAJ_QUOTIDIENNE,
            'timestamp': datetime.datetime.utcnow().isoformat()
        }
        self.transmettre_declencheur_domaine(domaine, dict_message)

    '''
     Transmet un message via l'echange MilleGrilles pour un domaine specifique
    
     :param domaine: Domaine millegrilles    
     '''
    def transmettre_declencheur_domaine(self, domaine, dict_message):
        nom_millegrille = self.configuration.nom_millegrille
        routing_key = '%s.destinataire.domaine.%s' % (nom_millegrille, domaine)
        self.message_dao.transmettre_message(dict_message, routing_key)


class TraitementMessageLecture(BaseCallback):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire.configuration)
        self._gestionnaire = gestionnaire

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get("evenements")

        if evenement == Constantes.EVENEMENT_TRANSACTION_PERSISTEE:
            processus = "mgdomaines_appareils_SenseursPassifs:ProcessusTransactionSenseursPassifsLecture"
            self._gestionnaire.demarrer_processus(processus, message_dict)
        elif evenement == SenseursPassifsConstantes.EVENEMENT_MAJ_HORAIRE:
            processus = "mgdomaines_appareils_SenseursPassifs:ProcessusTransactionSenseursPassifsMAJHoraire"
            self._gestionnaire.demarrer_processus(processus, message_dict)
        elif evenement == SenseursPassifsConstantes.EVENEMENT_MAJ_QUOTIDIENNE:
            processus = "mgdomaines_appareils_SenseursPassifs:ProcessusTransactionSenseursPassifsMAJQuotidienne"
            self._gestionnaire.demarrer_processus(processus, message_dict)
        elif evenement == Constantes.EVENEMENT_CEDULEUR:
            self._gestionnaire.traiter_cedule(message_dict)
        else:
            # Type d'evenement inconnu, on lance une exception
            raise ValueError("Type d'evenement inconnu: %s" % evenement)


# Classe qui produit et maintient un document de metadonnees et de lectures pour un SenseurPassif.
class ProducteurDocumentSenseurPassif:

    def __init__(self, message_dao, document_dao):
        self._message_dao = message_dao
        self._document_dao = document_dao
        self._logger = logging.getLogger("%s.ProducteurDocumentSenseurPassif" % __name__)

    ''' 
    Extrait l'information d'une lecture de senseur passif pour creer ou mettre a jour le document du senseur.
    
    :param transaction: Document de la transaction.
    :return: L'identificateur mongo _id du document de senseur qui a ete cree/modifie.
    '''
    def maj_document_senseur(self, transaction):

        # Verifier si toutes les cles sont presentes
        contenu_transaction = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_CHARGE_UTILE].copy()
        noeud = contenu_transaction[SenseursPassifsConstantes.TRANSACTION_NOEUD]
        id_appareil = contenu_transaction[SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR]
        date_lecture_epoch = contenu_transaction[SenseursPassifsConstantes.TRANSACTION_DATE_LECTURE]

        # Transformer les donnees en format natif (plus facile a utiliser plus tard)
        date_lecture = datetime.datetime.fromtimestamp(date_lecture_epoch)   # Mettre en format date standard
        contenu_transaction[SenseursPassifsConstantes.TRANSACTION_DATE_LECTURE] = date_lecture

        # Preparer le critere de selection de la lecture. Utilise pour trouver le document courant et pour l'historique
        selection = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: SenseursPassifsConstantes.LIBELLE_DOCUMENT_SENSEUR,
            SenseursPassifsConstantes.TRANSACTION_NOEUD: noeud,
            SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR: id_appareil,
            SenseursPassifsConstantes.TRANSACTION_DATE_LECTURE: {'$lt': date_lecture}
        }

        # Effectuer une maj sur la date de derniere modification.
        # Inserer les champs par defaut lors de la creation du document.
        operation = {
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
            '$setOnInsert': {Constantes.DOCUMENT_INFODOC_LIBELLE: SenseursPassifsConstantes.LIBELLE_DOCUMENT_SENSEUR}
        }

        # Si location existe, s'assurer de l'ajouter uniquement lors de l'insertion (possible de changer manuellement)
        if contenu_transaction.get(SenseursPassifsConstantes.TRANSACTION_LOCATION) is not None:
            operation['$setOnInsert'][SenseursPassifsConstantes.TRANSACTION_LOCATION] = \
                contenu_transaction.get(SenseursPassifsConstantes.TRANSACTION_LOCATION)
            del contenu_transaction[SenseursPassifsConstantes.TRANSACTION_LOCATION]

        # Mettre a jour les informations du document en copiant ceux de la transaction
        operation['$set'] = contenu_transaction

        self._logger.debug("Donnees senseur passif: selection=%s, operation=%s" % (str(selection), str(operation)))

        collection = self._document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_NOM)
        document_senseur = collection.find_one_and_update(
            filter=selection, update=operation, upsert=False, fields="_id:1")

        # Verifier si un document a ete modifie.
        if document_senseur is None:
            # Aucun document n'a ete modifie. Verifier si c'est parce qu'il n'existe pas. Sinon, le match a echoue
            # parce qu'une lecture plus recente a deja ete enregistree (c'est OK)
            selection_sansdate = selection.copy()
            del selection_sansdate[SenseursPassifsConstantes.TRANSACTION_DATE_LECTURE]
            document_senseur = collection.find_one(filter=selection_sansdate)

            if document_senseur is None:
                # Executer la meme operation avec upsert=True pour inserer un nouveau document
                resultat_update = collection.update_one(filter=selection, update=operation, upsert=True)
                document_senseur = {'_id': resultat_update.upserted_id}
                self._logger.info("_id du nouveau document: %s" % str(resultat_update.upserted_id))
            else:
                self._logger.debug("Document existant non MAJ: %s" % str(document_senseur))
                document_senseur = None
        else:
            self._logger.debug("MAJ update: %s" % str(document_senseur))

        return document_senseur

    ''' 
    Calcule les moyennes de la derniere journee pour un senseur avec donnees numeriques. 
    
    :param id_document_senseur: _id de base de donnees Mongo pour le senseur a mettre a jour.
    '''
    def calculer_aggregation_journee(self, id_document_senseur):

        senseur_objectid_key = {"_id": ObjectId(id_document_senseur)}

        # Charger l'information du senseur
        collection_senseurs = self._document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_NOM)
        document_senseur = collection_senseurs.find_one(senseur_objectid_key)

        self._logger.debug("Document charge: %s" % str(document_senseur))

        noeud = document_senseur[SenseursPassifsConstantes.TRANSACTION_NOEUD]
        no_senseur = document_senseur[SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR]

        regroupement_champs = {
            'temperature-moyenne': {'$avg': '$charge-utile.temperature'},
            'humidite-moyenne': {'$avg': '$charge-utile.humidite'},
            'pression-moyenne': {'$avg': '$charge-utile.pression'}
        }

        # Creer l'intervalle pour les donnees. Utiliser timezone pour s'assurer de remonter un nombre d'heures correct
        time_range_from, time_range_to = ProducteurDocumentSenseurPassif.calculer_daterange(hours=25)

        # Transformer en epoch (format de la transaction)
        time_range_to = int(time_range_to.timestamp())
        time_range_from = int(time_range_from.timestamp())

        self._logger.debug("Requete time range %d a %d" % (time_range_from, time_range_to))

        selection = {
            'info-transaction.domaine': SenseursPassifsConstantes.TRANSACTION_VALEUR_DOMAINE,
            'charge-utile.temps_lecture': {'$gte': time_range_from, '$lt': time_range_to},
            'charge-utile.senseur': no_senseur,
            'charge-utile.noeud': noeud
        }

        # Noter l'absence de timezone - ce n'est pas important pour le regroupement par heure.
        regroupement_periode = {
            'year': {'$year': {'$toDate': {'$multiply': ['$charge-utile.temps_lecture', 1000]}}},
            'month': {'$month': {'$toDate': {'$multiply': ['$charge-utile.temps_lecture', 1000]}}},
            'day': {'$dayOfMonth': {'$toDate': {'$multiply': ['$charge-utile.temps_lecture', 1000]}}},
            'hour': {'$hour': {'$toDate': {'$multiply': ['$charge-utile.temps_lecture', 1000]}}},
        }

        regroupement = {
            '_id': {
                'noeud': '$charge-utile.noeud',
                'senseur': '$charge-utile.senseur',
                'periode': {
                    '$dateFromParts': regroupement_periode
                }
            }
        }
        regroupement.update(regroupement_champs)

        operation = [
            {'$match': selection},
            {'$group': regroupement},
        ]

        self._logger.debug("Operation aggregation: %s" % str(operation))

        collection_transactions = self._document_dao.get_collection(Constantes.DOCUMENT_COLLECTION_TRANSACTIONS)
        resultat_curseur = collection_transactions.aggregate(operation)

        resultat = []
        for res in resultat_curseur:
            # Extraire la date, retirer le reste de la cle (redondant, ca va deja etre dans le document du senseur)
            res['periode'] = res['_id']['periode']
            del res['_id']
            resultat.append(res)
            self._logger.debug("Resultat: %s" % str(res))

            self._logger.debug("Document %s, Nombre resultats: %d" % (id_document_senseur, len(resultat)))

        # Trier les resultats en ordre decroissant de date
        resultat.sort(key=lambda res2: res2['periode'], reverse=True)
        for res in resultat:
            self._logger.debug("Resultat trie: %s" % res)

        operation_set = {'moyennes_dernier_jour': resultat}

        # Si on a des lectures de pression atmospheriques, on peut calculer la tendance
        if len(resultat) > 1:
            heure_1 = resultat[0].get('pression-moyenne')
            heure_2 = resultat[1].get('pression-moyenne')

            if heure_1 is not None and heure_2 is not None:
                # Note: il faudrait aussi verifier l'intervalle entre les lectures (aucunes lectures pendant des heures)
                tendance = '='
                if heure_1 > heure_2:
                    tendance = '+'
                elif heure_2 > heure_1:
                    tendance = '-'
                operation_set['pression_tendance'] = tendance
                self._logger.debug("Tendance pour %s / %s: %s" % (heure_1, heure_2, tendance))
            else:
                self._logger.debug("Pas de pression atmospherique %s" % id_document_senseur)

        else:
            self._logger.debug("Pas assez de donnees pour tendance: %s" % id_document_senseur)

        # Sauvegarde de l'information dans le document du senseur
        operation_update = {
            '$set': operation_set,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }
        collection_senseurs.update_one(filter=senseur_objectid_key, update=operation_update, upsert=False)

    '''
    Calcule les moyennes/min/max du dernier mois pour un senseur avec donnees numeriques.
    
    :param id_document_senseur: _id de base de donnees Mongo pour le senseur a mettre a jour.
    '''
    def calculer_aggregation_mois(self, id_document_senseur):
        senseur_objectid_key = {"_id": ObjectId(id_document_senseur)}

        # Charger l'information du senseur
        collection_senseurs = self._document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_NOM)
        document_senseur = collection_senseurs.find_one(senseur_objectid_key)

        self._logger.debug("Document charge: %s" % str(document_senseur))

        noeud = document_senseur[SenseursPassifsConstantes.TRANSACTION_NOEUD]
        no_senseur = document_senseur[SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR]

        regroupement_champs = {
            'temperature-maximum': {'$max': '$charge-utile.temperature'},
            'temperature-minimum': {'$min': '$charge-utile.temperature'},
            'humidite-maximum': {'$max': '$charge-utile.humidite'},
            'humidite-minimum': {'$min': '$charge-utile.humidite'},
            'pression-maximum': {'$max': '$charge-utile.pression'},
            'pression-minimum': {'$min': '$charge-utile.pression'}
        }

        # Creer l'intervalle pour les donnees
        time_range_from, time_range_to = ProducteurDocumentSenseurPassif.calculer_daterange(days=31)

        # Transformer en epoch (format de la transaction)
        time_range_to = int(time_range_to.timestamp())
        time_range_from = int(time_range_from.timestamp())

        selection = {
            'info-transaction.domaine': SenseursPassifsConstantes.TRANSACTION_VALEUR_DOMAINE,
            'charge-utile.temps_lecture': {'$gte': time_range_from, '$lt': time_range_to},
            'charge-utile.senseur': no_senseur,
            'charge-utile.noeud': noeud
        }

        # Noter l'utilisation de la timezone pour le regroupement. Important pour faire la separation des donnees
        # correctement.
        # Noter l'absence de timezone - ce n'est pas important pour le regroupement par heure.
        regroupement_periode = {
            'year': {'$year': {
                'date': {'$toDate': {'$multiply': ['$charge-utile.temps_lecture', 1000]}},
                'timezone': 'America/Montreal'
            }},
            'month': {'$month': {
                'date': {'$toDate': {'$multiply': ['$charge-utile.temps_lecture', 1000]}},
                'timezone': 'America/Montreal'
            }},
            'day': {'$dayOfMonth': {
                'date': {'$toDate': {'$multiply': ['$charge-utile.temps_lecture', 1000]}},
                'timezone': 'America/Montreal'
            }}
        }

        regroupement = {
            '_id': {
                'noeud': '$charge-utile.noeud',
                'senseur': '$charge-utile.senseur',
                'periode': {
                    '$dateFromParts': regroupement_periode
                }
            }
        }
        regroupement.update(regroupement_champs)

        operation = [
            {'$match': selection},
            {'$group': regroupement},
        ]

        self._logger.debug("Operation aggregation: %s" % str(operation))

        collection_transactions = self._document_dao.get_collection(Constantes.DOCUMENT_COLLECTION_TRANSACTIONS)
        resultat_curseur = collection_transactions.aggregate(operation)

        resultat = []
        for res in resultat_curseur:
            # Extraire la date, retirer le reste de la cle (redondant, ca va deja etre dans le document du senseur)
            res['periode'] = res['_id']['periode']
            del res['_id']
            resultat.append(res)

        # Trier les resultats en ordre decroissant de date
        resultat.sort(key=lambda res2: res2['periode'], reverse=True)
        for res in resultat:
            self._logger.debug("Resultat: %s" % res)

        # Sauvegarde de l'information dans le document du senseur
        operation_update = {
            '$set': {'extremes_dernier_mois': resultat},
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }
        collection_senseurs.update_one(filter=senseur_objectid_key, update=operation_update, upsert=False)

    ''' 
    Methode qui calcule un date range a partir de maintenant
    
    :param days: Nombre de jour a remonter (passe) 
    :param hours: Nombre de jour a remonter (passe)
    :return: Format datetime, from, to 
    '''
    @staticmethod
    def calculer_daterange(days=0, hours=0):
        date_reference = datetime.datetime.utcnow()
        time_range_to = datetime.datetime(date_reference.year, date_reference.month,
                                          date_reference.day,
                                          date_reference.hour)
        time_range_from = time_range_to - datetime.timedelta(days=days, hours=hours)
        time_range_from = time_range_from.replace(minute=0, second=0, microsecond=0)
        if days > 0 and hours == 0:  # Ajuster pour avoir la journee au complet
            time_range_from = time_range_from.replace(hour=0)

        return time_range_from, time_range_to

    '''
    Retourne les _id de tous les documents de senseurs. 
    '''
    def trouver_id_documents_senseurs(self):
        collection_senseurs = self._document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_NOM)

        selection = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: SenseursPassifsConstantes.LIBELLE_DOCUMENT_SENSEUR,
        }
        documents = collection_senseurs.find(filter=selection, projection={'_id': 1})

        # Extraire les documents du curseur, change de ObjectId vers un string
        document_ids = []
        for doc in documents:
            document_ids.append(str(doc['_id']))

        return document_ids


# Classe qui gere le document pour un noeud. Supporte une mise a jour incrementale des donnees.
class ProducteurDocumentNoeud:

    def __init__(self, message_dao, document_dao):
        self._message_dao = message_dao
        self._document_dao = document_dao

    '''
    Mise a jour du document de noeud par une transaction senseur passif
    
    :param id_document_senseur: _id du document du senseur.
    '''
    def maj_document_noeud_senseurpassif(self, id_document_senseur):

        collection_senseurs = self._document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_NOM)
        document_senseur = collection_senseurs.find_one(ObjectId(id_document_senseur))

        noeud = document_senseur['noeud']
        no_senseur = document_senseur[SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR]

        champs_a_copier = ['bat_mv', 'humidite', 'temperature', 'pression', 'temps_lecture', 'location']
        valeurs = {}
        for champ in champs_a_copier:
            valeur = document_senseur.get(champ)
            if valeur is not None:
                valeurs[champ] = valeur

        donnees_senseur = {
            'dict_senseurs.%s' % str(no_senseur): valeurs
        }

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: SenseursPassifsConstantes.LIBELLE_DOCUMENT_NOEUD,
            'noeud': noeud
        }

        update = {
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
            '$setOnInsert': filtre,
            '$set': donnees_senseur
        }

        collection_senseurs.update_one(filter=filtre, update=update, upsert=True)


class VerificateurNotificationsSenseursPassifs:

    def __init__(self, message_dao, regles, doc_senseur):
        self.message_dao = message_dao
        self.regles = regles
        self.doc_senseur = doc_senseur
        self._logger = logging.getLogger('%s.VerificateurNotificationsSenseursPassifs' % __name__)

    ''' Traite les regles et envoit les notifications au besoin. '''
    def traiter_regles(self):
        self._logger.debug("Traiter regles: %s" % self.regles)

        # Les regles sont dans une liste, elles doivent etre executees en ordre
        for regle in self.regles:
            self._logger.debug("Ligne regle: %s" % str(regle))
            for nom_regle in regle:
                parametres = regle[nom_regle]
                self._logger.debug("Regle: %s, parametres: %s" % (nom_regle, str(parametres)))

                try:
                    # Le nom de la regle correspond a la methode de cette classe
                    methode_regle = getattr(self, nom_regle)
                    methode_regle(parametres)
                except AttributeError as ae:
                    self._logger.error("Erreur regle de notification inconnue: %s" % nom_regle)
                except Exception as e:
                    self._logger.exception("Erreur notification")

    def transmettre_notification(self, nom_regle, message):
        sub_routing_key = 'mgdomaines.appareils.SenseursPassifs.%s' % nom_regle

        message_copy = message.copy()
        message['_id'] = str(self.doc_senseur['_id'])
        message_copy['date'] = int(datetime.datetime.utcnow().timestamp())
        message['noeud'] = self.doc_senseur['noeud']
        message['senseur'] = self.doc_senseur['senseur']
        message['regle'] = nom_regle
        message['domaine'] = sub_routing_key

        self.message_dao.transmettre_notification(message, sub_routing_key)

    ''' Regle qui envoit une notification si la valeur du senseur sort de l'intervalle. '''
    def avertissement_hors_intervalle(self, parametres):
        nom_element = parametres['element']
        valeur_min = parametres['min']
        valeur_max = parametres['max']

        valeur_courante = self.doc_senseur[nom_element]
        if not valeur_min <= valeur_courante <= valeur_max:
            self._logger.debug(
                "Valeur %s hors des limites (%f), on transmet une notification" % (nom_element, valeur_courante)
            )
            nom_regle = 'avertissement_hors_intervalle'
            message = parametres.copy()
            message['valeur'] = valeur_courante
            self.transmettre_notification(nom_regle, message)

    ''' Regle qui envoit une notification si la valeur du senseur est dans l'intervalle. '''
    def avertissement_dans_intervalle(self, parametres):
        nom_element = parametres['element']
        valeur_min = parametres['min']
        valeur_max = parametres['max']

        valeur_courante = self.doc_senseur[nom_element]
        if valeur_min <= valeur_courante <= valeur_max:
            self._logger.debug(
                "Valeur %s dans les limites (%f), on transmet une notification" % (nom_element, valeur_courante)
            )
            nom_regle = 'avertissement_dans_intervalle'
            message = parametres.copy()
            message['valeur'] = valeur_courante
            self.transmettre_notification(nom_regle, message)

    ''' Regle qui envoit une notification si la valeur du senseur est inferieure. '''
    def avertissement_inferieur(self, parametres):
        nom_element = parametres['element']
        valeur_min = parametres['min']

        valeur_courante = self.doc_senseur[nom_element]
        if valeur_courante < valeur_min:
            self._logger.debug(
                "Valeur %s sous la limite (%f), on transmet une notification" % (nom_element, valeur_courante)
            )
            nom_regle = 'avertissement_inferieur'
            message = parametres.copy()
            message['valeur'] = valeur_courante
            self.transmettre_notification(nom_regle, message)

    ''' Regle qui envoit une notification si la valeur du senseur est inferieure. '''
    def avertissement_superieur(self, parametres):
        nom_element = parametres['element']
        valeur_max = parametres['max']

        valeur_courante = self.doc_senseur[nom_element]
        if valeur_courante > valeur_max:
            self._logger.debug(
                "Valeur %s au-dessus de la limite (%f), on transmet une notification" % (nom_element, valeur_courante)
            )
            nom_regle = 'avertissement_superieur'
            message = parametres.copy()
            message['valeur'] = valeur_courante
            self.transmettre_notification(nom_regle, message)


# Processus pour enregistrer une transaction d'un senseur passif
class ProcessusTransactionSenseursPassifsLecture(MGProcessusTransaction):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self._logger = logging.getLogger('%s.ProcessusTransactionSenseursPassifsLecture' % __name__)

    ''' Enregistrer l'information de la transaction dans le document du senseur '''
    def initiale(self):
        doc_transaction = self.charger_transaction()
        self._logger.debug("Document processus: %s" % self._document_processus)
        self._logger.debug("Document transaction: %s" % doc_transaction)

        producteur_document = ProducteurDocumentSenseurPassif(self.message_dao(), self.document_dao())
        document_senseur = producteur_document.maj_document_senseur(doc_transaction)

        parametres = None
        if document_senseur and document_senseur.get("_id") is not None:
            # Preparer la prochaine etape - mettre a jour le noeud
            parametres = {"id_document_senseur": document_senseur.get("_id")}

            # Verifier s'il y a des regles de notifications pour ce senseur. Si oui, on va mettre un flag
            # pour les verifier plus tard.
            if document_senseur.get(SenseursPassifsConstantes.SENSEUR_REGLES_NOTIFICATIONS) is not None:
                parametres['verifier_notifications'] = True  # Ajout un flag au processus pour envoyer notifications

            self.set_etape_suivante(ProcessusTransactionSenseursPassifsLecture.maj_noeud.__name__)
        else:
            # Le document de senseur n'a pas ete modifie, probablement parce que les donnees n'etaient pas
            # les plus recentes. Il n'y a plus rien d'autre a faire.
            self.set_etape_suivante()   # Etape finale par defaut

        return parametres

    ''' Mettre a jour l'information du noeud pour ce senseur '''
    def maj_noeud(self):

        id_document_senseur = self._document_processus['parametres']['id_document_senseur']

        producteur_document = ProducteurDocumentNoeud(self.message_dao(), self.document_dao())
        producteur_document.maj_document_noeud_senseurpassif(id_document_senseur)

        # Verifier si on doit executer les notifications
        if self._document_processus['parametres'].get("verifier_notifications"):
            # On a des regles de notifications, c'est la prochaine etape.
            self.set_etape_suivante(ProcessusTransactionSenseursPassifsLecture.notifications.__name__)
        else:
            # Il ne reste rien a faire
            self.set_etape_suivante()  # Etape finale

    def notifications(self):
        # Identifier et transmettre les notifications
        id_document_senseur = self._document_processus['parametres']['id_document_senseur']
        collection = self._controleur.document_dao().get_collection(SenseursPassifsConstantes.COLLECTION_NOM)
        document_senseur = collection.find_one(id_document_senseur)
        regles_notification = document_senseur[SenseursPassifsConstantes.SENSEUR_REGLES_NOTIFICATIONS]

        self._logger.debug("Document senseur, regles de notification: %s" % regles_notification)
        verificateur = VerificateurNotificationsSenseursPassifs(
            self._controleur.message_dao(),
            regles_notification,
            document_senseur
        )
        verificateur.traiter_regles()

        # Terminer ce processus
        self.set_etape_suivante()


class ProcessusTransactionSenseursPassifsMAJHoraire(MGProcessus):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        # Faire liste des documents a mettre a jour
        producteur = ProducteurDocumentSenseurPassif(self.message_dao(), self.document_dao())
        liste_documents = producteur.trouver_id_documents_senseurs()

        parametres = {}
        if len(liste_documents) > 0:
            parametres['documents_senseurs'] = liste_documents
            self.set_etape_suivante(ProcessusTransactionSenseursPassifsMAJHoraire.calculer_moyennes.__name__)
        else:
            self.set_etape_suivante()   # Rien a faire, etape finale

        return parametres

    def calculer_moyennes(self):
        producteur = ProducteurDocumentSenseurPassif(self.message_dao(), self.document_dao())

        liste_documents = self._document_processus['parametres']['documents_senseurs']
        for doc_senseur in liste_documents:
            producteur.calculer_aggregation_journee(doc_senseur)

        self.set_etape_suivante()  # Rien a faire, etape finale


class ProcessusTransactionSenseursPassifsMAJQuotidienne(MGProcessus):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        # Faire liste des documents a mettre a jour
        producteur = ProducteurDocumentSenseurPassif(self.message_dao(), self.document_dao())
        liste_documents = producteur.trouver_id_documents_senseurs()

        parametres = {}
        if len(liste_documents) > 0:
            parametres['documents_senseurs'] = liste_documents
            self.set_etape_suivante(
                ProcessusTransactionSenseursPassifsMAJQuotidienne.calculer_valeurs_quotidiennes.__name__)
        else:
            self.set_etape_suivante()   # Rien a faire, etape finale

        return parametres

    def calculer_valeurs_quotidiennes(self):
        producteur = ProducteurDocumentSenseurPassif(self.message_dao(), self.document_dao())

        liste_documents = self._document_processus['parametres']['documents_senseurs']
        for doc_senseur in liste_documents:
            producteur.calculer_aggregation_mois(doc_senseur)

        self.set_etape_suivante()  # Rien a faire, etape finale


class TraitementBacklogLecturesSenseursPassifs:

    def __init__(self, message_dao, document_dao):
        self._message_dao = message_dao
        self._document_dao = document_dao
        self._logger = logging.getLogger('%s.TraitementBacklogLecturesSenseursPassifs' % __name__)

        self.demarreur_processus = MGPProcessusDemarreur(self._message_dao, self._document_dao)

    ''' 
    Identifie la transaction de lecture la plus recente pour chaque noeud/senseur. Cherche uniquement dans
    les transactions qui ne sont pas marquees comme traitees. 
    
    :returns: Liste de noeud/senseurs avec temps_lecture de la transaction la plus recente. 
    '''
    def run_requete_plusrecentetransactionlecture_parsenseur(self):
        filtre = {
            'info-transaction.domaine': SenseursPassifsConstantes.TRANSACTION_VALEUR_DOMAINE,
            'evenements.transaction_traitee': {'$exists': False}
        }

        # Trouver la request la plus recente pour chaque noeud/senseur.
        regroupement = {
            '_id': {
                'noeud': '$charge-utile.noeud',
                'senseur': '$charge-utile.senseur'
            },
            'temps_lecture': {'$max': '$charge-utile.temps_lecture'}
        }

        operation = [
            {'$match': filtre},
            {'$group': regroupement}
        ]

        self._logger.debug("Operation aggregation: %s" % str(operation))

        collection_transactions = self._document_dao.get_collection(Constantes.DOCUMENT_COLLECTION_TRANSACTIONS)
        resultat_curseur = collection_transactions.aggregate(operation)

        liste_transaction_senseurs = []
        for res in resultat_curseur:
            transaction = {
                'noeud': res['_id']['noeud'],
                'senseur': res['_id']['senseur'],
                'temps_lecture': res['temps_lecture']
            }
            liste_transaction_senseurs.append(transaction)
            self._logger.debug("Resultat: %s" % str(transaction))

        return liste_transaction_senseurs

    '''
    Identifier le _id des transaction les plus recentes pour chaque noeud/senseur et lance un message pour
    effectuer le traitement.
    
    Marque toutes les transactions anterieures comme traitees (elles n'ont aucun impact).
    
    :param liste_senseurs: Liste des senseurs avec temps_lecture de la plus recente transaction pour chaque.
    '''
    def run_requete_genererdeclencheur_parsenseur(self, liste_senseurs):

        collection_transactions = self._document_dao.get_collection(Constantes.DOCUMENT_COLLECTION_TRANSACTIONS)

        for transaction_senseur in liste_senseurs:
            filtre = {
                'charge-utile.noeud': transaction_senseur['noeud'],
                'charge-utile.senseur': transaction_senseur['senseur'],
                'charge-utile.temps_lecture': transaction_senseur['temps_lecture']
            }
            projection = {
                '_id': 1
            }
            resultat_curseur = collection_transactions.find(filter=filtre, projection=projection)

            for res in resultat_curseur:
                # Preparer un message pour declencher la transaction
                self._logger.debug("Transaction a declencher: _id = %s" % str(res['_id']))
                processus = "mgdomaines_appareils_SenseursPassifs:ProcessusTransactionSenseursPassifsLecture"
                message_dict = {
                    Constantes.TRANSACTION_MESSAGE_LIBELLE_ID_MONGO: str(res['_id']),
                    'senseur': transaction_senseur
                }
                self.demarreur_processus.demarrer_processus(processus, message_dict)

                # Marquer toutes les transaction anterieures comme traitees
                filtre['evenements.transaction_traitee'] = {'$exists': False}
                filtre['charge-utile.temps_lecture'] = {'$lt': transaction_senseur['temps_lecture']}

                operation = {
                    '$push': {'evenements.transaction_traitee': datetime.datetime.utcnow()}
                }

                collection_transactions.update_many(filter=filtre, update=operation)

    def declencher_calculs(self):
        # Declencher le calcule des moyennes horaires
        processus = "mgdomaines_appareils_SenseursPassifs:ProcessusTransactionSenseursPassifsMAJHoraire"
        self.demarreur_processus.demarrer_processus(processus, {})

        processus = "mgdomaines_appareils_SenseursPassifs:ProcessusTransactionSenseursPassifsMAJQuotidienne"
        self.demarreur_processus.demarrer_processus(processus, {})


# Processus pour mettre a jour un document de noeud suite a une transaction de senseur passif
class ProcessusMAJNoeudsSenseurPassif(MGProcessus):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)


# Producteur de transactions pour les SenseursPassifs.
class ProducteurTransactionSenseursPassifs(GenerateurTransaction):

    def __init__(self, configuration=None, message_dao=None, noeud=socket.getfqdn()):
        super().__init__(configuration, message_dao)
        self._noeud = noeud

    def transmettre_lecture_senseur(self, dict_lecture):
        # Preparer le dictionnaire a transmettre pour la lecture
        message = dict_lecture.copy()

        # Verifier valeurs qui doivent etre presentes
        if message.get(SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR) is None:
            raise ValueError("L'identificateur du senseur (%s) doit etre fourni." %
                             SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR)
        if message.get(SenseursPassifsConstantes.TRANSACTION_DATE_LECTURE) is None:
            raise ValueError("Le temps de la lecture (%s) doit etre fourni." %
                             SenseursPassifsConstantes.TRANSACTION_DATE_LECTURE)

        # Ajouter le noeud s'il n'a pas ete fourni
        if message.get(SenseursPassifsConstantes.TRANSACTION_NOEUD) is None:
            message[SenseursPassifsConstantes.TRANSACTION_NOEUD] = self._noeud

        uuid_transaction = self.soumettre_transaction(message, SenseursPassifsConstantes.TRANSACTION_VALEUR_DOMAINE)

        return uuid_transaction

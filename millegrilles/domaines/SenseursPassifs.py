# Module avec les classes de donnees, processus et gestionnaire de sous domaine millegrilles.domaines.SenseursPassifs
import datetime
import socket
import logging

from millegrilles import Constantes
from millegrilles.Domaines import GestionnaireDomaine, GestionnaireDomaineStandard
from millegrilles.Domaines import GroupeurTransactionsARegenerer, RegenerateurDeDocuments, TraitementMessageDomaineMiddleware
from millegrilles.MGProcessus import MGPProcesseur, MGProcessus, MGProcessusTransaction
from millegrilles.dao.MessageDAO import TraitementMessageDomaine
from millegrilles.domaines.Taches import FormatteurEvenementNotification, TachesConstantes
from millegrilles.transaction.GenerateurTransaction import TransactionOperations, GenerateurTransaction
from bson.objectid import ObjectId


# Constantes pour SenseursPassifs
class SenseursPassifsConstantes:

    DOMAINE_NOM = 'millegrilles.domaines.SenseursPassifs'
    COLLECTION_TRANSACTIONS_NOM = DOMAINE_NOM
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_TRANSACTIONS_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_TRANSACTIONS_NOM
    QUEUE_NOM = DOMAINE_NOM
    QUEUE_NOEUDS_NOM = '%s.noeuds' % DOMAINE_NOM
    QUEUE_INTER_NOM = '%s.inter' % DOMAINE_NOM
    QUEUE_ROUTING_CHANGEMENTS = 'noeuds.source.millegrilles_domaines_SenseursPassifs.documents'

    LIBELLE_DOCUMENT_SENSEUR = 'senseur.individuel'
    LIBELLE_DOCUMENT_NOEUD = 'noeud.individuel'
    LIBELLE_DOCUMENT_GROUPE = 'groupe.senseurs'
    LIBVAL_CONFIGURATION = 'configuration'

    TRANSACTION_NOEUD = 'noeud'
    TRANSACTION_ID_SENSEUR = 'senseur'
    TRANSACTION_DATE_LECTURE = 'temps_lecture'
    TRANSACTION_LOCATION = 'location'
    TRANSACTION_DOMAINE_LECTURE = '%s.lecture' % DOMAINE_NOM
    TRANSACTION_DOMAINE_CHANG_ATTRIBUT_SENSEUR = '%s.changementAttributSenseur' % DOMAINE_NOM
    TRANSACTION_DOMAINE_SUPPRESSION_SENSEUR = '%s.suppressionSenseur' % DOMAINE_NOM
    SENSEUR_REGLES_NOTIFICATIONS = 'regles_notifications'

    EVENEMENT_MAJ_HORAIRE = 'miseajour.horaire'
    EVENEMENT_MAJ_QUOTIDIENNE = 'miseajour.quotidienne'

    DOCUMENT_DEFAUT_CONFIGURATION = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_CONFIGURATION,
        Constantes.TRANSACTION_MESSAGE_LIBELLE_VERSION: Constantes.TRANSACTION_MESSAGE_LIBELLE_VERSION_4
    }


# Gestionnaire pour le domaine millegrilles.domaines.SenseursPassifs.
class GestionnaireSenseursPassifs(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self.__traitement_lecture = None
        self.__traitement_requetes = None
        self._traitement_backlog_lectures = None
        self.__channel = None

        self._logger = logging.getLogger("%s.GestionnaireSenseursPassifs" % __name__)

    def configurer(self):
        super().configurer()

        # Configuration des callbacks pour traiter les messages
        self.__traitement_lecture = TraitementMessageLecture(self)
        # self.__traiter_transaction = self._traitement_lecture.callbackAvecAck   # Transfert methode

        self.__traitement_requetes = TraitementMessageRequete(self)
        # self.__traiter_requete_noeud = self._traitement_requetes.callbackAvecAck  # Transfert methode
        # self.__traiter_requete_inter = self._traitement_requetes.callbackAvecAck  # Transfert methode

        # Index collection domaine
        collection_domaine = self.document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM)
        # Index noeud, _mg-libelle
        collection_domaine.create_index([
            (SenseursPassifsConstantes.TRANSACTION_NOEUD, 1),
            (Constantes.DOCUMENT_INFODOC_LIBELLE, 1)
        ])
        # Index senseur, noeud, _mg-libelle
        collection_domaine.create_index([
            (SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR, 1),
            (SenseursPassifsConstantes.TRANSACTION_NOEUD, 1),
            (Constantes.DOCUMENT_INFODOC_LIBELLE, 1),
            ('%s' % SenseursPassifsConstantes.TRANSACTION_DATE_LECTURE, 2),
        ])
        # Ajouter les index dans la collection de transactions
        collection_transactions = self.document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM)
        collection_transactions.create_index([
            ('%s' % SenseursPassifsConstantes.TRANSACTION_DATE_LECTURE, 2),
            ('%s.%s' %
             (Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION, Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE),
             1),
            (Constantes.DOCUMENT_INFODOC_LIBELLE, 1)
        ])
        collection_transactions.create_index([
            ('%s' % SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR, 1),
            ('%s' % SenseursPassifsConstantes.TRANSACTION_NOEUD, 1),
            ('%s' % SenseursPassifsConstantes.TRANSACTION_DATE_LECTURE, 2),
            ('%s.%s' %
             (Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION, Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE),
             1),
            (Constantes.DOCUMENT_INFODOC_LIBELLE, 1)
        ])

    def demarrer(self):
        super().demarrer()
        # Documents initiaux
        self.initialiser_document(
            SenseursPassifsConstantes.LIBVAL_CONFIGURATION,
            SenseursPassifsConstantes.DOCUMENT_DEFAUT_CONFIGURATION
        )
        self.demarrer_watcher_collection(
            SenseursPassifsConstantes.COLLECTION_DOCUMENTS_NOM, SenseursPassifsConstantes.QUEUE_ROUTING_CHANGEMENTS)

    def get_nom_queue(self):
        return SenseursPassifsConstantes.QUEUE_NOM

    def get_collection_transaction_nom(self):
        return SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return SenseursPassifsConstantes.COLLECTION_PROCESSUS_NOM

    def get_nom_domaine(self):
        return SenseursPassifsConstantes.DOMAINE_NOM

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
            Constantes.EVENEMENT_MESSAGE_EVENEMENT: SenseursPassifsConstantes.EVENEMENT_MAJ_HORAIRE,
            'timestamp': datetime.datetime.utcnow().isoformat()
        }
        self.transmettre_declencheur_domaine(domaine, dict_message)

    def traiter_cedule_quotidienne(self, evenement):

        # Declencher l'aggregation quotidienne des lectures
        domaine = '%s.MAJQuotidienne' % SenseursPassifsConstantes.DOMAINE_NOM
        dict_message = {
            Constantes.EVENEMENT_MESSAGE_EVENEMENT: SenseursPassifsConstantes.EVENEMENT_MAJ_QUOTIDIENNE,
            'timestamp': datetime.datetime.utcnow().isoformat()
        }
        self.transmettre_declencheur_domaine(domaine, dict_message)

    '''
     Transmet un message via l'echange MilleGrilles pour un domaine specifique
    
     :param domaine: Domaine millegrilles    
     '''

    def get_nom_collection(self):
        return SenseursPassifsConstantes.COLLECTION_DOCUMENTS_NOM

    def identifier_processus(self, domaine_transaction):
        if domaine_transaction == SenseursPassifsConstantes.TRANSACTION_DOMAINE_LECTURE:
            processus = "millegrilles_domaines_SenseursPassifs:ProcessusTransactionSenseursPassifsLecture"
        elif domaine_transaction == SenseursPassifsConstantes.TRANSACTION_DOMAINE_CHANG_ATTRIBUT_SENSEUR:
            processus = "millegrilles_domaines_SenseursPassifs:ProcessusChangementAttributSenseur"
        elif domaine_transaction == SenseursPassifsConstantes.TRANSACTION_DOMAINE_SUPPRESSION_SENSEUR:
            processus = "millegrilles_domaines_SenseursPassifs:ProcessusSupprimerSenseur"
        else:
            # Type de transaction inconnue, on lance une exception
            processus = super().identifier_processus(domaine_transaction)

        return processus

    def transmettre_declencheur_domaine(self, domaine, dict_message):
        routing_key = 'destinataire.domaine.%s' % domaine
        self.message_dao.transmettre_message(dict_message, routing_key)

    def creer_regenerateur_documents(self):
        return RegenerateurSenseursPassifs(self)

    def get_handler_transaction(self):
        return TraitementRapportsSenseursPassifs(self)


class TraitementMessageLecture(TraitementMessageDomaine):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire)

    def traiter_message(self, ch, method, properties, body):
        routing_key = method.routing_key
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)

        if routing_key.split('.')[0:2] == ['processus', 'domaine']:
            # Chaining vers le gestionnaire de processus du domaine
            self._gestionnaire.traitement_evenements.traiter_message(ch, method, properties, body)

        elif evenement == Constantes.EVENEMENT_TRANSACTION_PERSISTEE:
            # Verifier quel processus demarrer.
            routing_key_sansprefixe = routing_key.replace(
                'destinataire.domaine.',
                ''
            )
            processus = self.gestionnaire.identifier_processus(routing_key_sansprefixe)
            self._gestionnaire.demarrer_processus(processus, message_dict)
        elif evenement == SenseursPassifsConstantes.EVENEMENT_MAJ_HORAIRE:
            processus = "millegrilles_domaines_SenseursPassifs:ProcessusTransactionSenseursPassifsMAJHoraire"
            self._gestionnaire.demarrer_processus(processus, message_dict)
        elif evenement == SenseursPassifsConstantes.EVENEMENT_MAJ_QUOTIDIENNE:
            processus = "millegrilles_domaines_SenseursPassifs:ProcessusTransactionSenseursPassifsMAJQuotidienne"
            self._gestionnaire.demarrer_processus(processus, message_dict)
        elif evenement == Constantes.EVENEMENT_CEDULEUR:
            self._gestionnaire.traiter_cedule(message_dict)
        else:
            # Type d'evenement inconnu, on lance une exception
            raise ValueError("Type d'evenement inconnu: routing=%s, evenement=%s" % (routing_key, str(evenement)))


class TraitementMessageRequete(TraitementMessageDomaine):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire)
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def traiter_message(self, ch, method, properties, body):
        routing_key = method.routing_key
        exchange = method.exchange
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        enveloppe_certificat = self.gestionnaire.verificateur_transaction.verifier(message_dict)
        self._logger.debug("Certificat: %s" % str(enveloppe_certificat))
        resultats = list()
        for requete in message_dict['requetes']:
            resultat = self.executer_requete(requete)
            resultats.append(resultat)

        # Genere message reponse
        self.transmettre_reponse(message_dict, resultats, properties.reply_to, properties.correlation_id)

    def executer_requete(self, requete):
        self._logger.debug("Requete: %s" % str(requete))
        collection = self.document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_DOCUMENTS_NOM)
        filtre = requete.get('filtre')
        projection = requete.get('projection')
        sort_params = requete.get('sort')

        if projection is None:
            curseur = collection.find(filtre)
        else:
            curseur = collection.find(filtre, projection)

        if sort_params is not None:
            curseur.sort(sort_params)

        resultats = list()
        for resultat in curseur:
            resultats.append(resultat)

        self._logger.debug("Resultats: %s" % str(resultats))

        return resultats

    def transmettre_reponse(self, requete, resultats, reply_to, correlation_id):
        # enveloppe_val = generateur.soumettre_transaction(requete, 'millegrilles.domaines.Principale.creerAlerte')
        message_resultat = {
            'resultats': resultats,
            'uuid-requete': requete[Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID],
        }
        self.gestionnaire.generateur_transactions.transmettre_reponse(message_resultat, reply_to, correlation_id)


class TraitementRapportsSenseursPassifs(TraitementMessageDomaineMiddleware):

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)

        if evenement == SenseursPassifsConstantes.EVENEMENT_MAJ_HORAIRE:
            processus = "millegrilles_domaines_SenseursPassifs:ProcessusTransactionSenseursPassifsMAJHoraire"
            self._gestionnaire.demarrer_processus(processus, message_dict)
        elif evenement == SenseursPassifsConstantes.EVENEMENT_MAJ_QUOTIDIENNE:
            processus = "millegrilles_domaines_SenseursPassifs:ProcessusTransactionSenseursPassifsMAJQuotidienne"
            self._gestionnaire.demarrer_processus(processus, message_dict)
        else:
            super().traiter_message(ch, method, properties, body)


# Classe qui produit et maintient un document de metadonnees et de lectures pour un SenseurPassif.
class ProducteurDocumentSenseurPassif:

    def __init__(self, document_dao):
        self._document_dao = document_dao
        self._logger = logging.getLogger("%s.ProducteurDocumentSenseurPassif" % __name__)

    ''' 
    Extrait l'information d'une lecture de senseur passif pour creer ou mettre a jour le document du senseur.
    
    :param transaction: Document de la transaction.
    :return: L'identificateur mongo _id du document de senseur qui a ete cree/modifie.
    '''
    def maj_document_senseur(self, transaction):

        # Verifier si toutes les cles sont presentes
        operations = TransactionOperations()
        copie_transaction = operations.enlever_champsmeta(transaction)

        noeud = copie_transaction[SenseursPassifsConstantes.TRANSACTION_NOEUD]
        id_appareil = copie_transaction[SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR]
        date_lecture_epoch = copie_transaction[SenseursPassifsConstantes.TRANSACTION_DATE_LECTURE]

        # Transformer les donnees en format natif (plus facile a utiliser plus tard)
        date_lecture = datetime.datetime.fromtimestamp(date_lecture_epoch)   # Mettre en format date standard
        copie_transaction[SenseursPassifsConstantes.TRANSACTION_DATE_LECTURE] = date_lecture

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
        if copie_transaction.get(SenseursPassifsConstantes.TRANSACTION_LOCATION) is not None:
            operation['$setOnInsert'][SenseursPassifsConstantes.TRANSACTION_LOCATION] = \
                copie_transaction.get(SenseursPassifsConstantes.TRANSACTION_LOCATION)
            del copie_transaction[SenseursPassifsConstantes.TRANSACTION_LOCATION]

        # Mettre a jour les informations du document en copiant ceux de la transaction
        operation['$set'] = copie_transaction

        self._logger.debug("Donnees senseur passif: selection=%s, operation=%s" % (str(selection), str(operation)))

        collection = self._document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_DOCUMENTS_NOM)
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
        collection_senseurs = self._document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_DOCUMENTS_NOM)
        document_senseur = collection_senseurs.find_one(senseur_objectid_key)

        self._logger.debug("Document charge: %s" % str(document_senseur))

        noeud = document_senseur[SenseursPassifsConstantes.TRANSACTION_NOEUD]
        no_senseur = document_senseur[SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR]

        regroupement_champs = {
            'temperature-moyenne': {'$avg': '$temperature'},
            'humidite-moyenne': {'$avg': '$humidite'},
            'pression-moyenne': {'$avg': '$pression'}
        }

        # Creer l'intervalle pour les donnees. Utiliser timezone pour s'assurer de remonter un nombre d'heures correct
        time_range_from, time_range_to = ProducteurDocumentSenseurPassif.calculer_daterange(hours=25)

        # Transformer en epoch (format de la transaction)
        time_range_to = int(time_range_to.timestamp())
        time_range_from = int(time_range_from.timestamp())

        self._logger.debug("Requete time range %d a %d" % (time_range_from, time_range_to))

        selection = {
            'en-tete.domaine': SenseursPassifsConstantes.TRANSACTION_DOMAINE_LECTURE,
            'temps_lecture': {'$gte': time_range_from, '$lt': time_range_to},
            'senseur': no_senseur,
            'noeud': noeud
        }

        # Noter l'absence de timezone - ce n'est pas important pour le regroupement par heure.
        regroupement_periode = {
            'year': {'$year': {'$toDate': {'$multiply': ['$temps_lecture', 1000]}}},
            'month': {'$month': {'$toDate': {'$multiply': ['$temps_lecture', 1000]}}},
            'day': {'$dayOfMonth': {'$toDate': {'$multiply': ['$temps_lecture', 1000]}}},
            'hour': {'$hour': {'$toDate': {'$multiply': ['$temps_lecture', 1000]}}},
        }

        regroupement = {
            '_id': {
                'noeud': '$noeud',
                'senseur': '$senseur',
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

        collection_transactions = self._document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM)
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
        collection_senseurs = self._document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_DOCUMENTS_NOM)
        document_senseur = collection_senseurs.find_one(senseur_objectid_key)

        self._logger.debug("Document charge: %s" % str(document_senseur))

        noeud = document_senseur[SenseursPassifsConstantes.TRANSACTION_NOEUD]
        no_senseur = document_senseur[SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR]

        regroupement_champs = {
            'temperature-maximum': {'$max': '$temperature'},
            'temperature-minimum': {'$min': '$temperature'},
            'humidite-maximum': {'$max': '$humidite'},
            'humidite-minimum': {'$min': '$humidite'},
            'pression-maximum': {'$max': '$pression'},
            'pression-minimum': {'$min': '$pression'}
        }

        # Creer l'intervalle pour les donnees
        time_range_from, time_range_to = ProducteurDocumentSenseurPassif.calculer_daterange(days=31)

        # Transformer en epoch (format de la transaction)
        time_range_to = int(time_range_to.timestamp())
        time_range_from = int(time_range_from.timestamp())

        selection = {
            'en-tete.domaine': SenseursPassifsConstantes.TRANSACTION_DOMAINE_LECTURE,
            'temps_lecture': {'$gte': time_range_from, '$lt': time_range_to},
            'senseur': no_senseur,
            'noeud': noeud
        }

        # Noter l'utilisation de la timezone pour le regroupement. Important pour faire la separation des donnees
        # correctement.
        # Noter l'absence de timezone - ce n'est pas important pour le regroupement par heure.
        regroupement_periode = {
            'year': {'$year': {
                'date': {'$toDate': {'$multiply': ['$temps_lecture', 1000]}},
                'timezone': 'America/Montreal'
            }},
            'month': {'$month': {
                'date': {'$toDate': {'$multiply': ['$temps_lecture', 1000]}},
                'timezone': 'America/Montreal'
            }},
            'day': {'$dayOfMonth': {
                'date': {'$toDate': {'$multiply': ['$temps_lecture', 1000]}},
                'timezone': 'America/Montreal'
            }}
        }

        regroupement = {
            '_id': {
                'noeud': '$noeud',
                'senseur': '$senseur',
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

        collection_transactions = self._document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM)
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
        collection_senseurs = self._document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_DOCUMENTS_NOM)

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

    def __init__(self, document_dao):
        self._document_dao = document_dao

    '''
    Mise a jour du document de noeud par une transaction senseur passif
    
    :param id_document_senseur: _id du document du senseur.
    '''
    def maj_document_noeud_senseurpassif(self, id_document_senseur):

        collection_senseurs = self._document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_DOCUMENTS_NOM)
        document_senseur = collection_senseurs.find_one(ObjectId(id_document_senseur))

        noeud = document_senseur['noeud']
        no_senseur = document_senseur[SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR]

        champs_a_exclure = ['en-tete', 'moyennes_dernier_jour', 'extremes_dernier_mois']

        valeurs = document_senseur.copy()
        operations_filtre = TransactionOperations()
        valeurs = operations_filtre.enlever_champsmeta(valeurs, champs_a_exclure)

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


# class VerificateurNotificationsSenseursPassifs:
#
#     def __init__(self, message_dao, regles, doc_senseur):
#         self.message_dao = message_dao
#         self.regles = regles
#         self.doc_senseur = doc_senseur
#         self._logger = logging.getLogger('%s.VerificateurNotificationsSenseursPassifs' % __name__)
#         self._formatteur_notification = FormatteurEvenementNotification(
#             SenseursPassifsConstantes.DOMAINE_NOM,
#             SenseursPassifsConstantes.COLLECTION_DOCUMENTS_NOM
#         )
#
#     ''' Traite les regles et envoit les notifications au besoin. '''
#     def traiter_regles(self):
#         self._logger.debug("Traiter regles: %s" % self.regles)
#
#         # Les regles sont dans une liste, elles doivent etre executees en ordre
#         for regle in self.regles:
#             self._logger.debug("Ligne regle: %s" % str(regle))
#             for nom_regle in regle:
#                 parametres = regle[nom_regle]
#                 self._logger.debug("Regle: %s, parametres: %s" % (nom_regle, str(parametres)))
#
#                 try:
#                     # Le nom de la regle correspond a la methode de cette classe
#                     methode_regle = getattr(self, nom_regle)
#                     methode_regle(parametres)
#                 except AttributeError as ae:
#                     self._logger.exception("Erreur regle de notification inconnue: %s" % nom_regle)
#                 except Exception as e:
#                     self._logger.exception("Erreur notification")
#
#     def transmettre_notification(self, nom_regle, parametres, message, niveau=TachesConstantes.AVERTISSEMENT):
#         """
#         Formatte et transmet une notification.
#
#         :param nom_regle: Nom de la regle enfreinte
#         :param parametres: Parametres de la regle enfreinte (copie de la regle)
#         :param message: Valeurs du senseur au moment de l'execution de la regle.
#         :param niveau: Niveau de la notification (voir classe NotificationsConstantes)
#         """
#         notification_formattee = self._formatteur_notification.formatter_notification(
#             self.doc_senseur['_id'],
#             {nom_regle: parametres},
#             message
#         )
#         self.message_dao.transmettre_notification(notification_formattee, niveau)
#
#     ''' Regle qui envoit une notification si la valeur du senseur sort de l'intervalle. '''
#     def avertissement_hors_intervalle(self, parametres):
#         nom_element = parametres['element']
#         valeur_min = parametres['min']
#         valeur_max = parametres['max']
#
#         valeur_courante = self.doc_senseur[nom_element]
#         if not valeur_min <= valeur_courante <= valeur_max:
#             self._logger.debug(
#                 "Valeur %s hors des limites (%f), on transmet une notification" % (nom_element, valeur_courante)
#             )
#             nom_regle = 'avertissement_hors_intervalle'
#             message = {
#                 'element': nom_element,
#                 'valeur': valeur_courante
#             }
#             self.transmettre_notification(nom_regle, parametres, message)
#
#     ''' Regle qui envoit une notification si la valeur du senseur est dans l'intervalle. '''
#     def avertissement_dans_intervalle(self, parametres):
#         nom_element = parametres['element']
#         valeur_min = parametres['min']
#         valeur_max = parametres['max']
#
#         valeur_courante = self.doc_senseur[nom_element]
#         if valeur_min <= valeur_courante <= valeur_max:
#             self._logger.debug(
#                 "Valeur %s dans les limites (%f), on transmet une notification" % (nom_element, valeur_courante)
#             )
#             nom_regle = 'avertissement_dans_intervalle'
#             message = {
#                 'element': nom_element,
#                 'valeur': valeur_courante
#             }
#             self.transmettre_notification(nom_regle, parametres, message)
#
#     ''' Regle qui envoit une notification si la valeur du senseur est inferieure. '''
#     def avertissement_inferieur(self, parametres):
#         nom_element = parametres['element']
#         valeur_min = parametres['min']
#
#         valeur_courante = self.doc_senseur[nom_element]
#         if valeur_courante < valeur_min:
#             self._logger.debug(
#                 "Valeur %s sous la limite (%f), on transmet une notification" % (nom_element, valeur_courante)
#             )
#             nom_regle = 'avertissement_inferieur'
#             message = {
#                 'element': nom_element,
#                 'valeur': valeur_courante
#             }
#             self.transmettre_notification(nom_regle, parametres, message)
#
#     ''' Regle qui envoit une notification si la valeur du senseur est inferieure. '''
#     def avertissement_superieur(self, parametres):
#         nom_element = parametres['element']
#         valeur_max = parametres['max']
#
#         valeur_courante = self.doc_senseur[nom_element]
#         if valeur_courante > valeur_max:
#             self._logger.debug(
#                 "Valeur %s au-dessus de la limite (%f), on transmet une notification" % (nom_element, valeur_courante)
#             )
#             nom_regle = 'avertissement_superieur'
#             message = {
#                 'element': nom_element,
#                 'valeur': valeur_courante
#             }
#             self.transmettre_notification(nom_regle, parametres, message)


# Processus pour enregistrer une transaction d'un senseur passif
class ProcessusTransactionSenseursPassifsLecture(MGProcessusTransaction):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self._logger = logging.getLogger('%s.ProcessusTransactionSenseursPassifsLecture' % __name__)

    ''' Enregistrer l'information de la transaction dans le document du senseur '''
    def initiale(self):
        doc_transaction = self.charger_transaction(SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM)
        self._logger.debug("Document processus: %s" % self._document_processus)
        self._logger.debug("Document transaction: %s" % doc_transaction)

        producteur_document = ProducteurDocumentSenseurPassif(self._controleur.document_dao)
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

        producteur_document = ProducteurDocumentNoeud(self._controleur.document_dao)
        producteur_document.maj_document_noeud_senseurpassif(id_document_senseur)

        self.set_etape_suivante()  # Etape finale

    #     # Verifier si on doit executer les notifications
    #     if self._document_processus['parametres'].get("verifier_notifications"):
    #         # On a des regles de notifications, c'est la prochaine etape.
    #         self.set_etape_suivante(ProcessusTransactionSenseursPassifsLecture.notifications.__name__)
    #     else:
    #         # Il ne reste rien a faire
    #         self.set_etape_suivante()  # Etape finale
    #
    # def notifications(self):
    #     # Identifier et transmettre les notifications
    #     id_document_senseur = self._document_processus['parametres']['id_document_senseur']
    #     collection = self._controleur.document_dao().get_collection(SenseursPassifsConstantes.COLLECTION_DOCUMENTS_NOM)
    #     document_senseur = collection.find_one(id_document_senseur)
    #     regles_notification = document_senseur[SenseursPassifsConstantes.SENSEUR_REGLES_NOTIFICATIONS]
    #
    #     self._logger.debug("Document senseur, regles de notification: %s" % regles_notification)
    #     verificateur = VerificateurNotificationsSenseursPassifs(
    #         self._controleur.message_dao(),
    #         regles_notification,
    #         document_senseur
    #     )
    #     verificateur.traiter_regles()
    #
    #     # Terminer ce processus
    #     self.set_etape_suivante()

    def get_collection_transaction_nom(self):
        return SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return SenseursPassifsConstantes.COLLECTION_PROCESSUS_NOM


class ProcessusTransactionSenseursPassifsMAJHoraire(MGProcessus):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        # Faire liste des documents a mettre a jour
        producteur = ProducteurDocumentSenseurPassif(self._controleur.document_dao)
        liste_documents = producteur.trouver_id_documents_senseurs()

        parametres = {}
        if len(liste_documents) > 0:
            parametres['documents_senseurs'] = liste_documents
            self.set_etape_suivante(ProcessusTransactionSenseursPassifsMAJHoraire.calculer_moyennes.__name__)
        else:
            self.set_etape_suivante()   # Rien a faire, etape finale

        return parametres

    def calculer_moyennes(self):
        producteur = ProducteurDocumentSenseurPassif(self._controleur.document_dao)

        liste_documents = self._document_processus['parametres']['documents_senseurs']
        for doc_senseur in liste_documents:
            producteur.calculer_aggregation_journee(doc_senseur)

        self.set_etape_suivante()  # Rien a faire, etape finale

    def get_collection_transaction_nom(self):
        return SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return SenseursPassifsConstantes.COLLECTION_PROCESSUS_NOM


class ProcessusTransactionSenseursPassifsMAJQuotidienne(MGProcessus):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        # Faire liste des documents a mettre a jour
        producteur = ProducteurDocumentSenseurPassif(self._controleur.document_dao)
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
        producteur = ProducteurDocumentSenseurPassif(self._controleur.document_dao)

        liste_documents = self._document_processus['parametres']['documents_senseurs']
        for doc_senseur in liste_documents:
            producteur.calculer_aggregation_mois(doc_senseur)

        self.set_etape_suivante()  # Rien a faire, etape finale

    def get_collection_transaction_nom(self):
        return SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return SenseursPassifsConstantes.COLLECTION_PROCESSUS_NOM


class TraitementBacklogLecturesSenseursPassifs:

    def __init__(self, document_dao, demarreur_processus):
        self._document_dao = document_dao
        self._logger = logging.getLogger('%s.TraitementBacklogLecturesSenseursPassifs' % __name__)

        # self.demarreur_processus = MGPProcessusDemarreur(self._contexte)
        self.demarreur_processus = demarreur_processus

    ''' 
    Identifie la transaction de lecture la plus recente pour chaque noeud/senseur. Cherche uniquement dans
    les transactions qui ne sont pas marquees comme traitees. 
    
    :returns: Liste de noeud/senseurs avec temps_lecture de la transaction la plus recente. 
    '''
    def run_requete_plusrecentetransactionlecture_parsenseur(self):
        filtre = {
            'info-transaction.domaine': SenseursPassifsConstantes.TRANSACTION_DOMAINE_LECTURE,
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

        collection_transactions = self._document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM)
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

        collection_transactions = self._document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM)

        for transaction_senseur in liste_senseurs:
            filtre = {
                'info-transaction.domaine': SenseursPassifsConstantes.TRANSACTION_DOMAINE_LECTURE,
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
                processus = "millegrilles_domaines_SenseursPassifs:ProcessusTransactionSenseursPassifsLecture"
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
        """ Declencher le calcul des moyennes horaires """

        processus = "millegrilles_domaines_SenseursPassifs:ProcessusTransactionSenseursPassifsMAJHoraire"
        self.demarreur_processus.demarrer_processus(processus, {})

        processus = "millegrilles_domaines_SenseursPassifs:ProcessusTransactionSenseursPassifsMAJQuotidienne"
        self.demarreur_processus.demarrer_processus(processus, {})

    def declencher_maj_manuelle(self):
        """ Re-declencher les transactions de mise a jour manuelles qui n'ont pas ete executees. """

        collection_transactions = self._document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM)
        filtre = {
            'info-transaction.domaine': SenseursPassifsConstantes.TRANSACTION_DOMAINE_CHANG_ATTRIBUT_SENSEUR,
            'evenements.transaction_traitee': {'$exists': False}
        }
        projection = {
            '_id': 1,
            'info-transaction.uuid-transaction': 1
        }
        tri = [
            ('info-transaction.estampille', 1)
        ]

        curseur = collection_transactions.find(filtre, projection, sort=tri)

        processus = "millegrilles_domaines_SenseursPassifs:ProcessusMajManuelle"
        for transaction in curseur:
            transaction['_id-transaction'] = transaction['_id']  # Copier le _id pour que le processus ait la bonne cle
            self._logger.debug("Redemarrer processus pour ProcessusMajManuelle _id:%s" % transaction['_id'])
            self.demarreur_processus.demarrer_processus(processus, transaction)


# Processus pour mettre a jour un document de noeud suite a une transaction de senseur passif
class ProcessusMAJSenseurPassif(MGProcessusTransaction):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def modifier_noeud(self):
        """ Appliquer les modifications au noeud """
        id_document_senseur = self._document_processus['parametres']['id_document_senseur']
        producteur_document = ProducteurDocumentNoeud(self._controleur.document_dao)
        producteur_document.maj_document_noeud_senseurpassif(id_document_senseur)

        self.set_etape_suivante()  # Termine

    def get_collection_transaction_nom(self):
        return SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return SenseursPassifsConstantes.COLLECTION_PROCESSUS_NOM


class ProcessusChangementAttributSenseur(ProcessusMAJSenseurPassif):
    """
    Processus de modification d'un attribut de senseur par un usager
    Format de la transaction:
    {
        senseur: NO_SENSEUR,
        noeud: NOM_NOEUD,
        attribut1: valeur1,
        attribut2: valeur2,
        ...
        attributN: valeurN,
    }
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        """ Mettre a jour le document de senseur """

        document_transaction = self.charger_transaction(SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM)

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: SenseursPassifsConstantes.LIBELLE_DOCUMENT_SENSEUR,
            "senseur": document_transaction['senseur'],
            "noeud": document_transaction['noeud'],
        }
        valeurs_modifiees = dict()
        for cle in document_transaction:
            if not cle.startswith('_') and cle not in ['senseur', 'noeud']:
                valeurs_modifiees[cle] = document_transaction[cle]
        valeurs = {
            '$set': valeurs_modifiees,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }

        self._logger.debug("Application des changements de la transaction: %s = %s" % (str(filtre), str(valeurs)))
        collection_transactions = self.document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_DOCUMENTS_NOM)
        document = collection_transactions.find_one_and_update(filtre, valeurs)

        if document is None:
            message_erreur = "Mise a jour echoue sur document SenseurPassif %s" % str(filtre)
            self._logger.error(message_erreur)
            raise AssertionError(message_erreur)

        self.set_etape_suivante(ProcessusMajManuelle.modifier_noeud.__name__)  # Mettre a jour le noeud

        # Retourner l'id du document pour mettre a jour le noeud
        return {'id_document_senseur': document['_id']}


class ProcessusSupprimerSenseur(ProcessusMAJSenseurPassif):
    """
    Processus de suppression d'une liste de senseur d'un meme noeud.
    Format de la transaction:
    {
        noeud: NOM_NOEUD,
        senseurs: [NO_SENSEUR1, NO_SENSEUR2, ... NO_SENSEURN]
    }
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        """ Mettre a jour le document de senseur """

        document_transaction = self.charger_transaction(SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM)

        liste_cles = dict()
        for senseur in document_transaction['senseurs']:
            senseur_cle = 'dict_senseurs.%s' % senseur
            liste_cles[senseur_cle] = 1

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: SenseursPassifsConstantes.LIBELLE_DOCUMENT_NOEUD,
            "noeud": document_transaction['noeud'],
        }
        valeurs = {
            '$unset': liste_cles,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }

        self._logger.debug("Application des changements de la transaction: %s = %s" % (str(filtre), str(valeurs)))
        collection_transactions = self.document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_DOCUMENTS_NOM)
        document = collection_transactions.find_one_and_update(filtre, valeurs)

        if document is None:
            message_erreur = "Mise a jour echoue sur document SenseurPassif %s" % str(filtre)
            self._logger.error(message_erreur)
            raise AssertionError(message_erreur)

        self.set_etape_suivante()  # Termine

        # Retourner l'id du document pour mettre a jour le noeud
        return {'id_document_noeud': document['_id']}


class ProcessusMajManuelle(ProcessusMAJSenseurPassif):
    """ Processus de modification d'un senseur par un usager """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        """ Mettre a jour le document de senseur """

        document_transaction = self.charger_transaction(SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM)

        filtre = document_transaction['filtre']
        valeurs = {
            '$set': document_transaction['set'],
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }

        self._logger.debug("Application des changements de la transaction: %s = %s" % (str(filtre), str(valeurs)))
        collection_transactions = self.document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_DOCUMENTS_NOM)
        document = collection_transactions.find_one_and_update(filtre, valeurs)

        if document is None:
            message_erreur = "Mise a jour echoue sur document SenseurPassif %s" % str(filtre)
            self._logger.error(message_erreur)
            raise AssertionError(message_erreur)

        self.set_etape_suivante(ProcessusMajManuelle.modifier_noeud.__name__)  # Mettre a jour le noeud

        # Retourner l'id du document pour mettre a jour le noeud
        return {'id_document_senseur': document['_id']}


class ProducteurTransactionSenseursPassifs(GenerateurTransaction):
    """ Producteur de transactions pour les SenseursPassifs. """

    def __init__(self, contexte, noeud=socket.getfqdn()):
        super().__init__(contexte)
        self._noeud = noeud
        self._logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

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

        self._logger.debug("Message a transmettre: %s" % str(message))

        uuid_transaction = self.soumettre_transaction(message, SenseursPassifsConstantes.TRANSACTION_DOMAINE_LECTURE)

        return uuid_transaction


class RegenerateurSenseursPassifs(RegenerateurDeDocuments):
    """
    Efface et regenere les documents de SenseursPassifs. Optimise pour utiliser lectures recentes.
    """

    def creer_generateur_transactions(self):
        return GroupeurRegenererTransactionsSenseursPassif(self._gestionnaire_domaine)


class GroupeurRegenererTransactionsSenseursPassif(GroupeurTransactionsARegenerer):
    """
    Classe qui permet de grouper les transactions d'un domaine pour regenerer les documents.
    Groupe toutes les transactions dans un seul groupe, en ordre de transaction_traitee.
    """

    def __init__(self, gestionnaire_domaine: GestionnaireDomaine):
        super().__init__(gestionnaire_domaine)

        self.__complete = False

        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def __preparer_curseur_lectures(self):
        nom_millegrille = self.gestionnaire.configuration.nom_millegrille

        match_query = {
            '_evenements.transaction_complete': True,
            'en-tete.domaine': 'millegrilles.domaines.SenseursPassifs.lecture',
            '_evenements.%s.transaction_traitee' % nom_millegrille: {'$exists': True},
            'temps_lecture': {'$exists': True},
        }
        group_query = {
            '_id': {
                'noeud': '$noeud',
                'senseur': '$senseur'
            },
            'temps_lecture': {'$max': '$temps_lecture'}
        }

        collection_transaction_nom = self.gestionnaire.get_collection_transaction_nom()
        collection_transaction = self.gestionnaire.document_dao.get_collection(collection_transaction_nom)
        curseur = collection_transaction.aggregate([
            {'$match': match_query},
            {'$group': group_query}
        ])

        return curseur

    def __preparer_curseur_autres(self):
        nom_millegrille = self.gestionnaire.configuration.nom_millegrille

        match_query = {
            '_evenements.transaction_complete': True,
            '_evenements.%s.transaction_traitee' % nom_millegrille: {'$exists': True},
            'en-tete.domaine': {'$not': {'$in': ['millegrilles.domaines.SenseursPassifs.lecture']}}
        }
        sort_query = [
            ('_evenements.%s.transaction_traitee' % nom_millegrille, 1)
        ]

        collection_transaction_nom = self.gestionnaire.get_collection_transaction_nom()
        collection_transaction = self.gestionnaire.document_dao.get_collection(collection_transaction_nom)

        return collection_transaction.find(match_query).sort(sort_query)

    def __charger_lecture(self, senseur_lecture):
        collection_transaction_nom = self.gestionnaire.get_collection_transaction_nom()
        collection_transaction = self.gestionnaire.document_dao.get_collection(collection_transaction_nom)

        senseur_dict = senseur_lecture['_id']
        senseur_dict['temps_lecture'] = senseur_lecture['temps_lecture']
        transaction = collection_transaction.find_one(senseur_dict)

        return transaction

    def __iter__(self):
        return self.__next__()

    def __next__(self):
        """
        Retourne un curseur Mongo avec les transactions a executer en ordre.
        :return:
        """
        if self.__complete:
            raise StopIteration()

        curseur_aggregation = self.__preparer_curseur_lectures()
        for senseur_lecture in curseur_aggregation:
            transaction = self.__charger_lecture(senseur_lecture)
            yield transaction

        curseur_autres = self.__preparer_curseur_autres()
        for transaction in curseur_autres:
            yield transaction

        self.__complete = True

        return

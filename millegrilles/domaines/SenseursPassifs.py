# Module avec les classes de donnees, processus et gestionnaire de sous domaine millegrilles.domaines.SenseursPassifs
import datetime
import logging

from millegrilles import Constantes
from millegrilles.Constantes import SenseursPassifsConstantes
from millegrilles.Domaines import GestionnaireDomaine, GestionnaireDomaineStandard
from millegrilles.Domaines import GroupeurTransactionsARegenerer, RegenerateurDeDocuments
from millegrilles.MGProcessus import MGProcessusTransaction, MGProcessus
from millegrilles.dao.MessageDAO import TraitementMessageDomaine
from millegrilles.transaction.GenerateurTransaction import TransactionOperations
from bson.objectid import ObjectId


# Gestionnaire pour le domaine millegrilles.domaines.SenseursPassifs.
class GestionnaireSenseursPassifs(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self.__traitement_lecture = None
        self.__traitement_requetes = None
        self._traitement_backlog_lectures = None

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
        collection_domaine.create_index(
            [
                (SenseursPassifsConstantes.TRANSACTION_NOEUD, 1),
                (Constantes.DOCUMENT_INFODOC_LIBELLE, 1)
            ],
            name='noeud-mglibelle'
        )
        # Index senseur, noeud, _mg-libelle
        collection_domaine.create_index(
            [
                (SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR, 1),
                (SenseursPassifsConstantes.TRANSACTION_NOEUD, 1),
                (Constantes.DOCUMENT_INFODOC_LIBELLE, 1),
                ('%s' % SenseursPassifsConstantes.TRANSACTION_DATE_LECTURE, 2),
            ],
            name='senseur-noeud-mglibelle'
        )
        # Ajouter les index dans la collection de transactions
        collection_transactions = self.document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM)
        collection_transactions.create_index(
            [
                ('%s' % SenseursPassifsConstantes.TRANSACTION_DATE_LECTURE, 2),
                ('%s.%s' %
                 (Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION, Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE),
                 1),
                (Constantes.DOCUMENT_INFODOC_LIBELLE, 1)
            ],
            name='date-domaine-mglibelle'
        )
        collection_transactions.create_index(
            [
                ('%s' % SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR, 1),
                ('%s' % SenseursPassifsConstantes.TRANSACTION_NOEUD, 1),
                ('%s' % SenseursPassifsConstantes.TRANSACTION_DATE_LECTURE, 2),
                ('%s.%s' %
                 (Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION, Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE),
                 1),
                (Constantes.DOCUMENT_INFODOC_LIBELLE, 1)
            ],
            name='senseur-noeud-date-domaine-mglibelle'
        )

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
        elif domaine_transaction == SenseursPassifsConstantes.EVENEMENT_MAJ_HORAIRE:
            processus = "millegrilles_domaines_SenseursPassifs:ProcessusMajFenetreHoraireRapport"
        elif domaine_transaction == SenseursPassifsConstantes.EVENEMENT_MAJ_QUOTIDIENNE:
            processus = "millegrilles_domaines_SenseursPassifs:ProcessusMajFenetreQuotidienneRapport"
        else:
            # Type de transaction inconnue, on lance une exception
            processus = super().identifier_processus(domaine_transaction)

        return processus

    def transmettre_declencheur_domaine(self, domaine, dict_message):
        routing_key = 'destinataire.domaine.%s' % domaine
        self.message_dao.transmettre_message(dict_message, routing_key)

    def creer_regenerateur_documents(self):
        return RegenerateurSenseursPassifs(self)

    # def get_handler_transaction(self):
    #     return TraitementRapportsSenseursPassifs(self)

    def regenerer_rapports_sur_cedule(self):
        """ Permet de regenerer les documents de rapports sur cedule lors du demarrage du domaine """
        self.demarrer_processus('millegrilles_domaines_SenseursPassifs:ProcessusRegenererFenetresRapport', {})


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
            processus = "millegrilles_domaines_SenseursPassifs:ProcessusMajFenetreHoraireRapport"
            self._gestionnaire.demarrer_processus(processus, message_dict)
        elif evenement == SenseursPassifsConstantes.EVENEMENT_MAJ_QUOTIDIENNE:
            processus = "millegrilles_domaines_SenseursPassifs:ProcessusMajFenetreQuotidienneRapport"
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


# Classe qui produit et maintient un document de metadonnees et de lectures pour un SenseurPassif.
class ProducteurDocumentSenseurPassif:

    def __init__(self, document_dao):
        self._document_dao = document_dao
        self._logger = logging.getLogger("%s.ProducteurDocumentSenseurPassif" % __name__)

        self._regroupement_elem_numeriques = [
            'temperature', 'humidite', 'pression', 'millivolt', 'reserve'
        ]
        self._accumulateurs = ['max', 'min', 'avg']

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
        date_lecture = datetime.datetime.utcfromtimestamp(date_lecture_epoch)  # Mettre en format date standard
        copie_transaction[SenseursPassifsConstantes.TRANSACTION_DATE_LECTURE] = date_lecture

        # Extraire les donnees de la liste "senseurs" pour les utiliser plus facilement
        senseurs = copie_transaction.get('senseurs')

        if senseurs is not None:
            for senseur in copie_transaction.get('senseurs'):
                if senseur.get('type') == 'batterie':
                    copie_transaction['bat_mv'] = senseur['millivolt']
                    copie_transaction['bat_reserve'] = senseur['reserve']
                else:
                    if senseur.get('type') == 'onewire/temperature':
                        # 1W: copier avec l'adresse unique du senseur comme cle d'affichage
                        cle = 'affichage.1W%s' % senseur['adresse']
                    else:
                        # Pour les types sans adresses uniques, on fait juste copier le type
                        cle = 'affichage.%s' % senseur['type']

                    for elem, valeur in senseur.items():
                        if elem not in ['type', 'adresse'] and valeur is not None:
                            cle_elem = '%s.%s' % (cle, elem)
                            copie_transaction[cle_elem] = valeur

                            cle_date = '%s.timestamp' % (cle)
                            copie_transaction[cle_date] = date_lecture

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
            filter=selection, update=operation, upsert=False, fields={"_id": 1})

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

    def _requete_aggregation_senseurs(
            self,
            uuid_senseur: str = None,
            niveau_regroupement: str = 'hour',
            temps_fin_rapport: datetime.datetime = datetime.datetime.utcnow(),
            range_rapport: datetime.timedelta = datetime.timedelta(days=7)
    ):
        """
        Effectue une requete d'aggregation des transactions de senseurs passifs.
        :param uuid_senseur: Senseur a utiliser (None == tous)
        :param niveau_regroupement: hour ou day
        :param temps_fin_rapport: datetime de fin du rapport. Defaut = now
        :param range_rapport: timedelta qui represente l'intervalle du rapport
        :return: Un curseur d'aggregation
        """
        collection_transactions = self._document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM)

        # LIBELLE_DOCUMENT_SENSEUR_RAPPORT_HORAIRE
        temps_fin_rapport.replace(minute=0, second=0)  # Debut de l'heure courante est la fin du rapport
        if niveau_regroupement == 'day':
            temps_fin_rapport.replace(hour=0)  # Minuit

        temps_debut_rapport = temps_fin_rapport - range_rapport

        filtre_rapport = {
            SenseursPassifsConstantes.TRANSACTION_DATE_LECTURE: {
                '$gte': temps_debut_rapport.timestamp(),
                '$lt': temps_fin_rapport.timestamp(),
            },
            '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE, Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE): SenseursPassifsConstantes.TRANSACTION_DOMAINE_LECTURE,
        }
        if uuid_senseur is not None:
            filtre_rapport[SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR] = uuid_senseur

        regroupement_periode = {
            'year': {'$year': '$_evenements._estampille'},
            'month': {'$month': '$_evenements._estampille'},
        }
        if niveau_regroupement == 'day':
            regroupement_periode['day'] = {'$dayOfMonth': '$_evenements._estampille'}
        elif niveau_regroupement == 'hour':
            regroupement_periode['day'] = {'$dayOfMonth': '$_evenements._estampille'}
            regroupement_periode['hour'] = {'$hour': '$_evenements._estampille'}

        regroupement = {
            '_id': {
                'uuid_senseur': '$uuid_senseur',
                'appareil_type': '$senseurs.type',
                'appareil_adresse': '$senseurs.adresse',
                'timestamp': {
                    '$dateFromParts': regroupement_periode
                },
            },
        }

        for elem_regroupement in self._regroupement_elem_numeriques:
            for accumulateur in self._accumulateurs:
                key = '%s_%s' % (elem_regroupement, accumulateur)
                regroupement[key] = {'$%s' % accumulateur: '$senseurs.%s' % elem_regroupement}

        operation = [
            {'$match': filtre_rapport},
            {'$unwind': '$senseurs'},
            {'$group': regroupement},
        ]

        # S'assurer d'utiliser l'index sur l'estampille - permet au match de filtrer par date
        hint = {'_evenements._estampille': -1}

        resultat = collection_transactions.aggregate(operation, hint=hint)

        return resultat

    def parse_resultat_aggregation(self, curseur):

        # Key=uuid_senseur, Value=[{appareil_type, appareil_adresse, timestamp, accums...}, ...]
        resultats_par_senseur = dict()

        for ligne_rapport in curseur:
            # self._logger.info(str(ligne_rapport))
            resultats_appareil = resultats_par_senseur.get(ligne_rapport['_id']['uuid_senseur'])
            if resultats_appareil is None:
                resultats_appareil = dict()
                resultats_par_senseur[ligne_rapport['_id']['uuid_senseur']] = resultats_appareil

            # Reorganiser valeurs pour insertion dans document de rapport
            cle_appareil = ligne_rapport['_id']['appareil_type']
            if cle_appareil == 'onewire/temperature':
                adresse = ligne_rapport['_id'].get('appareil_adresse')
                cle_appareil = '1W%s' % adresse

            liste_valeurs = resultats_appareil.get(cle_appareil)
            if liste_valeurs is None:
                liste_valeurs = list()
                resultats_appareil[cle_appareil] = liste_valeurs

            ligne_formattee = dict()
            liste_valeurs.append(ligne_formattee)

            ligne_formattee['timestamp'] = ligne_rapport['_id']['timestamp']

            for elem_regroupement in self._regroupement_elem_numeriques:
                for accumulateur in self._accumulateurs:
                    key = '%s_%s' % (elem_regroupement, accumulateur)
                    valeur = ligne_rapport[key]
                    if valeur is not None:
                        ligne_formattee[key] = valeur

        return resultats_par_senseur

    def remplacer_resultats_rapport(self, resultats: dict, infodoc_libelle, nombre_resultats_limite: int = 366):

        collection_documents = self._document_dao.get_collection(
            SenseursPassifsConstantes.COLLECTION_DOCUMENTS_NOM)

        for uuid_senseur, appareils in resultats.items():
            self._logger.debug("Inserer resultats dans document %s" % uuid_senseur)
            set_operation = dict()
            for appareil, valeurs in appareils.items():
                # Ajouter les valeurs en ordre croissant de timestamp.
                valeurs = sorted(valeurs, key=lambda valeur: valeur['timestamp'])

                # Garder les "nombre_resultats_limite" plus recents
                valeurs = valeurs[- nombre_resultats_limite:]

                set_operation['appareils.%s' % appareil] = valeurs

            self._logger.debug('Operation push: %s' % str(set_operation))

            filtre = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: infodoc_libelle,
                SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR: uuid_senseur,
            }

            set_on_insert = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: infodoc_libelle,
                Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
                SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR: uuid_senseur,
            }

            operations = {
                '$setOnInsert': set_on_insert,
                '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
                '$set': set_operation,
            }

            collection_documents.update_one(filter=filtre, update=operations, upsert=True)

    def inserer_resultats_rapport(self, resultats: dict, infodoc_libelle, nombre_resultats_limite: int = 366):

        collection_documents = self._document_dao.get_collection(
            SenseursPassifsConstantes.COLLECTION_DOCUMENTS_NOM)

        for uuid_senseur, appareils in resultats.items():
            self._logger.info("Inserer resultats dans document %s" % uuid_senseur)
            push_operation = dict()
            for appareil, valeurs in appareils.items():
                # Ajouter les valeurs en ordre croissant de timestamp.
                # Garder les "nombre_resultats_limite" plus recents (~1 semaine)
                push_operation['appareils.%s' % appareil] = {
                    '$each': valeurs,
                    '$sort': {SenseursPassifsConstantes.TRANSACTION_DATE_LECTURE: 1},
                    '$slice': - nombre_resultats_limite,
                }

            self._logger.info('Operation push: %s' % str(push_operation))

            filtre = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: infodoc_libelle,
                SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR: uuid_senseur,
            }

            set_on_insert = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: infodoc_libelle,
                Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
                SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR: uuid_senseur,
            }

            operations = {
                '$setOnInsert': set_on_insert,
                '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
                '$push': push_operation
            }

            collection_documents.update_one(filter=filtre, update=operations, upsert=True)

    def generer_fenetre_horaire(self):
        curseur_aggregation = self._requete_aggregation_senseurs(
            niveau_regroupement='hour',
            range_rapport=datetime.timedelta(days=7)
        )

        resultats = self.parse_resultat_aggregation(curseur_aggregation)

        self.remplacer_resultats_rapport(
            resultats,
            SenseursPassifsConstantes.LIBELLE_DOCUMENT_SENSEUR_RAPPORT_SEMAINE,
            nombre_resultats_limite=170
        )

    def ajouter_derniereheure_fenetre_horaire(self):
        curseur_aggregation = self._requete_aggregation_senseurs(
            niveau_regroupement='hour',
            range_rapport=datetime.timedelta(hours=1)
        )

        resultats = self.parse_resultat_aggregation(curseur_aggregation)

        self.inserer_resultats_rapport(
            resultats,
            SenseursPassifsConstantes.LIBELLE_DOCUMENT_SENSEUR_RAPPORT_SEMAINE,
            nombre_resultats_limite=170
        )

    def generer_fenetre_quotidienne(self):
        curseur_aggregation = self._requete_aggregation_senseurs(
            niveau_regroupement='day',
            range_rapport=datetime.timedelta(days=366)
        )

        resultats = self.parse_resultat_aggregation(curseur_aggregation)

        self.remplacer_resultats_rapport(
            resultats,
            SenseursPassifsConstantes.LIBELLE_DOCUMENT_SENSEUR_RAPPORT_ANNEE,
            nombre_resultats_limite=366
        )

    def ajouter_dernierjour_fenetre_quotidienne(self):
        curseur_aggregation = self._requete_aggregation_senseurs(
            niveau_regroupement='day',
            range_rapport=datetime.timedelta(days=1)
        )

        resultats = self.parse_resultat_aggregation(curseur_aggregation)

        self.inserer_resultats_rapport(
            resultats,
            SenseursPassifsConstantes.LIBELLE_DOCUMENT_SENSEUR_RAPPORT_ANNEE,
            nombre_resultats_limite=366
        )


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

    def get_collection_transaction_nom(self):
        return SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return SenseursPassifsConstantes.COLLECTION_PROCESSUS_NOM


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
            "uuid_senseur": document_transaction['uuid_senseur'],
        }
        valeurs_modifiees = dict()
        for cle in document_transaction:
            if not cle.startswith('_') and cle not in ['uuid_senseur']:
                # Remplacer les / en . (probleme de sauvegarde de la transaction originale si on utilise des .
                cleModifiee = cle.replace('/', '.').replace("'", "")
                valeurs_modifiees[cleModifiee] = document_transaction[cle]

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


class ProcessusGenererRapport(ProcessusMAJSenseurPassif):
    """ Processus de calcul d'un rapport pour les senseurs """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        """ Mettre a jour le document de senseur """

        document_transaction = self.charger_transaction(SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM)

        uuid_senseur = document_transaction.get(SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR)

        # Granularite: quoditien, horaire
        granularite = document_transaction.get('granularite')

        # Si True, le rapport est sauvegarde sous forme de transaction.
        date_debut = document_transaction.get('date_debut')
        date_fin = document_transaction.get('date_fin')

        self.set_etape_suivante()


class ProcessusRegenererFenetresRapport(MGProcessus):
    """ Processus de calcul des fenetres d'aggregation horaire pour les senseurs. Ajoute la derniere heure. """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        """ Regenerer les rapports de fenetre mobile horaire """

        producteur = ProducteurDocumentSenseurPassif(self.document_dao)
        producteur.generer_fenetre_horaire()

        self.set_etape_suivante(ProcessusRegenererFenetresRapport.rapport_annuel.__name__)  # Termine

    def rapport_annuel(self):
        """ Regenerer les rapports de fenetre mobile quotidienne """

        producteur = ProducteurDocumentSenseurPassif(self.document_dao)
        producteur.generer_fenetre_quotidienne()

        self.set_etape_suivante()  # Termine


class ProcessusMajFenetreQuotidienneRapport(MGProcessus):
    """ Processus de calcul des fenetres d'aggregation quotidienne pour les senseurs. Ajoute le dernier jour. """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        """ Mettre a jour les documents de senseurs """

        producteur = ProducteurDocumentSenseurPassif(self.document_dao)
        producteur.ajouter_dernierjour_fenetre_quotidienne()

        self.set_etape_suivante()  # Termine


class ProcessusMajFenetreHoraireRapport(MGProcessus):
    """ Processus de calcul des fenetres d'aggregation horaire pour les senseurs. Ajoute la derniere heure. """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        """ Mettre a jour les documents de senseurs """

        producteur = ProducteurDocumentSenseurPassif(self.document_dao)
        producteur.ajouter_derniereheure_fenetre_horaire()

        self.set_etape_suivante()  # Termine


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
        idmg = self.gestionnaire.configuration.idmg

        match_query = {
            '_evenements.transaction_complete': True,
            'en-tete.domaine': 'millegrilles.domaines.SenseursPassifs.lecture',
            '_evenements.%s.transaction_traitee' % idmg: {'$exists': True},
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
        idmg = self.gestionnaire.configuration.idmg

        match_query = {
            '_evenements.transaction_complete': True,
            '_evenements.%s.transaction_traitee' % idmg: {'$exists': True},
            'en-tete.domaine': {'$not': {'$in': ['millegrilles.domaines.SenseursPassifs.lecture']}}
        }
        sort_query = [
            ('_evenements.%s.transaction_traitee' % idmg, 1)
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

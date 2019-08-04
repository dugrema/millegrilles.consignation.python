# Module de processus pour MilleGrilles
import logging
import datetime

from bson.objectid import ObjectId

from millegrilles import Constantes
from millegrilles.dao.MessageDAO import BaseCallback, JSONHelper
from millegrilles.util.UtilScriptLigneCommande import ModeleConfiguration
from millegrilles.transaction.ConsignateurTransaction import ConsignateurTransactionCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction


class MGPProcessusControleur(ModeleConfiguration):
    """
    Controleur des processus MilleGrilles. Identifie et execute les processus.

    MGPProcessus = MilleGrilles Python Processus. D'autres controleurs de processus peuvent etre disponibles.
    """

    def __init__(self):
        super().__init__()
        # self._json_helper = JSONHelper()
        # self._message_handler = None

        self._traitement_evenements = None

    def initialiser(self, init_message=True, init_document=True, connecter=True):
        super().initialiser(init_document, init_message, connecter)

        # Executer la configuration pour RabbitMQ
        self._contexte.message_dao.configurer_rabbitmq()
        self._traitement_evenements = MGPProcesseurTraitementEvenements(self._contexte)

    def executer(self):
        """ Methode qui demarre la lecture des evenements sur la Q de processus. """
        self.contexte.message_dao.demarrer_lecture_etape_processus(self._traitement_evenements.callbackAvecAck)

    def document_dao(self):
        return self.contexte.document_dao

    def message_dao(self):
        return self.contexte.message_dao

    @property
    def contexte(self):
        return self._contexte


class MGPProcesseurTraitementEvenements(BaseCallback):

    def __init__(self, contexte, gestionnaire_domaine=None):
        super().__init__(contexte)

        self._json_helper = JSONHelper()
        self._contexte = contexte
        self._gestionnaire_domaine = gestionnaire_domaine
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def initialiser(self, collection_processus_noms: list):
        # Configuration pour les processus
        for collection_processus_nom in collection_processus_noms:
            collection = self._contexte.document_dao.get_collection(collection_processus_nom)
            collection.create_index([
                (Constantes.PROCESSUS_MESSAGE_LIBELLE_ETAPESUIVANTE, 1),
                (Constantes.PROCESSUS_MESSAGE_LIBELLE_PROCESSUS, 1),
                (Constantes.DOCUMENT_INFODOC_DATE_CREATION, 1)
            ])
            collection.create_index([
                (Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKEN_ATTENTE, 1)
            ])
            collection.create_index([
                (Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKEN_RESUMER, 1)
            ])

    def extraire_evenement(self, message_body):
        """
        Lit l'evenement JSON est retourne un dictionnaire avec toute l'information.

        :param message_body:
        :return: Dictionnaire de tout le contenu de l'evenement.
        """
        # Extraire le message qui devrait etre un document JSON
        message_dict = self._json_helper.bin_utf8_json_vers_dict(message_body)
        return message_dict

    def traiter_evenement(self, evenement):
        """
        Execute une etape d'un processus. La classe MGProcessus est responsable de l'orchestration.
        :param evenement:
        :return:
        """
        classe_processus = self.identifier_processus(evenement)
        instance_processus = classe_processus(self, evenement)
        instance_processus.traitement_etape()

    def identifier_processus(self, evenement):
        """
        Identifie le processus a executer, retourne une instance si le processus est trouve.
        :param evenement:
        :return: Instance MGPProcessus si le processus est trouve.
        :raises ErreurProcessusInconnu: Si le processus est inconnu.
        """
        nom_processus = evenement.get(Constantes.PROCESSUS_DOCUMENT_LIBELLE_PROCESSUS)
        nom_module, nom_classe = nom_processus.split(':')
        nom_module = nom_module.replace("_", ".")
        logging.debug('Importer %s, %s' % (nom_module, nom_classe))
        module_processus = __import__('%s' % nom_module, fromlist=nom_classe)
        classe_processus = getattr(module_processus, nom_classe)
        return classe_processus

    def charger_transaction_par_id(self, id_transaction, nom_collection):
        return self.contexte.document_dao.charger_transaction_par_id(id_transaction, nom_collection)

    def charger_document_processus(self, id_document_processus, nom_collection):
        return self.contexte.document_dao.charger_processus_par_id(
            id_document_processus, nom_collection)

    def sauvegarder_etape_processus(self, collection_processus_nom, id_document_processus, dict_etape,
                                    etape_suivante=None):
        """
        Modifie un document de processus en ajoutant l'information de l'etape a la suite des autres etapes
        dans la liste du processus.

        :param collection_processus_nom: Nom de la collection mongo des processus pour le domaine
        :param id_document_processus: _id du document dans la collection processus.
        :param dict_etape: Dictionnaire complet a ajoute a la file des autres etapes.
        :param etape_suivante:
        """
        collection_processus = self._contexte.document_dao.get_collection(collection_processus_nom)

        # Convertir id_document_process en ObjectId
        if isinstance(id_document_processus, ObjectId):
            id_document = {Constantes.MONGO_DOC_ID: id_document_processus}
        else:
            id_document = {Constantes.MONGO_DOC_ID: ObjectId(id_document_processus)}

        doc_etape = dict_etape.copy()
        doc_etape[Constantes.PROCESSUS_DOCUMENT_LIBELLE_DATEEXECUTION] = datetime.datetime.utcnow()

        # print("$push vers mongo: %s --- %s" % (id_document, str(dict_etape)))
        operation = {}

        # $push operations (toujours presente)
        push_operation = {Constantes.PROCESSUS_DOCUMENT_LIBELLE_ETAPES: doc_etape}

        # $addToSet operation
        addtoset_operation = {}
        tokens = doc_etape.get(Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKENS)
        if tokens is not None:
            tokens_attente = tokens.get(Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKEN_ATTENTE)
            if tokens_attente is not None:
                push_operation[Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKEN_ATTENTE] = {'$each': tokens_attente}

            tokens_resumer = tokens.get(Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKEN_RESUMER)
            if tokens_resumer is not None:
                addtoset_operation[Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKEN_RESUMER] = {'$each': tokens_resumer}

        # $set operations
        set_operation = {}
        unset_operation = {}
        if etape_suivante is None:
            # Nettoyage pour finalisation du processus
            # Enlever tous les elements qui font parti d'un index / recherche de traitement actif
            unset_operation.update({
                Constantes.PROCESSUS_DOCUMENT_LIBELLE_ETAPESUIVANTE: '',
                Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKEN_ATTENTE: '',
                Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKEN_RESUMER: '',
            })
        else:
            set_operation[Constantes.PROCESSUS_DOCUMENT_LIBELLE_ETAPESUIVANTE] = etape_suivante

        dict_etapes_parametres = dict_etape.get(Constantes.PROCESSUS_DOCUMENT_LIBELLE_PARAMETRES)
        if dict_etapes_parametres is not None:
            for key, value in dict_etapes_parametres.items():
                complete_key = 'parametres.%s' % key
                set_operation[complete_key] = value

        # Preparer les operations globales de la requete MongoDB
        operation['$push'] = push_operation
        if len(set_operation) > 0:
            operation['$set'] = set_operation
        if len(addtoset_operation) > 0:
            operation['$addToSet'] = addtoset_operation
        if len(unset_operation) > 0:
            operation['$unset'] = unset_operation

        # Conserver la date de mise a jour
        operation['$currentDate'] = {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}

        self.__logger.debug("Requete MongoDB pour update processus:\n%s" % str(operation))

        resultat = collection_processus.update_one(id_document, operation)

        if resultat.modified_count != 1:
            raise ErreurMAJProcessus("Erreur MAJ processus: %s" % str(resultat))

    def message_etape_suivante(self, id_document_processus, nom_processus, nom_etape, tokens=None):
        self.contexte.message_dao.transmettre_evenement_mgpprocessus(
            self._gestionnaire_domaine.get_nom_domaine(), id_document_processus, nom_processus, nom_etape, tokens)

    def transmettre_message_resumer(self, id_document_declencheur, tokens: list, id_document_processus_attente=None):
        self.contexte.message_dao.transmettre_evenement_mgp_resumer(
            self._gestionnaire_domaine.get_nom_domaine(), id_document_declencheur, tokens, id_document_processus_attente)

    def transmettre_message_continuer(self, id_document_processus, tokens=None):
        document_processus = self.charger_document_processus(
            id_document_processus, self._gestionnaire_domaine.get_collection_processus_nom())

        self.contexte.message_dao.transmettre_evenement_mgpprocessus(
            self._gestionnaire_domaine.get_nom_domaine(),
            id_document_processus,
            document_processus.get(Constantes.PROCESSUS_DOCUMENT_LIBELLE_PROCESSUS),
            document_processus.get(Constantes.PROCESSUS_DOCUMENT_LIBELLE_ETAPESUIVANTE),
            info=tokens
        )

    def preparer_document_helper(self, collection, classe):
        helper = classe(self.contexte.document_dao.get_collection(collection))
        return helper

    '''
    Callback pour chaque evenement. Gere l'execution d'une etape a la fois.
    '''
    def traiter_message(self, ch, method, properties, body):

        id_doc_processus = None
        try:
            # Decoder l'evenement qui contient l'information sur l'etape a traiter
            evenement_dict = self.extraire_evenement(body)
            evenement_type = evenement_dict.get('evenement')
            if evenement_type == Constantes.EVENEMENT_RESUMER:
                self.traiter_resumer(evenement_dict)
            else:
                id_doc_processus = evenement_dict.get(Constantes.PROCESSUS_MESSAGE_LIBELLE_ID_DOC_PROCESSUS)
                logging.debug("Recu evenement processus: %s" % str(evenement_dict))
                self.traiter_evenement(evenement_dict)
        except Exception as e:
            # Mettre le message d'erreur sur la Q erreur processus
            self.erreur_fatale(id_doc_processus, str(body), e)

    def traiter_resumer(self, evenement_dict):
        id_doc_attente = evenement_dict.get(Constantes.PROCESSUS_MESSAGE_LIBELLE_ID_DOC_PROCESSUS_ATTENTE)
        tokens = evenement_dict.get(Constantes.PROCESSUS_MESSAGE_LIBELLE_RESUMER_TOKENS)

        nom_collection_processus = self._gestionnaire_domaine.get_collection_processus_nom()
        collection_processus = self._contexte.document_dao.get_collection(nom_collection_processus)

        if id_doc_attente is None:
            filtre = {
                Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKEN_ATTENTE: {"$in": tokens}
            }
            self.__logger.debug("Trouver documents en attente de :\n %s" % str(filtre))
            curseur_processus = collection_processus.find(filtre)

            # Declencher le traitement des processus trouves
            for processus in curseur_processus:
                self.__logger.debug("Resumer processus %s" % str(processus))
                self.message_etape_suivante(processus.get('_id'),
                                            processus.get(Constantes.PROCESSUS_DOCUMENT_LIBELLE_PROCESSUS),
                                            processus.get(Constantes.PROCESSUS_DOCUMENT_LIBELLE_ETAPESUIVANTE),
                                            tokens={
                                                'processus': evenement_dict.get('_id_document_processus_declencheur'),
                                                'tokens': tokens}
                                            )

        else:
            self.__logger.debug("Resumer document %s en attente de %s" % (id_doc_attente, str(tokens)))

    '''
    Sauvegarde un nouveau document dans la collection de processus pour l'initialisation d'un processus.

    :param parametres: Parametres pour l'etape initiale.
    :returns: _id du nouveau document de processus
    '''

    def sauvegarder_initialisation_processus(self, collection_processus, moteur, nom_processus, parametres):
        document = {
            Constantes.PROCESSUS_DOCUMENT_LIBELLE_MOTEUR: moteur,
            Constantes.PROCESSUS_DOCUMENT_LIBELLE_PROCESSUS: nom_processus,
            Constantes.PROCESSUS_DOCUMENT_LIBELLE_ETAPESUIVANTE: 'initiale',
            Constantes.PROCESSUS_DOCUMENT_LIBELLE_PARAMETRES: parametres,
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
            Constantes.PROCESSUS_DOCUMENT_LIBELLE_ETAPES: [
                {
                    Constantes.PROCESSUS_DOCUMENT_LIBELLE_NOMETAPE: 'orientation',
                    Constantes.PROCESSUS_DOCUMENT_LIBELLE_PARAMETRES: parametres,
                    Constantes.PROCESSUS_DOCUMENT_LIBELLE_DATEEXECUTION: datetime.datetime.utcnow()
                }
            ]
        }
        doc_id = collection_processus.insert_one(document)
        return doc_id.inserted_id

    @property
    def contexte(self):
        return self._contexte

    @property
    def configuration(self):
        return self.contexte.configuration

    @property
    def demarreur_processus(self):
        return self._gestionnaire_domaine.demarreur_processus

    def erreur_fatale(self, id_document_processus, message_original=None, erreur=None):
        """
        Lance une erreur fatale pour ce message. Met l'information sur la Q d'erreurs.
        :param id_document_processus:
        :param message_original: Le message pour lequel l'erreur a ete generee.
        :param erreur: Optionnel, objet ErreurExecutionEtape.
        :return:
        """
        self.contexte.message_dao.transmettre_erreur_processus(
            id_document_processus=id_document_processus, message_original=message_original, detail=erreur)


# class MGControlleurMessageHandler(BaseCallback):
#
#     def __init__(self, contexte, controleur):
#         super().__init__(contexte)
#         self._contexte = contexte
#         self._controleur = controleur
#
#     '''
#     Callback pour chaque evenement. Gere l'execution d'une etape a la fois.
#     '''
#     def traiter_message(self, ch, method, properties, body):
#
#         id_doc_processus = None
#         try:
#             # Decoder l'evenement qui contient l'information sur l'etape a traiter
#             evenement_dict = self._controleur.extraire_evenement(body)
#             id_doc_processus = evenement_dict.get(Constantes.PROCESSUS_MESSAGE_LIBELLE_ID_DOC_PROCESSUS)
#             logging.debug("Recu evenement processus: %s" % str(evenement_dict))
#             self._controleur.traiter_evenement(evenement_dict)
#         except Exception as e:
#             # Mettre le message d'erreur sur la Q erreur processus
#             self._controleur.erreur_fatale(id_doc_processus, str(body), e)


class MGProcessus:

    """
    Classe de processus MilleGrilles. Continent des methodes qui representes les etapes du processus.

    :param controleur: Controleur de processus qui appelle l'etape
    :param evenement: Message recu qui a declenche l'execution de cette etape
    """
    def __init__(self, controleur: MGPProcesseurTraitementEvenements, evenement):
        if controleur is None or evenement is None:
            raise Exception('controleur et evenement ne doivent pas etre None')

        self._controleur = controleur
        self._evenement = evenement

        self._document_processus = None
        self._etape_suivante = None
        self._etape_complete = False
        self._methode_etape_courante = None
        self._processus_complete = False
        self._ajouter_token_attente = None
        self._ajouter_token_resumer = None

        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    '''
    Utilise le message pour identifier l'etape courante qui doit etre executee. 
    
    :returns: Methode executable.
    :raises ErreurEtapeInconnue: Si l'evenement ne contient pas l'information sur quelle etape executer
    :raises AttributeError: Si le nom de l'etape ne correspond a aucune methode de la classe.
    '''
    def _identifier_etape_courante(self):
        # Retourner le contenu de l'element etape-suivante du message. L'etape a executer
        # est determinee par l'etape precedente d'un processus.
        nom_methode = self._evenement.get(Constantes.PROCESSUS_MESSAGE_LIBELLE_ETAPESUIVANTE)
        if nom_methode is None:
            raise ErreurEtapeInconnue("etape-suivante est manquante sur evenement pour classe %s: %s" % (
                self.__class__.__name__, self._evenement))
        methode_a_executer = getattr(self, nom_methode)

        return methode_a_executer

    '''
    Prepare un message qui peut etre mis sur la Q de MGPProcessus pour declencher l'execution de l'etape suivante.
    
    :returns: Libelle identifiant l'etape suivante a executer.
    '''
    def transmettre_message_etape_suivante(self, parametres=None):
        # Verifier que l'etape a ete executee avec succes.
        if not self._etape_complete or self._etape_suivante is None:
            raise ErreurEtapePasEncoreExecutee("L'etape n'a pas encore ete executee ou l'etape suivante est inconnue")

        # L'etape suviante est declenchee a partir d'un message qui a le nom du processus, l'etape et
        # le document de processus. On va chercher le nom du module et de la classe directement (__module__ et
        # __name__) plutot que d'utiliser des constantes pour faciliter le refactoring.
        nom_module_tronque = self.__class__.__module__.replace('.', '_')
        nom_classe = self.__class__.__name__
        nom_processus = '%s:%s' % (nom_module_tronque, nom_classe)

        self._controleur.message_etape_suivante(
            self._document_processus[Constantes.MONGO_DOC_ID],
            nom_processus,
            self._etape_suivante
        )

    '''
    Execute l'etape identifiee dans le message.

    :raises ErreurExecutionEtape: Erreur fatale encontree lors de l'execution de l'etape
    '''
    def traitement_etape(self):

        id_document_processus = None
        try:
            # Charger le document du processus
            id_document_processus = self._evenement[Constantes.PROCESSUS_MESSAGE_LIBELLE_ID_DOC_PROCESSUS]
            self._document_processus = self._controleur.charger_document_processus(
                id_document_processus, self.get_collection_processus_nom())

            # Executer l'etape
            etape_execution = self._identifier_etape_courante()
            resultat = etape_execution()
            self._etape_complete = True

            # Enregistrer le resultat de l'execution de l'etape
            document_etape = {
                Constantes.PROCESSUS_DOCUMENT_LIBELLE_NOMETAPE: etape_execution.__name__
            }
            if resultat is not None:
                document_etape[Constantes.PROCESSUS_DOCUMENT_LIBELLE_PARAMETRES] = resultat

            # Ajouter tokens pour synchronisation inter-transaction.
            tokens = {}
            if self._ajouter_token_resumer is not None:
                tokens[Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKEN_RESUMER] = self._ajouter_token_resumer
            if self._ajouter_token_attente is not None:
                tokens[Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKEN_ATTENTE] = self._ajouter_token_attente
            if len(tokens) > 0:
                document_etape[Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKENS] = tokens

            self._controleur.sauvegarder_etape_processus(
                self.get_collection_processus_nom(), id_document_processus, document_etape, self._etape_suivante)

            # Verifier s'il faut transmettre un message pour continuer le processus ou s'il est complete.
            if self._ajouter_token_resumer is not None:
                self._controleur.transmettre_message_resumer(
                    id_document_processus, self._ajouter_token_resumer)
            elif not self._processus_complete and self._ajouter_token_attente is None:
                self.transmettre_message_etape_suivante(resultat)

            # Verifier s'il faut avertir d'autres processus que le traitement de l'etape est complete
            if self._evenement.get('resumer_token') is not None:
                info_tokens_resume = self._evenement['resumer_token']
                id_document_processus = info_tokens_resume.get('processus')
                self._logger.debug("Transmission message terminer processus resumer tokens %s" % id_document_processus)
                self._controleur.transmettre_message_continuer(
                    id_document_processus,
                    {'processus': id_document_processus, 'tokens': info_tokens_resume.get('tokens')}
                )

        except Exception as erreur:
            # Erreur inconnue. On va assumer qu'elle est fatale.
            self._controleur.erreur_fatale(id_document_processus=id_document_processus, erreur=erreur)

    ''' Methode initiale, doit etre implementee par la sous-classe '''
    def initiale(self):
        raise NotImplemented("La methode initiale doit etre implementee par la sous-classe")

    '''
    Implementation de reference pour l'etape finale. Peut etre modifiee par la sous-classe au besoin.
    '''
    def finale(self):
        self._etape_complete = True
        self._processus_complete = True

        succes = self.parametres.get('succes')
        if succes is None:
            succes = True

        resultat = {
            'complete': self._processus_complete,
            'succes': succes,
            'reponse_transmise': False,
        }

        # Verifier si on doit transmettre une notification de traitement termine
        properties = self.parametres.get('properties')
        if properties is not None:
            # Verifier si on a reply_to et correlation_id pour transmettre une confirmation de traitement
            if properties.get('reply_to') is not None and properties.get('correlation_id') is not None:
                generateur_transactions = GenerateurTransaction(self.contexte)
                generateur_transactions.transmettre_reponse(
                    resultat, properties['reply_to'], properties['correlation_id'])
                resultat['reponse_transmise'] = True

        logging.debug("Etape finale executee pour %s" % self.__class__.__name__)
        return resultat

    def erreur_fatale(self, detail=None):
        self._etape_complete = True
        self._processus_complete = True
        logging.error("Erreur fatale - voir Q")

        information = None
        if detail is not None:
            information = {'erreur': detail}
        return information

    '''
    Utiliser cette methode pour indiquer quelle est la prochaine etape a executer.
    
    :param etape_suivante: Prochaine etape (methode) a executer. Par defaut utilise l'etape finale qui va terminer le processus.
    '''
    def set_etape_suivante(self, etape_suivante='finale', token_attente: list = None):
        self._etape_complete = True
        self._etape_suivante = etape_suivante
        self._ajouter_token_attente = token_attente

    def attendre_token(self, tokens: list):
        """
        Verifie si les tokens existent deja.
        Ajoute un token pour dire que le processus est en attente d'un evenement externe.
        :return: "True, list documents" processus si tous les tokens ont ete trouves. False si pas tous trouves.
        """
        liste_documents_process_trouves = None

        # Chercher la collection pour les documents avec les tokens resumes correspondants aux tokens d'attente

        if self._ajouter_token_attente is None:
            self._ajouter_token_attente = tokens
        else:
            self._ajouter_token_attente.extend(tokens)

        return False, liste_documents_process_trouves

    def resumer_processus(self, tokens: list):
        """
            Ajoute un token pour dire que le processus/transaction du processus est necessaire a un autre processus.
            Va automatiquement transmettre un message qui sera recu par le processus en attente (s'il existe).
        """
        if self._ajouter_token_resumer is None:
            self._ajouter_token_resumer = tokens
        else:
            self._ajouter_token_resumer.extend(tokens)

    @property
    def contexte(self):
        return self._controleur.contexte

    @property
    def document_processus(self):
        """
        Retourne le document pour ce processus.
        :return: Document de processus
        """
        return self._document_processus

    @property
    def parametres(self):
        """
        Retourne le document des parametres courants (read-only - les changements sont ignores).
        :return: Document de parametres.
        """
        return self._document_processus['parametres']

    def get_collection_transaction_nom(self):
        raise NotImplementedError("Pas implemente")

    def get_collection_processus_nom(self):
        raise NotImplementedError("Pas implemente")


# Classe de processus pour les transactions. Contient certaines actions dans finale() pour marquer la transaction
# comme ayant ete completee.
class MGProcessusTransaction(MGProcessus):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

        self._transaction = None

    def trouver_id_transaction(self):
        parametres = self._document_processus[Constantes.PROCESSUS_MESSAGE_LIBELLE_PARAMETRES]
        id_transaction = parametres[Constantes.TRANSACTION_MESSAGE_LIBELLE_ID_MONGO]
        domaine = parametres[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]
        collection = ConsignateurTransactionCallback.identifier_collection_domaine(domaine)
        return {'id_transaction': id_transaction, 'nom_collection': collection}

    def charger_transaction(self, nom_collection=None):
        if nom_collection is None:
            nom_collection = self.get_collection_transaction_nom()
        info_transaction = self.trouver_id_transaction()
        id_transaction = info_transaction['id_transaction']
        self._transaction = self._controleur.charger_transaction_par_id(id_transaction, nom_collection)
        return self._transaction

    def finale(self):
        # Ajouter l'evenement 'traitee' dans la transaction
        self.marquer_transaction_traitee()
        return super().finale()

    ''' Ajoute l'evenement 'traitee' dans la transaction '''
    def marquer_transaction_traitee(self):
        info_transaction = self.trouver_id_transaction()
        id_transaction = info_transaction['id_transaction']
        nom_collection = info_transaction['nom_collection']
        ConsignateurTransactionCallback.ajouter_evenement_transaction(
            self._controleur.contexte,
            id_transaction,
            nom_collection,
            Constantes.EVENEMENT_TRANSACTION_TRAITEE
        )

    def marquer_transaction_intraitable(self):
        pass

    @property
    def transaction(self):
        if self._transaction is None:
            return self.charger_transaction()
        return self._transaction


# Classe qui sert a demarrer un processus
class MGPProcessusDemarreur:

    def __init__(self, contexte, nom_domaine: str, collection_transaction_nom: str, collection_processus_nom: str,
                 traitement_processus: MGPProcesseurTraitementEvenements):
        self._contexte = contexte
        self._json_helper = JSONHelper()

        self._nom_domaine = nom_domaine
        self._collection_transaction_nom = collection_transaction_nom
        self._collection_processus_nom = collection_processus_nom
        self._traitement_processus = traitement_processus

        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def demarrer_processus(self, processus_a_declencher, dictionnaire_evenement, moteur="MGPProcessus"):
        """
        Demarre un processus - par defaut c'est un MGPProcessus

        :param processus_a_declencher: Pour un MGPProcessus, nom qualifie d'une classe selon: modA_modB[_...]:Classe
        :param dictionnaire_evenement: Le message qui declenche ce processus.
        :param moteur: Nom du moteur (si autre que MGPProcessus)
        :return:
        """

        self._logger.debug(
            "Demarrer processus: %s. Parametres: %s" % (processus_a_declencher, str(dictionnaire_evenement)))
        id_document = dictionnaire_evenement.get(Constantes.TRANSACTION_MESSAGE_LIBELLE_ID_MONGO)

        try:
            # On va declencher un nouveau processus
            collection_processus = self.contexte.document_dao.get_collection(self._collection_processus_nom)
            id_doc_processus = self._traitement_processus.sauvegarder_initialisation_processus(
                collection_processus, moteur, processus_a_declencher, dictionnaire_evenement)

            self.contexte.message_dao.transmettre_evenement_mgpprocessus(
                self._nom_domaine, id_doc_processus, nom_processus=processus_a_declencher
            )

        except Exception as erreur:
            # Erreur inconnue. On va assumer qu'elle est fatale.
            self.contexte.message_dao.transmettre_erreur_transaction(id_document=id_document, detail=erreur)

    @property
    def contexte(self):
        return self._contexte




'''
Exception lancee lorsqu'une etape ne peut plus continuer (erreur fatale).
'''


class ErreurProcessusInconnu(Exception):

    def __init__(self, message=None):
        super().__init__(self, message)


class ErreurEtapeInconnue(Exception):

    def __init__(self, message=None):
        super().__init__(self, message)


class ErreurEtapePasEncoreExecutee(Exception):

    def __init__(self, message=None):
        super().__init__(self, message)


class ErreurMAJProcessus(Exception):

    def __init__(self, message=None):
        super().__init__(message=message)


# --- MAIN ---
#
#
# controleur = MGPProcessusControleur()
#
#
# def exit_gracefully(signum, frame):
#     logging.info("Arret de MGProcessusControleur")
#     controleur.deconnecter()
#
#
# def main():
#     logging.basicConfig(format='%(asctime)s %(message)s')
#     logging.getLogger('mgdomaines').setLevel(logging.DEBUG)
#     logging.getLogger('millegrilles').setLevel(logging.DEBUG)
#     logging.info("Demarrage de MGProcessusControleur")
#
#     signal.signal(signal.SIGINT, exit_gracefully)
#     signal.signal(signal.SIGTERM, exit_gracefully)
#
#     controleur.initialiser()
#
#     try:
#         logging.info("MGProcessusControleur est pret")
#         controleur.executer()
#     finally:
#         exit_gracefully(None, None)
#
#     logging.info("MGProcessusControleur est arrete")
#
#
# if __name__=="__main__":
#     main()

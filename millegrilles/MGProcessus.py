# Module de processus pour MilleGrilles
import logging
import datetime
import requests
import hashlib

from threading import Thread, Event, Barrier
from bson.objectid import ObjectId
import uuid

from millegrilles import Constantes
from millegrilles.Erreurs import ErreurModeRegeneration
from millegrilles.dao.MessageDAO import JSONHelper, ConnexionWrapper, TraitementMessageDomaine, \
    TraitementMessageDomaineMiddleware, CertificatInconnu
from millegrilles.transaction import GenerateurTransaction
from millegrilles.transaction.TransmetteurMessage import TransmetteurMessageMilleGrilles
from millegrilles.SecuritePKI import AutorisationConditionnelleDomaine
from millegrilles.util.ValidateursMessages import ValidateurMessage
from millegrilles.util.ValidateursPki import ValidateurCertificat


class MGPProcesseur:

    def __init__(self, gestionnaire_domaine, contexte):
        self.__gestionnaire_domaine = gestionnaire_domaine
        self.__contexte = contexte
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

        self.__transmetteur = TransmetteurMessageMilleGrilles(self.__contexte)
        self.__contexte.message_dao.register_channel_listener(self.__transmetteur)

    def charger_transaction_par_id(self, id_transaction, nom_collection):
        return self.document_dao.charger_transaction_par_id(id_transaction, nom_collection)

    def charger_transaction_par_uuid(self, uuid_transaction, nom_collection):
        collection = self.document_dao.get_collection(nom_collection)
        label_uuid = '.'.join(
            [Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE, Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID])
        return collection.find_one({label_uuid: uuid_transaction})

    def charger_document_processus(self, id_document_processus, nom_collection):
        return self.document_dao.charger_processus_par_id(
            id_document_processus, nom_collection)

    def identifier_processus(self, evenement):
        """
        Identifie le processus a executer, retourne une instance si le processus est trouve.
        :param evenement:
        :return: Instance MGPProcessus si le processus est trouve.
        :raises ErreurProcessusInconnu: Si le processus est inconnu.
        """
        nom_processus = evenement.get(Constantes.PROCESSUS_DOCUMENT_LIBELLE_PROCESSUS)
        resultats = nom_processus.split(':')

        if len(resultats) == 2:
            routing = resultats[0]
            nom_module = resultats[0]
            nom_classe = resultats[1]
        elif len(resultats) == 3:
            routing = resultats[0]
            nom_module = resultats[1]
            nom_classe = resultats[2]
        else:
            raise ValueError("Mapping processus incorrect: %s" % nom_processus)

        nom_module = nom_module.replace("_", ".")
        logging.debug('Importer domaine %s : %s.%s' % (routing, nom_module, nom_classe))
        module_processus = __import__('%s' % nom_module, fromlist=nom_classe)
        classe_processus = getattr(module_processus, nom_classe)
        return classe_processus

    def message_etape_suivante(self, id_document_processus, nom_processus, nom_etape, tokens=None):
        raise NotImplementedError("Pas Implemente")

    def transmettre_message_verifier_resumer(self, id_document_processus_attente, tokens:list):
        raise NotImplementedError("Pas Implemente")

    def transmettre_message_resumer(self, id_document_declencheur, tokens: list, id_document_processus_attente=None):
        raise NotImplementedError("Pas Implemente")

    def transmettre_message_continuer(self, id_document_processus, tokens=None):
        raise NotImplementedError("Pas Implemente")

    def sauvegarder_etape_processus(self, collection_processus_nom, id_document_processus, dict_etape,
                                    etape_suivante=None):
        raise NotImplementedError("Pas Implemente")

    def erreur_fatale(self, id_document_processus, message_original=None, erreur=None, processus=None):
        raise NotImplementedError("Pas Implemente")

    @property
    def message_dao(self):
        return self.__contexte.message_dao

    @property
    def document_dao(self):
        return self.__contexte.document_dao

    @property
    def generateur_transactions(self) -> GenerateurTransaction:
        return self.__contexte.generateur_transactions

    @property
    def transmetteur(self) -> TransmetteurMessageMilleGrilles:
        return self.__transmetteur

    @property
    def verificateur_transaction(self):
        raise NotImplementedError("Deprecated - utiliser validateur_message()")
        # return self.__contexte.verificateur_transaction

    @property
    def validateur_message(self) -> ValidateurMessage:
        return self.__contexte.validateur_message

    @property
    def validateur_pki(self) -> ValidateurCertificat:
        return self.__contexte.validateur_pki

    @property
    def configuration(self):
        return self.__contexte.configuration

    @property
    def _gestionnaire(self):
        return self.__gestionnaire_domaine

    @property
    def gestionnaire(self):
        return self.__gestionnaire_domaine

    @property
    def demarreur_processus(self):
        return self.__gestionnaire_domaine.demarreur_processus

    @property
    def collection_processus_nom(self):
        return self.__gestionnaire_domaine.get_collection_processus_nom

    @property
    def get_collection_transaction_nom(self):
        return self.__gestionnaire_domaine.get_collection_transaction_nom

    @property
    def get_collection_documents(self):
        return self.__gestionnaire_domaine.get_collection

    @property
    def contexte(self):
        self.__logger.warning("Acces contexte par MGProcessus est deprecated")
        return self.__contexte

    @property
    def _contexte(self):
        return self.__contexte

    @property
    def is_regeneration(self):
        """
        :return: Vrai pour un controleur de regeneration.
        """
        return False


class MGPProcesseurTraitementEvenements(MGPProcesseur, TraitementMessageDomaine):
    """
    Classe qui recoit les messages de MQ et gere une thread de travail longue duree.
    Si le nombre de messages recus de MQ depasse la limite, un basic cancel et transmis et
    (interruption du consommateur) et le travail se poursuit jusqu'a l'epuisement de la Q locale.
    """

    def __init__(self, contexte, stop_event, gestionnaire_domaine=None):
        MGPProcesseur.__init__(self, gestionnaire_domaine, contexte)
        TraitementMessageDomaine.__init__(self, gestionnaire_domaine)

        self._json_helper = JSONHelper()
        self._gestionnaire_domaine = gestionnaire_domaine
        self.__stop_event = stop_event

        # Liste de messages a traiter
        self._q_locale = list()

        # Si limite est depasse, un cesse de consommer des messages dans MQ
        self._max_q_size = 50
        self._consume_actif = True
        self._q_processus = '%s.%s' % (gestionnaire_domaine.get_nom_queue(), 'evenements')

        self._thread_traitement = Thread(target=self.__run, name="MGPProcess", daemon=True)
        self.__connectionmq_publisher = ConnexionWrapper(self.configuration, self.__stop_event, heartbeat=15)
        self.__wait_event = Event()

        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

        self.__traitement_middleware = TraitementMessageDomaineMiddleware(self.gestionnaire)

        self._thread_traitement.start()

    def arreter(self):
        self.__wait_event.set()
        self.__connectionmq_publisher.deconnecter()

    def __run(self):

        self.__logger.info("Demarrage thread MGPProcessus")

        barrier = Barrier(2)
        self.__connectionmq_publisher.connecter(barrier)
        barrier.wait()
        if barrier.broken:
            raise Exception("Erreur connexion MQ %s" % self.__class__.__name__)

        maintenance_delta = datetime.timedelta(seconds=20)
        derniere_maintenance = datetime.datetime.now()

        while not self.__stop_event.is_set():
            try:
                temps_courant = datetime.datetime.now()

                if self.__connectionmq_publisher.is_closed:

                    # La connexion est fermee. Traitement interrompu jusque reconnexion
                    barrier = Barrier(2)
                    self.__connectionmq_publisher.connecter(barrier)
                    barrier.wait(10)

                elif temps_courant - maintenance_delta > derniere_maintenance:
                    derniere_maintenance = temps_courant

                    self.__connectionmq_publisher.executer_maintenance()

                if len(self._q_locale) > 0:
                    self.__prochain_message()
                elif not self._consume_actif:
                    # Reactiver le consume
                    self.gestionnaire.inscrire_basicconsume(self._q_processus, self.callbackAvecAck)
                    self._consume_actif = True
                else:
                    # Toutes les operations en suspend sont completees, reactiver le wait
                    self.__wait_event.clear()

            except Exception:
                self.__logger.exception("Erreur thread MGPProcessus")
                self.__stop_event.wait(5)  # Throttle, 5 secondes d'attente sur erreur

            self.__wait_event.wait(10)

        self.__logger.info("Fin thread MGPProcessus")

    def initialiser(self, collection_processus_noms: list):
        # Configuration pour les processus
        for collection_processus_nom in collection_processus_noms:
            collection = self._contexte.document_dao.get_collection(collection_processus_nom)
            collection.create_index(
                [
                    (Constantes.PROCESSUS_MESSAGE_LIBELLE_ETAPESUIVANTE, 1),
                    (Constantes.PROCESSUS_MESSAGE_LIBELLE_PROCESSUS, 1),
                    (Constantes.DOCUMENT_INFODOC_DATE_CREATION, 1)
                ],
                name='etapesuivante-processus-creation',
            )
            collection.create_index(
                [
                    (Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKEN_ATTENTE, 1)
                ],
                name='tokenattente',
            )
            collection.create_index(
                [
                (Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKEN_RESUMER, 1)
                ],
                name='tokenresumer'
            )

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

        # Optimistic locking - force une correspondance sur l'etape qui vient d'etre traitee
        # Permet d'identifier des situations ou plusieurs messages sont envoyes pour un meme processus
        # self.__logger.debug("Dict etape:\n%s" % json.dumps(dict_etape, indent=4))  # Peut faire planter a cause du ObjectId
        id_document[Constantes.PROCESSUS_DOCUMENT_LIBELLE_ETAPESUIVANTE] = dict_etape.get(Constantes.PROCESSUS_DOCUMENT_LIBELLE_NOMETAPE)

        doc_etape = dict_etape.copy()
        doc_etape[Constantes.PROCESSUS_DOCUMENT_LIBELLE_DATEEXECUTION] = datetime.datetime.utcnow()

        # print("$push vers mongo: %s --- %s" % (id_document, str(dict_etape)))
        operation = {}

        # $push operations (toujours presente)
        push_operation = {Constantes.PROCESSUS_DOCUMENT_LIBELLE_ETAPES: doc_etape}

        # $set operations
        set_operation = {}
        unset_operation = {}
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

            tokens_connectes = tokens.get(Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKEN_CONNECTES)
            if tokens_connectes is not None:
                set_operation[Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKEN_CONNECTES] = tokens_connectes

        # $set operations
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
            raise ErreurOptimisticLocking("MAJ processus - Echec optimistic locking: %s" % str(resultat))

    def message_etape_suivante(self, id_document_processus, nom_processus, nom_etape, tokens=None):
        self._contexte.message_dao.transmettre_evenement_mgpprocessus(
            self._gestionnaire_domaine.get_nom_domaine(), id_document_processus, nom_processus, nom_etape, tokens,
            channel=self.__connectionmq_publisher.channel)

        # Indique qu'il faut surveiller si la connexion est active
        self.__connectionmq_publisher.publish_watch()

    def transmettre_message_resumer(self, id_document_declencheur, tokens: list, id_document_processus_attente=None):
        self._contexte.message_dao.transmettre_evenement_mgp_resumer(
            self._gestionnaire_domaine.get_nom_domaine(), id_document_declencheur, tokens, id_document_processus_attente,
            channel=self.__connectionmq_publisher.channel)

        # Indique qu'il faut surveiller si la connexion est active
        self.__connectionmq_publisher.publish_watch()

    def transmettre_message_verifier_resumer(self, id_document_processus_attente, tokens: list):
        self._contexte.message_dao.transmettre_evenement_mgp_verifier_resumer(
            self._gestionnaire_domaine.get_nom_domaine(), id_document_processus_attente, tokens,
            channel=self.__connectionmq_publisher.channel)

        # Indique qu'il faut surveiller si la connexion est active
        self.__connectionmq_publisher.publish_watch()

    def transmettre_message_continuer(self, id_document_processus, tokens=None):
        document_processus = self.charger_document_processus(
            id_document_processus, self._gestionnaire_domaine.get_collection_processus_nom())

        self.__logger.debug("Transmettre evenement continuer pour %s, %s" % (
            id_document_processus, document_processus.get('processus')))
        self._contexte.message_dao.transmettre_evenement_mgpprocessus(
            self._gestionnaire_domaine.get_nom_domaine(),
            id_document_processus,
            document_processus.get(Constantes.PROCESSUS_DOCUMENT_LIBELLE_PROCESSUS),
            document_processus.get(Constantes.PROCESSUS_DOCUMENT_LIBELLE_ETAPESUIVANTE),
            info=tokens,
            channel=self.__connectionmq_publisher.channel
        )

        # Indique qu'il faut surveiller si la connexion est active
        self.__connectionmq_publisher.publish_watch()

    def preparer_document_helper(self, collection, classe):
        helper = classe(self._contexte.document_dao.get_collection(collection))
        return helper

    '''
    Callback pour chaque evenement. Gere l'execution d'une etape a la fois.
    '''
    def traiter_message(self, ch, method, properties, body):
        routing_key = method.routing_key

        if routing_key.endswith('recevoirTransaction'):
            self.__traitement_middleware.traiter_message(ch, method, properties, body)
        else:
            id_doc_processus = None
            try:
                # Decoder l'evenement qui contient l'information sur l'etape a traiter
                evenement_dict = self.extraire_evenement(body)
                evenement_type = evenement_dict.get('evenement')

                message = {
                    'evenement_dict': evenement_dict,
                    'evenement_type': evenement_type,
                    'routing_key': routing_key,
                }
                if properties.correlation_id is not None:
                    message['correlation_id'] = properties.correlation_id

                    if evenement_type is None:
                        message['evenement_type'] = 'reponse'

                self._q_locale.append(message)

                if len(self._q_locale) > self._max_q_size or self.__connectionmq_publisher.is_closed:
                    # On va arreter la consommation de messages pour passer au travers de la liste en memoire
                    self.__logger.warning("Throttling Q processus : %s" % self._q_processus)
                    self._consume_actif = False
                    # ch.basic_ack(delivery_tag=method.delivery_tag)  # Transmettre ACK avant stop consuming
                    self.gestionnaire.stop_consuming(self._q_processus)

                # Activer la thread de traitement
                self.__wait_event.set()

            except Exception as e:
                # Mettre le message d'erreur sur la Q erreur processus
                self.erreur_fatale(id_doc_processus, str(body), e)

    def __prochain_message(self):
        id_doc_processus = None
        message = self._q_locale.pop(0)
        try:
            evenement_dict = message['evenement_dict']
            evenement_type = message['evenement_type']
            correlation_id = message.get('correlation_id')

            if evenement_type in [
                Constantes.EVENEMENT_TRANSACTION_TRAITEE
            ]:
                # Rien a faire
                pass
            elif evenement_type == Constantes.EVENEMENT_RESUMER:
                self.traiter_resumer(evenement_dict)

            elif evenement_type == Constantes.EVENEMENT_VERIFIER_RESUMER:
                self.verifier_resumer(evenement_dict)

            elif evenement_type == Constantes.ConstantesSecurityPki.EVENEMENT_CERTIFICAT:
                self.gestionnaire.recevoir_certificat(evenement_dict)

            elif evenement_type == Constantes.EVENEMENT_REPONSE or correlation_id is not None:
                self.ajouter_reponse(evenement_dict, correlation_id)

            else:
                id_doc_processus = evenement_dict.get(Constantes.PROCESSUS_MESSAGE_LIBELLE_ID_DOC_PROCESSUS)
                logging.debug("Recu evenement processus: %s" % str(evenement_dict))
                try:
                    self.traiter_evenement(evenement_dict)
                except AttributeError as e:
                    self.__logger.error(
                        "Erreur non reconciliable, mauvais type evenement : %s\n%s",
                        str(e), str(message))
                    raise e
        except Exception as e:
            # Mettre le message d'erreur sur la Q erreur processus
            self.erreur_fatale(id_doc_processus, str(message), e)

    def traiter_resumer(self, evenement_dict):
        id_doc_attente = evenement_dict.get(Constantes.PROCESSUS_MESSAGE_LIBELLE_ID_DOC_PROCESSUS_ATTENTE)
        id_declencheur = evenement_dict.get('_id_document_processus_declencheur')
        tokens = evenement_dict.get(Constantes.PROCESSUS_MESSAGE_LIBELLE_RESUMER_TOKENS)

        nom_collection_processus = self._gestionnaire_domaine.get_collection_processus_nom()
        collection_processus = self._contexte.document_dao.get_collection(nom_collection_processus)

        if id_doc_attente is None:
            # Faire la liste des documents en attente et les resumer un par un
            filtre = {
                Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKEN_ATTENTE: {"$in": tokens}
            }
            self.__logger.debug("Trouver documents en attente de :\n %s" % str(filtre))
            curseur_processus = collection_processus.find(filtre)

            # Declencher le traitement des processus trouves
            for processus in curseur_processus:
                self._resumer_processus(processus, tokens, id_declencheur)

        else:
            # Document en attente est connu
            filtre = {
                Constantes.MONGO_DOC_ID: ObjectId(id_doc_attente)
            }
            processus = collection_processus.find_one(filtre)
            self.__logger.debug("Resumer document %s en attente de %s:\n%s" % (id_doc_attente, str(tokens), str(processus)))
            self._resumer_processus(processus, tokens, id_declencheur)

    def _resumer_processus(self, processus, tokens, id_declencheur):
        self.__logger.debug("Resumer processus %s" % str(processus))
        filtre_processus = {Constantes.MONGO_DOC_ID: processus.get(Constantes.MONGO_DOC_ID)}

        nom_collection_processus = self._gestionnaire_domaine.get_collection_processus_nom()
        collection_processus = self._contexte.document_dao.get_collection(nom_collection_processus)

        filtre_declencheur = {Constantes.MONGO_DOC_ID: ObjectId(id_declencheur)}
        processus_declencheur = collection_processus.find_one(filtre_declencheur)
        parametres_declencheur = processus_declencheur.get('parametres')

        # Mettre a jour le document en attente
        tokens_restants = list()
        tokens_connectes = dict()
        set_update = dict()
        for token in processus.get(Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKEN_ATTENTE):
            if token not in tokens:
                tokens_restants.append(token)
            else:
                token_dockey = '%s.%s' % (Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKEN_CONNECTES, token)
                tokens_connectes[token_dockey] = id_declencheur
                set_update['parametres.%s' % token.split(':')[0]] = parametres_declencheur

        set_update[Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKEN_ATTENTE] = tokens_restants
        set_update.update(tokens_connectes)
        collection_processus.update_one(filtre_processus, {'$set': set_update})

        # Terminer l'execution du processus "resumer" correspondant
        self.message_etape_suivante(
            id_declencheur,
            processus_declencheur.get(Constantes.PROCESSUS_DOCUMENT_LIBELLE_PROCESSUS),
            processus_declencheur.get(Constantes.PROCESSUS_DOCUMENT_LIBELLE_ETAPESUIVANTE),
            tokens={
                'processus': id_declencheur,
                'tokens': tokens}
        )

        # Il ne reste aucun token d'attente, on resume le processus maitre
        if len(tokens_restants) == 0:
            self.message_etape_suivante(
                processus.get('_id'),
                processus.get(Constantes.PROCESSUS_DOCUMENT_LIBELLE_PROCESSUS),
                processus.get(Constantes.PROCESSUS_DOCUMENT_LIBELLE_ETAPESUIVANTE),
                tokens={
                    'processus': id_declencheur,
                    'tokens': tokens}
            )

    def verifier_resumer(self, evenement_dict: dict):
        """
        Verifier si les tokens resumer sont arrives pour un processus. Si des tokens sont trouves,
        ils sont associes au processus en attente.
        """
        # raise Exception("Pas complete")
        # Requete pour verifier si on a recu des transactions pour resumer le processus
        tokens = evenement_dict['resumer_tokens']
        filtre = {
            Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKEN_RESUMER: {"$in": tokens}
        }

        self.__logger.debug("Trouver tokens resumer pour : %s" % str(tokens))
        nom_collection_processus = self._gestionnaire_domaine.get_collection_processus_nom()
        collection_processus = self._contexte.document_dao.get_collection(nom_collection_processus)
        curseur_processus = collection_processus.find(filtre)

        # Declencher le traitement des processus trouves
        id_document_attente = evenement_dict['_id_document_processus_attente']
        for processus in curseur_processus:
            tokens_resumer = processus['resumer_token']
            processus_resumer_id = processus.get(Constantes.MONGO_DOC_ID)

            self.__logger.debug("Emettre message resumer %s pour tokens %s" % (id_document_attente, str(tokens_resumer)))
            self.transmettre_message_resumer(processus_resumer_id, tokens_resumer, id_document_attente)

    def ajouter_reponse(self, evenement_dict: dict, processus_id: str):
        """
        Reponse a une requete d'un processus
        On ajoute le resultat de la requete dans le processus et on redemarre l'execution.
        """
        nom_collection_processus = self._gestionnaire_domaine.get_collection_processus_nom()
        collection_processus = self._contexte.document_dao.get_collection(nom_collection_processus)

        filtre = {
            '_id': ObjectId(processus_id)
        }
        processus = collection_processus.find_one(filtre)

        ops = dict()
        if evenement_dict.get('resultats'):
            # Format de requete standard, on extrait les resultats
            ops['$push'] = {
                'parametres.reponse': evenement_dict.get('resultats')
            }
        else:
            # Format de requete non standard, on exclue l'entete et elements _
            ops_set = dict()
            ops['$push'] = {'parametres.reponse': ops_set}

            for key, value in evenement_dict.items():
                if not key.startswith('_') and key != Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE:
                    ops_set[key] = value

        collection_processus.update_one(filtre, ops)

        # Redemarrer le processus
        self.transmettre_message_continuer(processus_id)

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

    def erreur_fatale(self, id_document_processus, message_original=None, erreur=None, processus=None):
        """
        Lance une erreur fatale pour ce message. Met l'information sur la Q d'erreurs.
        :param id_document_processus:
        :param message_original: Le message pour lequel l'erreur a ete generee.
        :param erreur: Optionnel, objet ErreurExecutionEtape.
        :param processus:
        :return:
        """
        self._contexte.message_dao.transmettre_erreur_processus(
            id_document_processus=id_document_processus, message_original=message_original, detail=erreur)
        self.__logger.error("Processus erreur _id: %s" % id_document_processus)

        # Sauvegarder l'erreur dans le document de processus
        collection_processus = self._contexte.document_dao.get_collection(self.gestionnaire.get_collection_processus_nom())
        filtre_processus = {Constantes.MONGO_DOC_ID: id_document_processus}
        operations = {
            '$push': {'erreurs': str(erreur)}
        }
        collection_processus.update_one(filtre_processus, operations)

        # Transmettre  l'erreur pour completer la transaction
        if processus is not None:
            try:
                processus.marquer_evenement_transaction(Constantes.EVENEMENT_TRANSACTION_ERREUR_TRAITEMENT)
            except AttributeError:
                # Ce n'est pas un processus de transaction
                pass

    @property
    def connectionmq_publisher(self):
        return self.__connectionmq_publisher


class StubMessageDao:

    def transmettre_message(self, *args, **kwargs):
        pass

    def transmettre_message_exchange(self, *args, **kwargs):
        pass


class StubGenerateurTransactions:

    def soumettre_transaction(self, *args, **kwargs):
        pass

    def emettre_commande_noeuds(self, *args, **kwargs):
        pass

    def transmettre_requete(self, *args, **kwargs):
        pass

    def transmettre_commande(self, *args, **kwargs):
        pass

    def transmettre_reponse(self, *args, **kwargs):
        pass

    def emettre_message(self, *args, **kwargs):
        pass


class RegenerationContexteWrapper:
    """
    Wrapper pour le contexte durant la regeneration
    """

    def __init__(self, contexte):
        self.__contexte = contexte

    @property
    def message_dao(self):
        raise NotImplemented("Contexte de regeneration - message dao non disponible")

    @property
    def generateur_transactions(self):
        raise ErreurModeRegeneration()

    @property
    def document_dao(self):
        return self.__contexte.document_dao

    @property
    def verificateur_transaction(self):
        raise NotImplementedError("Deprecated - remplace par validateur_message()")
        # return self.__contexte.verificateur_transactions

    @property
    def verificateur_certificats(self):
        raise NotImplementedError("Deprecated - remplace par ")
        # return self.__contexte.verificateur_certificats

    @property
    def validateur_message(self) -> ValidateurMessage:
        return self.__contexte.validateur_message



    @property
    def configuration(self):
        return self.__contexte.configuration

    @property
    def validation_workdir_tmp(self):
        return self.__contexte.validation_workdir_tmp

    @property
    def idmg(self):
        return self.__contexte.idmg


class MGPProcesseurRegeneration(MGPProcesseur):
    """
    Processeur utiliser pour regenerer les documents d'un domaine a partir de transactions deja traitees avec succes.
    Ce processus empeche la transmission de messages et fait executer un processus sans interruption (token attente, etc.)
    """

    def __init__(self, contexte, gestionnaire_domaine):
        super().__init__(contexte, gestionnaire_domaine)

        self.__message_dao = StubMessageDao()  # Stub Message DAO
        self.__generateur_transactions = StubGenerateurTransactions()

        self.__contexte_regeneration = RegenerationContexteWrapper(super().contexte)

        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

        self._transactions_resumer = dict()  # Transactions a resumer

    @property
    def is_regeneration(self):
        return True

    @property
    def contexte(self):
        """
        :return: Wrapper sur le contexte, permet d'intercepter ou d'empecher certaines operations
        """
        return self.__contexte_regeneration

    @property
    def message_dao(self):
        """
        :return: Message Dao dummy qui ne fait rien.
        """
        return self.__message_dao

    def ajouter_transaction_resumer(self, token, transaction):
        self._transactions_resumer[token] = transaction

    def consommer_transaction_resumer(self, token_resumer: str):
        """
        Retourner une transaction qui correspond au token. Supprime la reference.

        :param token_resumer:
        :return:
        """
        transaction = self._transactions_resumer.get(token_resumer)
        if transaction:
            del self._transactions_resumer[token_resumer]

        return transaction

    @property
    def generateur_transactions(self):
        """
        :return: Generateur dummy qui ne fait rien.
        """
        return self.__generateur_transactions

    def regenerer_documents(self, stop_consuming=True):
        """
        Effectue une requete pour chaque type de transaction du domaine, en ordonnant les transactions
        completes et traitees correctement en ordre de traitement dans la MilleGrille avec autorite.

        Le groupe de base est: toutes les transactions traitees, en ordre.
        :return:
        """
        regenerateur = self._gestionnaire.creer_regenerateur_documents()

        # Deconnecter les Q (channel - consumer tags)
        if stop_consuming:
            self.gestionnaire.stop_consuming()

        filtre_doc_regeneration = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: Constantes.LIBVAL_REGENERATION
        }
        collection_documents = self.get_collection_documents()
        doc_regeneration = collection_documents.find_one(filtre_doc_regeneration)

        if doc_regeneration is not None:
            try:
                if doc_regeneration['regeneration_completee'] is True:
                    # On reset, c'est une regeneration complete
                    doc_regeneration = None
                    # Supprimer le contenu de la collection de documents
                    regenerateur.supprimer_documents()
            except KeyError:
                # On remet le document en place
                pass  # On resume la regeneration en cours
        else:
            # Supprimer le contenu de la collection de documents
            regenerateur.supprimer_documents()

        # Grouper et executer les transactions de regeneration
        generateur_groupes_transactions = regenerateur.creer_generateur_transactions(doc_regeneration)
        try:
            for transaction in generateur_groupes_transactions:
                idx_courant = generateur_groupes_transactions.index_transaction_courante
                nombre_transactions = generateur_groupes_transactions.nombre_transactions
                self.__logger.debug("Regenerer transaction %d de %d" % (idx_courant, nombre_transactions))

                uuid_transaction = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
                date_traitement = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT][Constantes.EVENEMENT_TRANSACTION_TRAITEE]
                info_regeneration = {
                    'idx_courant': idx_courant,
                    'nombre_transactions': nombre_transactions,
                    'uuid_transaction': uuid_transaction,
                    'date_traitement': date_traitement,
                    'complete': False,
                    'regeneration_completee': False,
                }
                ops = {
                    '$set': info_regeneration,
                    '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
                }

                # Conserver information de traitement de transaction dans le document de regeneration
                collection_documents.update_one(filtre_doc_regeneration, ops, upsert=True)

                transactions_a_resumer = list()

                if transaction is not None:
                    traiter = True

                    if traiter:
                        self.traiter_transaction_wrapper(transaction)

                        for transaction_resumer in transactions_a_resumer:
                            self.__logger.debug("Transaction master completee, resumer transaction " + str(transaction_resumer))
                            self.traiter_transaction_wrapper(transaction_resumer)

                    info_regeneration['complete'] = True
                    collection_documents.update_one(filtre_doc_regeneration, ops)

        except StopIteration as se:
            self.__logger.info("Traitement transactions termine - StopIteration")

        # Purger la Q de notifications de transactions
        # Re-soumettre les notifications pour toutes les transactions non traitees, en ordre de persistance.
        # Inclure notification pour regenerer l'information a date (e.g. trigger des cedules)
        self.gestionnaire.resoumettre_transactions()

        # Mettre a jour le document de regeneration pour indiquer que toutes les operations sont completes
        ops = {'$set': {'regeneration_completee': True}}
        collection_documents.update_one(filtre_doc_regeneration, ops, upsert=True)

        # Reconnecter les Q
        if stop_consuming:
            self.gestionnaire.setup_rabbitmq()

    def traiter_transaction_wrapper(self, transaction):
        erreurs_regeneration = []
        idmg = self.configuration.idmg
        try:
            self.traiter_transaction(transaction)
        except Exception as e:
            uuid = 'N/A'
            date_traitement = 'N/A'
            domaine_transactions = 'N/A'
            try:
                en_tete = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
                uuid = en_tete[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
                domaine_transactions = en_tete[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]
                date_traitement = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT][idmg][Constantes.EVENEMENT_TRANSACTION_TRAITEE]
            except Exception as e2:
                uuid = transaction
            finally:
                self.__logger.warning("Erreur regeneration transaction: %s, domaine: %s, date: %s" % (
                    uuid, domaine_transactions, str(date_traitement)))
                self.__logger.exception("Erreur")
                erreur = {
                    Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: uuid,
                    Constantes.EVENEMENT_TRANSACTION_TRAITEE: date_traitement,
                    'erreur': e
                }
                erreurs_regeneration.append(erreur)

        return erreurs_regeneration

    def traiter_transaction(self, transaction):
        """
        Traite la transaction pour simuler la reception et sauvegarde initiale
        :param transaction:
        :return:
        """
        self.__logger.debug("Traitement transaction %s" % transaction[Constantes.MONGO_DOC_ID])

        # Identifier le processus pour cette transaction
        id_transaction = transaction[Constantes.MONGO_DOC_ID]
        en_tete = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
        domaine_transaction = en_tete[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]
        uuid_transaction = en_tete[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
        nom_processus = self._gestionnaire.identifier_processus(domaine_transaction)
        classe_processus = self.identifier_processus({Constantes.PROCESSUS_DOCUMENT_LIBELLE_PROCESSUS: nom_processus})

        processus_parametres = {
            Constantes.EVENEMENT_MESSAGE_EVENEMENT: Constantes.EVENEMENT_TRANSACTION_PERSISTEE,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE: domaine_transaction,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_ID_MONGO: id_transaction,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: uuid_transaction,
        }
        instance_processus = classe_processus(self, processus_parametres)

        # Executer le processus
        instance_processus.traitement_regenerer(id_transaction, processus_parametres)

    def message_etape_suivante(self, id_document_processus, nom_processus, nom_etape, tokens=None):
        pass  # Aucun effet.

    def transmettre_message_resumer(self, id_document_declencheur, tokens: list, id_document_processus_attente=None):
        pass  # Aucun effet

    def transmettre_message_continuer(self, id_document_processus, tokens=None):
        if tokens:
            for token in tokens:
                try:
                    transaction_a_resumer = self._transactions_resumer[token]
                    uuid_transaction = transaction_a_resumer[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
                    self.__logger.debug("Resumer traitement transaction %s" % uuid_transaction)
                    self.traiter_transaction_wrapper(transaction_a_resumer)
                except KeyError:
                    # Aucune transaction correspondante
                    pass
        pass  # Aucun effet

    @property
    def connectionmq_publisher(self):
        return DummyConnexion()


class DummyConnexion:

    def __init__(self):
        pass

    def channel(self):
        pass


class MGProcessus:

    """
    Classe de processus MilleGrilles. Continent des methodes qui representes les etapes du processus.

    :param controleur: Controleur de processus qui appelle l'etape
    :param evenement: Message recu qui a declenche l'execution de cette etape
    """
    def __init__(self, controleur: MGPProcesseur, evenement):
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
        self._requete = None
        self._commande_blocking = None
        self._tokens_connectes = None
        self._messages_a_transmettre = list()
        self._blocking = False  # Toggle pour indiquer qu'on doit attendre un evenement deja en vol

        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

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

    def transmettre_message_etape_suivante(self, parametres=None):
        """'
        Prepare un message qui peut etre mis sur la Q de MGPProcessus pour declencher l'execution de l'etape suivante.

        :returns: Libelle identifiant l'etape suivante a executer.
        """
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

    def transmettre_message_verifier_resumer(self):
        """'
        Prepare un message qui peut etre mis sur la Q de MGPProcessus pour declencher l'execution de l'etape suivante.

        :returns: Libelle identifiant l'etape suivante a executer.
        """
        # Verifier que l'etape a ete executee avec succes.
        if not self._etape_complete or self._etape_suivante is None:
            raise ErreurEtapePasEncoreExecutee("L'etape n'a pas encore ete executee ou l'etape suivante est inconnue")

        self._controleur.transmettre_message_verifier_resumer(
            self._document_processus[Constantes.MONGO_DOC_ID],
            self._ajouter_token_attente
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

            # Verifier si on peut eviter d'attenre des tokens
            # Note: Cause problemes, c'est mieux d'attendre la verification async transmettre_message_verifier_resumer()
            # self.verifier_attendre_token()

            # Ajouter tokens pour synchronisation inter-transaction.
            tokens = {}
            if self._ajouter_token_resumer is not None:
                tokens[Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKEN_RESUMER] = self._ajouter_token_resumer
                self.marquer_evenement_transaction_token(Constantes.EVENEMENT_TOKEN_RESUMER, self._ajouter_token_resumer)
            if self._ajouter_token_attente is not None:
                tokens[Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKEN_ATTENTE] = self._ajouter_token_attente
                self.marquer_evenement_transaction_token(Constantes.EVENEMENT_TOKEN_ATTENTE, self._ajouter_token_attente)
            if self._tokens_connectes is not None:
                tokens[Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKEN_CONNECTES] = self._tokens_connectes
                # self.marquer_evenement_transaction_token(Constantes.EVENEMENT_TOKEN_RESUMER, self._tokens_connectes)
            if len(tokens) > 0:
                document_etape[Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKENS] = tokens

            if self._requete:
                document_etape['_requete'] = self._requete

            self._controleur.sauvegarder_etape_processus(
                self.get_collection_processus_nom(), id_document_processus, document_etape, self._etape_suivante)

            # Transmettre les transactions et les commandes
            if self._messages_a_transmettre is not None:
                for message in self._messages_a_transmettre:
                    if message['type'] == 'commande':
                        self.controleur.generateur_transactions.transmettre_commande(
                            message['contenu'], message['domaine'],
                            correlation_id=str(self.document_processus['_id']),
                            reply_to='%s.evenements' % self.controleur.gestionnaire.get_nom_queue()
                        )
                        if message.get('blocking') and self._requete is None:
                            self._commande_blocking = message['domaine']
                    elif message['type'] == 'transaction':
                        self.controleur.generateur_transactions.soumettre_transaction(
                            message['contenu'], message['domaine'])
                        if message.get('blocking') and self._requete is None:
                            self._commande_blocking = message['domaine']

            # Transmettre la requete inter-domaine, au besoin
            if self._requete is not None:
                self.generateur_transactions.transmettre_requete(
                    self._requete['requete'],
                    self._requete['domaine'],
                    str(self.document_processus['_id']),
                    '%s.evenements' % self.controleur.gestionnaire.get_nom_queue()
                )

            # Verifier s'il faut transmettre un message pour continuer le processus ou s'il est complete.
            if self._requete is not None or self._commande_blocking is not None:
                pass  # Arrete traitement pour attendre reponse
            elif self._blocking:
                pass  # On doit attendre un evenement deja en vol (e.g. commande, requete)
            elif self._ajouter_token_resumer is not None:
                self._controleur.transmettre_message_resumer(
                    id_document_processus, self._ajouter_token_resumer)
            elif not self._processus_complete and self._ajouter_token_attente is None:
                # self._logger.debug("Continuer %s" % self.parametres['_id-transaction'])
                self.transmettre_message_etape_suivante(resultat)
            elif self._ajouter_token_attente is not None:
                self.__logger.debug("Verifier si continuer/resumer %s" % self.parametres.get('_id-transaction'))
                self.transmettre_message_verifier_resumer()

            # Verifier s'il faut avertir d'autres processus que le traitement de l'etape est complete
            if self._evenement.get('resumer_token') is not None:
                info_tokens_resume = self._evenement['resumer_token']
                id_document_processus = info_tokens_resume.get('processus')
                self.__logger.debug("Transmission message terminer processus resumer tokens %s" % id_document_processus)
                self._controleur.transmettre_message_continuer(
                    id_document_processus,
                    {'processus': id_document_processus, 'tokens': info_tokens_resume.get('tokens')}
                )

        except ErreurEtapeInconnue as eei:
            # Verifier si c'est un evenement de "resumer" pour ce processus
            # Ces evenements sont transmis de maniere redondante, simplifie la synchronisation
            erreur_ok = False
            info_evenement = self._evenement.get(Constantes.PROCESSUS_DOCUMENT_LIBELLE_INFO)
            if info_evenement:
                id_processus_resume = info_evenement.get(Constantes.PROCESSUS_DOCUMENT_LIBELLE_PROCESSUS)
                if id_processus_resume == self._evenement.get(
                        Constantes.PROCESSUS_MESSAGE_LIBELLE_ID_DOC_PROCESSUS):
                    erreur_ok = True

            if not erreur_ok:
                raise eei

        except ErreurOptimisticLocking:
            self.__logger.info("Echec optimistic locking, on abandonne le travail pour cette thread")

        except CertificatInconnu as ce:
            fingerprint = ce.fingerprint
            self.__logger.info("Certificat inconnu, on demande %s" % ce.fingerprint)
            # Emettre demande pour le certificat manquant
            self._controleur.contexte.message_dao.transmettre_demande_certificat(fingerprint)

        except Exception as erreur:
            # Erreur inconnue. On va assumer qu'elle est fatale.
            # if self.__logger.isEnabledFor(logging.DEBUG):
            self.__logger.exception("Erreur traitement processus")
            self._controleur.erreur_fatale(id_document_processus=id_document_processus, erreur=erreur, processus=self)

    def initiale(self):
        """
        Methode initiale, doit etre implementee par la sous-classe
        :return:
        """
        raise NotImplemented("La methode initiale doit etre implementee par la sous-classe")

    def finale(self):
        """
        Implementation de reference pour l'etape finale. Peut etre modifiee par la sous-classe au besoin.
        :return:
        """
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

        params_copy = self.parametres.copy()
        params_copy.update(resultat)

        # Verifier si on doit transmettre une notification de traitement termine
        properties = self.parametres.get('properties')
        if properties is not None:
            # Verifier si on a reply_to et correlation_id pour transmettre une confirmation de traitement
            if properties.get('reply_to') is not None and properties.get('correlation_id') is not None:
                generateur_transactions = self._controleur.generateur_transactions
                generateur_transactions.transmettre_reponse(
                    params_copy, properties['reply_to'], properties['correlation_id'])
                resultat['reponse_transmise'] = True

        logging.debug("Etape finale executee pour %s" % self.__class__.__name__)
        return resultat

    def traitement_regenerer(self, id_transaction, parametres_processus):
        """
        Execute toutes les etapes d'un processus deja traiter avec succes. Sert a regenerer le document.
        :return:
        """
        etape_execution = 'initiale'  # Commencer l'execution apres orientation (qui n'a aucun effet)

        self._document_processus = {
            Constantes.PROCESSUS_MESSAGE_LIBELLE_PARAMETRES: parametres_processus
        }

        nombre_etapes_executees = 0
        while not self._processus_complete:
            nombre_etapes_executees = nombre_etapes_executees + 1

            methode_a_executer = getattr(self, etape_execution)

            # Recuperer les parametres pour la prochaine etape
            resultat = methode_a_executer()
            if resultat is not None:
                parametres_processus.update(resultat)  # On fait juste cumuler les parametres pour la prochaine etape

            # Identifier prochaine etape, reset etat
            etape_execution = self._etape_suivante
            self._etape_suivante = None
            self._etape_complete = False

            if self._ajouter_token_attente:
                for token in self._ajouter_token_attente:
                    controleur = self.controleur
                    transaction_resumer = controleur.consommer_transaction_resumer(token)
                    if transaction_resumer:
                        uuid_transaction_resumer = transaction_resumer[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
                        self.__logger.debug("Resumer transaction apres attente : %s" % uuid_transaction_resumer)
                        controleur.traiter_transaction_wrapper(transaction_resumer)

            # if self._ajouter_token_resumer is not None:
            #     self._logger.debug("Resumer transaction token %s" % self._ajouter_token_resumer)

            if nombre_etapes_executees > 100:
                raise Exception("Nombre d'etapes executees > 100, depasse limite")

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

    def set_requete(self, domaine, requete):
        self._requete = {
            'domaine': domaine,
            'requete': requete,
        }

    def resumer_processus(self, tokens: list):
        """
            Ajoute un token pour dire que le processus/transaction du processus est necessaire a un autre processus.
            Va automatiquement transmettre un message qui sera recu par le processus en attente (s'il existe).
        """
        if self._ajouter_token_resumer is None:
            self._ajouter_token_resumer = tokens
        else:
            self._ajouter_token_resumer.extend(tokens)

    def verifier_attendre_token(self):
        """
        Verifie si les tokens existent deja.
        Ajoute un token pour dire que le processus est en attente d'un evenement externe.
        :return: "True, list documents" processus si tous les tokens ont ete trouves. False si pas tous trouves.
        """
        tokens = self._ajouter_token_attente
        if tokens is None:
            return True, None

        # Chercher la collection pour les documents avec les tokens resumes correspondants aux tokens d'attente
        nom_collection_processus = self.get_collection_processus_nom()
        collection_processus = self._controleur.document_dao.get_collection(nom_collection_processus)
        filtre = {
            Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKEN_RESUMER: {"$in": tokens}
        }
        curseur = collection_processus.find(filtre)
        dict_tokens = dict()
        for processus_avec_tokens in curseur:
            resume_tokens = processus_avec_tokens.get(Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKEN_RESUMER)
            for token in resume_tokens:
                dict_tokens[token] = processus_avec_tokens.get(Constantes.MONGO_DOC_ID)

                # Transmettre message au processus pour indiquer qu'il peut continuer
                self._controleur.transmettre_message_continuer(
                    processus_avec_tokens.get(Constantes.MONGO_DOC_ID),
                    {'processus': str(self._document_processus.get(Constantes.MONGO_DOC_ID)), 'tokens': tokens}
                )

        # Conserver les tokens qui ont ete trouves
        if len(dict_tokens) > 0:
            self._tokens_connectes = dict_tokens

        tokens_restants = list()
        for token in tokens:
            if token not in dict_tokens.keys():
                tokens_restants.append(token)

        if len(tokens_restants) > 0:
            self._ajouter_token_attente = tokens_restants
        else:
            self._ajouter_token_attente = None

        return len(tokens_restants) == 0, dict_tokens

    def ajouter_commande_a_transmettre(self, domaine, commande, blocking=False):
        commande = {
            'type': 'commande',
            'domaine': domaine,
            'contenu': commande,
        }
        if blocking:
            commande['blocking'] = True
        self._messages_a_transmettre.append(commande)

    def ajouter_transaction_a_soumettre(self, domaine, transaction, blocking=False):
        transaction = {
            'type': 'transaction',
            'domaine': domaine,
            'contenu': transaction,
        }
        if blocking:
            transaction['blocking'] = True
        self._messages_a_transmettre.append(transaction)

    def set_blocking(self):
        """
        Inique qu'on doit attendre une reponse (d'une requete/commande DEJA emise)
        :return:
        """
        self._blocking = True

    def get_transaction_token_connecte(self, token):
        """
        Retourne la transaction qui s'est connectee via un token resumer
        :param token:
        :return:
        """
        self.__logger.debug("Charger transaction par token %s" % token)
        tokens = self._document_processus.get(Constantes.PROCESSUS_DOCUMENT_LIBELLE_TOKEN_CONNECTES)
        if tokens is not None:
            id_processus_connecte = tokens.get(token)
            self.__logger.debug("id processus connecte %s" % id_processus_connecte)
            if id_processus_connecte is not None:
                self.__logger.debug("Chargement de la transaction connectee via processus %s: %s" % (
                    token, str(id_processus_connecte)))
                nom_collection_processus = self.get_collection_processus_nom()
                collection_processus = self.controleur.document_dao.get_collection(nom_collection_processus)
                processus_connecte = collection_processus.find_one({'_id': id_processus_connecte})

                self.__logger.debug("Chargement processus connecte: %s" % str(processus_connecte))

                # Obtenir l'_id de la transaction
                id_transaction_connectee = processus_connecte[
                    Constantes.PROCESSUS_DOCUMENT_LIBELLE_PARAMETRES][Constantes.TRANSACTION_MESSAGE_LIBELLE_ID_MONGO]
                self.__logger.debug("ID Transaction connectee: %d" % id_transaction_connectee)
                id_transaction_connectee = ObjectId(id_transaction_connectee)

                nom_collection_transaction = self.get_collection_transaction_nom()
                collection_transactions = self.controleur.document_dao.get_collection(nom_collection_transaction)
                transaction_connectee = collection_transactions.find_one({'_id': id_transaction_connectee})

                return transaction_connectee

        return None

    def sauvegarder_consignationfichiers(self, fp, nom_fichier, mimetype: str = 'application/data', etiquettes: list = None, securite: str = Constantes.SECURITE_PRIVE):
        if securite in [Constantes.SECURITE_PROTEGE, Constantes.SECURITE_SECURE]:
            raise Exception("Support de fichiers cryptes non implemente")

        # Preparer le fichier
        BUF_SIZE = 65535
        sha256 = hashlib.sha256()

        taille_fichier = 0
        while True:
            data = fp.read(BUF_SIZE)
            taille_fichier = taille_fichier + len(data)
            if not data:
                break
            sha256.update(data)
        sha256_digest = sha256.hexdigest()

        # Reset fp a 0 pour upload
        fp.seek(0)

        fuuid = uuid.uuid1()
        consignationfichiers_host = self.controleur.configuration.serveur_consignationfichiers_host
        consignationfichiers_port = self.controleur.configuration.serveur_consignationfichiers_port
        adresse_serveur = '%s:%s' % (consignationfichiers_host, consignationfichiers_port)
        crypte = 'false'
        if securite in [Constantes.SECURITE_PROTEGE, Constantes.SECURITE_SECURE]:
            crypte = 'true'
        path_upload = 'https://%s/grosfichiers/local/nouveauFichier/%s' % (adresse_serveur, fuuid)
        headers = {
            'encrypte': crypte,
            'fileuuid': str(fuuid),
            'nomfichier': nom_fichier,
            'mimetype': mimetype,
        }

        response = requests.put(
            path_upload, fp, headers=headers,
            verify=self.controleur.configuration.pki_cafile,
            cert=(self.controleur.configuration.pki_certfile, self.controleur.configuration.pki_keyfile)
        )

        # Comparer hash server et celui calcule localement
        sha256_digest_serveur = response.json()['sha256Hash']
        if sha256_digest != sha256_digest_serveur:
            raise Exception("Erreur upload fichier, SHA256 different")

        transaction_nouveau = {
            'fuuid': str(fuuid),
            'securite': securite,
            'nom': nom_fichier,
            'taille': taille_fichier,
            'mimetype': mimetype,
            'sha256': sha256_digest,
        }

        if etiquettes is not None:
            transaction_nouveau['etiquettes'] = etiquettes

        self.ajouter_transaction_a_soumettre(
            Constantes.ConstantesGrosFichiers.TRANSACTION_NOUVELLEVERSION_METADATA, transaction_nouveau)

        return fuuid

    @property
    def document_dao(self):
        return self._controleur.document_dao

    @property
    def message_dao(self):
        return self._controleur.message_dao

    @property
    def generateur_transactions(self):
        return self._controleur.generateur_transactions

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

    @property
    def get_collection_documents(self):
        return self._controleur.get_collection_documents

    @property
    def get_collection_transaction_nom(self):
        return self._controleur.get_collection_transaction_nom

    @property
    def get_collection_processus_nom(self):
        return self._controleur.collection_processus_nom

    @property
    def controleur(self) -> MGPProcesseur:
        return self._controleur

    def marquer_evenement_transaction_token(self, type_token, token):
        """
        Hook pour sous-classes
        :param type_token:
        :param token:
        :return:
        """
        pass


# Classe de processus pour les transactions. Contient certaines actions dans finale() pour marquer la transaction
# comme ayant ete completee.
class MGProcessusTransaction(MGProcessus):

    def __init__(self, controleur: MGPProcesseur, evenement, transaction_mapper=None):
        super().__init__(controleur, evenement)

        self._transaction_mapper = transaction_mapper
        self._transaction = None
        self._certificat = None

        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def trouver_id_transaction(self):
        parametres = self.parametres
        collection = self.get_collection_transaction_nom()
        transaction = None
        try:
            id_transaction = parametres[Constantes.TRANSACTION_MESSAGE_LIBELLE_ID_MONGO]
        except KeyError:
            try:
                uuid_transaction = parametres[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
                transaction = self._controleur.charger_transaction_par_uuid(uuid_transaction, collection)
                id_transaction = transaction['_id']
                parametres[Constantes.TRANSACTION_MESSAGE_LIBELLE_ID_MONGO] = id_transaction
            except KeyError:
                # Le processus n'est pas pour une transaction
                return {'nom_collection': collection, 'transaction': transaction}

        return {'id_transaction': id_transaction, 'nom_collection': collection, 'transaction': transaction}

    def charger_transaction(self, nom_collection=None):
        if nom_collection is None:
            nom_collection = self.get_collection_transaction_nom()

        info_transaction = self.trouver_id_transaction()
        id_transaction = info_transaction['id_transaction']
        self._transaction = self._controleur.charger_transaction_par_id(id_transaction, nom_collection)
        try:
            # Verifier la transaction. Utilise idmg et date (estampille) du message pour permettre
            # de regenerer les transactions.
            self._certificat = self._controleur.gestionnaire.validateur_message.verifier(
                self._transaction, utiliser_date_message=True, utiliser_idmg_message=True)

            if self.verifier_autorisation() is False:
                raise Exception("Echec autorisation pour transaction %s", id_transaction)

        except AutorisationConditionnelleDomaine as acd:
            domaine = self._transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]
            if domaine not in acd.domaines:
                raise acd

        if self._transaction_mapper is not None:
            # Faire le mapping de la transaction en fonction de sa version
            self._transaction_mapper.map_version_to_current(self._transaction)

        return self._transaction

    def finale(self):
        # Ajouter l'evenement 'traitee' dans la transaction
        self.marquer_transaction_traitee()
        return super().finale()

    ''' Ajoute l'evenement 'traitee' dans la transaction '''
    def marquer_transaction_traitee(self):
        self.marquer_evenement_transaction(Constantes.EVENEMENT_TRANSACTION_TRAITEE)

    def marquer_transaction_intraitable(self):
        self.marquer_evenement_transaction(Constantes.EVENEMENT_TRANSACTION_ERREUR_TRAITEMENT)

    def marquer_evenement_transaction(self, evenement):
        info_transaction = self.trouver_id_transaction()
        id_transaction = info_transaction.get('id_transaction')
        nom_collection = info_transaction['nom_collection']

        evenement_message = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT: Constantes.EVENEMENT_MESSAGE_EVENEMENT,
            Constantes.MONGO_DOC_ID: id_transaction,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE: nom_collection,
            Constantes.EVENEMENT_MESSAGE_EVENEMENT: evenement,
            Constantes.EVENEMENT_MESSAGE_EVENEMENT_TIMESTAMP: datetime.datetime.utcnow().timestamp(),
        }
        routing = 'evenement.%s.transactionEvenement' % self.controleur.get_collection_transaction_nom()

        self._controleur.message_dao.transmettre_message_exchange(evenement_message, routing, exchange=Constantes.SECURITE_SECURE)

    def marquer_evenement_transaction_token(self, type_token, token):
        info_transaction = self.trouver_id_transaction()
        id_transaction = info_transaction.get('id_transaction')
        nom_collection = info_transaction['nom_collection']

        evenement = {
            Constantes.MONGO_DOC_ID: id_transaction,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE: nom_collection,
            Constantes.EVENEMENT_MESSAGE_TYPE_TOKEN: type_token,
            Constantes.EVENEMENT_MESSAGE_EVENEMENT_TOKEN: token,
            Constantes.EVENEMENT_MESSAGE_EVENEMENT_TIMESTAMP: datetime.datetime.utcnow().timestamp(),
        }
        self._controleur.message_dao.transmettre_message(evenement, Constantes.TRANSACTION_ROUTING_EVENEMENTTOKEN,
                                                         channel=self.controleur.connectionmq_publisher.channel)

    @property
    def transaction(self):
        if self._transaction is None:
            self._transaction = self.charger_transaction()

        return self._transaction

    @property
    def transaction_filtree(self):
        """
        Enleve les champs de metadonnees et l'entete
        :return:
        """

        transaction = self.transaction

        transaction_filtree = dict()
        for key, value in transaction.items():
            if not key.startswith('_') and key != Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE:
                transaction_filtree[key] = value

        return transaction_filtree

    @property
    def certificat(self):
        if self._certificat is None:
            self.charger_transaction()
        return self._certificat

    def verifier_autorisation(self):
        """ Verifier l'autorisation d'execution de la transaction """
        return True


class MGProcessusDocInitial(MGProcessusTransaction):

    def __init__(self, controleur: MGPProcesseur, evenement, transaction_mapper=None):
        super().__init__(controleur, evenement, transaction_mapper)

    def initiale(self):
        transaction = self.transaction
        document = transaction[Constantes.DOCUMENT_INFODOC_SOUSDOCUMENT]

        on_insert = document.copy()
        on_insert[Constantes.DOCUMENT_INFODOC_DATE_CREATION] = datetime.datetime.utcnow()
        mg_libelle = document[Constantes.DOCUMENT_INFODOC_LIBELLE]
        operations = {
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
            '$setOnInsert': on_insert
        }

        collection_documents = self._controleur.get_collection_documents()
        collection_documents.update_one({Constantes.DOCUMENT_INFODOC_LIBELLE: mg_libelle}, operations, upsert=True)

        self.set_etape_suivante()  # Termine


class MGProcessusUpdateDoc(MGProcessusTransaction):

    def __init__(self, controleur: MGPProcesseur, evenement, transaction_mapper=None):
        super().__init__(controleur, evenement, transaction_mapper)

    def initiale(self):
        transaction = self.transaction

        document = transaction[Constantes.DOCUMENT_INFODOC_SOUSDOCUMENT]
        mg_libelle = document[Constantes.DOCUMENT_INFODOC_LIBELLE]
        del document[Constantes.DOCUMENT_INFODOC_LIBELLE]
        operations = {
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
            '$set': document,
            '$setOnInsert': {
                Constantes.DOCUMENT_INFODOC_LIBELLE: mg_libelle
            }
        }

        collection_documents = self._controleur.get_collection_documents()
        collection_documents.update_one({Constantes.DOCUMENT_INFODOC_LIBELLE: mg_libelle}, operations, upsert=True)

        self.set_etape_suivante()  # Termine


# Classe qui sert a demarrer un processus
class MGPProcessusDemarreur:

    def __init__(self, contexte, nom_domaine: str, collection_transaction_nom: str, collection_processus_nom: str,
                 traitement_processus: MGPProcesseurTraitementEvenements, gestionnaire=None):
        self._contexte = contexte
        self._json_helper = JSONHelper()

        self._nom_domaine = nom_domaine
        self._collection_transaction_nom = collection_transaction_nom
        self._collection_processus_nom = collection_processus_nom
        self._traitement_processus = traitement_processus
        self.__gestionnaire = gestionnaire

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
            collection_processus = self._contexte.document_dao.get_collection(self._collection_processus_nom)
            id_doc_processus = self._traitement_processus.sauvegarder_initialisation_processus(
                collection_processus, moteur, processus_a_declencher, dictionnaire_evenement)

            channel = None
            if self.__gestionnaire is not None:
                channel = self.__gestionnaire.channel_mq

            self._contexte.message_dao.transmettre_evenement_mgpprocessus(
                self._nom_domaine, id_doc_processus, nom_processus=processus_a_declencher, channel=channel
            )

        except Exception as erreur:
            # Erreur inconnue. On va assumer qu'elle est fatale.
            self._logger.exception("Erreur demarrage processus")
            self._contexte.message_dao.transmettre_erreur_transaction(id_document=id_document, detail=erreur)


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
        super().__init__(message)


class ErreurProcessusComplet(Exception):
    pass


class ErreurOptimisticLocking(Exception):
    pass

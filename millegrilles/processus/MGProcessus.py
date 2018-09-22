# Module de processus pour MilleGrilles
import signal

from millegrilles import Constantes
from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.DocumentDAO import MongoDAO
from millegrilles.dao.MessageDAO import PikaDAO, BaseCallback, JSONHelper

'''
Controleur des processus MilleGrilles. Identifie et execute les processus.

MGPProcessus = MilleGrilles Python Processus. D'autres controleurs de processus peuvent etre disponibles.

'''


class MGPProcessusControleur(BaseCallback):

    def __init__(self):
        super().__init__()

        self._json_helper = JSONHelper()

        self._configuration = TransactionConfiguration()
        self._document_dao = None
        self._message_dao = None

    def initialiser(self):
        self._configuration.loadEnvironment()
        self._document_dao = MongoDAO(self._configuration)
        self._message_dao = PikaDAO(self._configuration)

        # Connecter les DAOs
        self._document_dao.connecter()
        self._message_dao.connecter()

        # Executer la configuration pour RabbitMQ
        self._message_dao.configurer_rabbitmq()

    def deconnecter(self):
        self._document_dao.deconnecter()
        self._message_dao.deconnecter()
        print("Deconnexion completee")

    '''
    Methode qui demarre la lecture des evenements sur la Q de processus.
    '''
    def executer(self):
        self._message_dao.demarrer_lecture_etape_processus(self.callbackAvecAck)

    '''
    Callback pour chaque evenement. Gere l'execution d'une etape a la fois.
    '''
    def traiter_message(self, ch, method, properties, body):

        id_doc_processus = None
        try:
            # Decoder l'evenement qui contient l'information sur l'etape a traiter
            evenement_dict = self.extraire_evenement(body)
            id_doc_processus = evenement_dict.get(Constantes.PROCESSUS_MESSAGE_LIBELLE_ID_DOC_PROCESSUS)
            #print("Recu evenement processus: %s" % str(evenement_dict))
            self.traiter_evenement(evenement_dict)
        except Exception as e:
            # Mettre le message d'erreur sur la Q erreur processus
            self.erreur_fatale(id_doc_processus, str(body), e)

    '''
    Lit l'evenement JSON est retourne un dictionnaire avec toute l'information.
    
    :returns: Dictionnaire de tout le contenu de l'evenement.
    '''
    def extraire_evenement(self, message_body):
        # Extraire le message qui devrait etre un document JSON
        message_dict = self._json_helper.bin_utf8_json_vers_dict(message_body)
        return message_dict

    '''
    Execute une etape d'un processus. La classe MGProcessus est responsable de l'orchestration.
    '''
    def traiter_evenement(self, evenement):
        classe_processus = self.identifier_processus(evenement)
        instance_processus = classe_processus(self, evenement)
        instance_processus.traitement_etape()

    """
    Identifie le processus a executer, retourne une instance si le processus est trouve.
    
    :returns: Instance MGPProcessus si le processus est trouve. 
    :raises ErreurProcessusInconnu: Si le processus est inconnu.  
    """
    def identifier_processus(self, evenement):
        nom_processus = evenement.get(Constantes.PROCESSUS_DOCUMENT_LIBELLE_PROCESSUS)
        nom_module, nom_classe = nom_processus.split('.')
        #print('Importer %s, %s' % (nom_module, nom_classe))
        module_processus = __import__('millegrilles.processus.%s' % nom_module, fromlist=nom_classe)
        classe_processus = getattr(module_processus, nom_classe)
        return classe_processus

    def charger_transaction_par_id(self, id_transaction):
        return self._document_dao.charger_transaction_par_id(id_transaction)

    def charger_document_processus(self, id_document_processus):
        return self._document_dao.charger_processus_par_id(id_document_processus)

    def sauvegarder_etape_processus(self, id_document_processus, dict_etape, etape_suivante=None):
        self._document_dao.sauvegarder_etape_processus(id_document_processus, dict_etape, etape_suivante)

    def message_etape_suivante(self, id_document_processus, nom_processus, nom_etape):
        self._message_dao.transmettre_evenement_mgpprocessus(id_document_processus, nom_processus, nom_etape)

    def transaction_helper(self):
        return self._document_dao.transaction_helper()

    def preparer_document_helper(self, collection, classe):
        helper = classe(self._document_dao.get_collection(collection))
        return helper

    """ 
    Lance une erreur fatale pour ce message. Met l'information sur la Q d'erreurs. 
    
    :param message: Le message pour lequel l'erreur a ete generee.
    :param nom_etape: Nom complet de l'etape qui a genere l'erreur.
    :param detail_erreur: Optionnel, objet ErreurExecutionEtape.
    """
    def erreur_fatale(self, id_document_processus, message_original=None, erreur=None):
        self._message_dao.transmettre_erreur_processus(
            id_document_processus=id_document_processus, message_original=message_original, detail=erreur)


class MGProcessus:

    """
    Classe de processus MilleGrilles. Continent des methodes qui representes les etapes du processus.

    :param controleur: Controleur de processus qui appelle l'etape
    :param message: Message recu qui a declenche l'execution de cette etape
    """
    def __init__(self, controleur, evenement):
        if controleur is None or evenement is None:
            raise Exception('controleur et evenement ne doivent pas etre None')

        self._controleur = controleur
        self._evenement = evenement

        self._document_processus = None
        self._etape_suivante = None
        self._etape_complete = False
        self._methode_etape_courante = None
        self._processus_complete = False

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
            raise ErreurEtapeInconnue("etape-suivante est manquante sur evenement pour classe %s: %s" % (self.__class__.__name__, self._evenement))
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
        nom_module_tronque = self.__module__.split('.')[2]
        nom_classe = self.__class__.__name__
        nom_processus = '%s.%s' % (nom_module_tronque, nom_classe)

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

        id_document_processus=None
        try:
            # Charger le document du processus
            id_document_processus = self._evenement[Constantes.PROCESSUS_MESSAGE_LIBELLE_ID_DOC_PROCESSUS]
            self._document_processus = self._controleur.charger_document_processus(id_document_processus)

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
            self._controleur.sauvegarder_etape_processus(id_document_processus, document_etape, self._etape_suivante)

            # Verifier s'il faut transmettre un message pour continuer le processus ou s'il est complete.
            if not self._processus_complete:
                self.transmettre_message_etape_suivante(resultat)

        except Exception as erreur:
            # Erreur inconnue. On va assumer qu'elle est fatale.
            self._controleur.erreur_fatale(id_document_processus=id_document_processus, erreur=erreur)


    '''
    Implementation de reference pour l'etape finale. Peut etre modifiee par la sous-classe au besoin.
    '''
    def finale(self):
        self._etape_complete = True
        self._processus_complete = True
        #print("Etape finale executee pour %s" % self.__class__.__name__)

    def erreur_fatale(self, detail=None):
        self._etape_complete = True
        self._processus_complete = True
        print("Erreur fatale - voir Q")

        information = None
        if detail is not None:
            information = {'erreur': detail}
        return information

    '''
    Utiliser cette methode pour indiquer quelle est la prochaine etape a executer.
    
    :param etape_suivante: Prochaine etape (methode) a executer. Par defaut utilise l'etape finale qui va terminer le processus.
    '''
    def set_etape_suivante(self, etape_suivante='finale'):
        self._etape_complete = True
        self._etape_suivante = etape_suivante

'''
Classe de processus pour les transactions. Contient certaines actions dans finale() pour marquer la transaction
comme ayant ete completee.
'''
class MGProcessusTransaction(MGProcessus):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

        self._transaction = None

    def trouver_id_transaction(self):
        id_transaction = self._document_processus[Constantes.PROCESSUS_MESSAGE_LIBELLE_PARAMETRES][
            Constantes.TRANSACTION_MESSAGE_LIBELLE_ID_MONGO]
        return id_transaction

    def charger_transaction(self):
        id_transaction = self.trouver_id_transaction()
        self._transaction = self._controleur.charger_transaction_par_id(id_transaction)
        return self._transaction

    def finale(self):
        # Ajouter l'evenement 'traitee' dans la transaction
        self.marquer_transaction_traitee()
        super().finale()

    ''' Ajoute l'evenement 'traitee' dans la transaction '''
    def marquer_transaction_traitee(self):
        id_transaction = self.trouver_id_transaction()
        helper = self._controleur.transaction_helper()
        helper.ajouter_evenement_transaction(id_transaction, Constantes.EVENEMENT_TRANSACTION_TRAITEE)

    def marquer_transaction_incomplete(self):
        pass

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

# --- MAIN ---


controleur = MGPProcessusControleur()

def exit_gracefully(signum, frame):
    print("Arret de MGProcessusControleur")
    controleur.deconnecter()

def main():

    print("Demarrage de MGProcessusControleur")

    signal.signal(signal.SIGINT, exit_gracefully)
    signal.signal(signal.SIGTERM, exit_gracefully)

    controleur.initialiser()

    try:
        print("MGProcessusControleur est pret")
        controleur.executer()
    finally:
        exit_gracefully(None, None)

    print("MGProcessusControleur est arrete")

if __name__=="__main__":
    main()

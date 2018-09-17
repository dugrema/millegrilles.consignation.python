# Module de processus pour MilleGrilles
from millegrilles import Constantes

'''
Controleur des processus MilleGrilles. Identifie et execute les processus.

MGPProcessus = MilleGrilles Python Processus. D'autres controleurs de processus peuvent etre disponibles.

'''


class MGPProcessusControleur:

    def __init__(self):
        self.document_dao = None
        self.message_dao = None

    """
    Identifie le processus a executer, retourne une instance si le processus est trouve.
    
    :returns: Instance MGPProcessus si le processus est trouve. 
    :raises ErreurProcessusInconnu: Si le processus est inconnu.  
    """
    def identifier_processus(self, message):
        pass

    """
    Demarre le processus - execute la premiere etape d'un processus.
    
    :param nom_processus: Nom du processus a initialiser.
    :param message: Le message recu sur la Q, devrait contenir les identificateurs necessaires au
                    demarrage du processus.
    """
    def demarrer_processus(self, nom_prcessus, message):
        pass

    """ 
    Lance une erreur fatale pour ce message. Met l'information sur la Q d'erreurs. 
    
    :param message: Le message pour lequel l'erreur a ete generee.
    :param nom_etape: Nom complet de l'etape qui a genere l'erreur.
    :param detail_erreur: Optionnel, objet ErreurExecutionEtape.
    """
    def erreur_fatale(self, message, nom_etape, detail_erreur=None):
        pass


class MGProcessus:

    """
    Classe de processus MilleGrilles. Continent des methodes qui representes les etapes du processus.

    :param controleur: Controleur de processus qui appelle l'etape
    :param nom_complet: Nom complet du processus (celui identifie dans le dictionnaire des processus)
    :param message: Message recu qui a declenche l'execution de cette etape
    """
    def __init__(self, controleur, nom_complet, message):
        self._controleur = controleur
        self._nom_complet = nom_complet
        self._message = message
        self._etape_suivante = None
        self._etape_complete = False

    '''
    Prepare un message qui peut etre mis sur la Q de MGPProcessus pour declencher l'execution de l'etape suivante.
    
    :returns: Libelle identifiant l'etape suivante a executer.
    '''
    def preparer_message_etape_suivante(self):
        if self._etape_suivante is None:
            raise ErreurEtapePasEncoreExecutee("L'etape n'a pas encore ete executee ou l'etape suivante est inconnue")

        # Verifier que l'etape a ete executee avec succes. Retourner etape suivante.
        message = {
            "processus": self._nom_complet,
            "etape": self._etape_suivante
        }

        return message

    """
    Execute l'etape.

    :raises ErreurExecutionEtape: Erreur fatale encontree lors de l'execution de l'etape
    """
    def executer_etape(self):
        self._etape_suivante = Constantes.PROCESSUS_ETAPE_FINALE
        self._etape_complete = True

'''
Exception lancee lorsqu'une etape ne peut plus continuer (erreur fatale).
'''


class ErreurExecutionEtape(Exception):

    def __init__(self, etape):
        super().__init__(self)
        self._etape = etape

    @property
    def etape(self):
        return self._etape

    @property
    def nom_etape(self):
        return self._etape.nom_complet

class ErreurProcessusInconnu(Exception):

    def __init__(self, etape):
        super().__init__(self)

class ErreurEtapePasEncoreExecutee(Exception):

    def __init__(self, etape):
        super().__init__(self)

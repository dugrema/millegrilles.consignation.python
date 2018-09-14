# Module de processus pour MilleGrilles

'''
Controleur des processus MilleGrilles. Connait le deroulement des etapes.

MGPProcessus = MilleGrilles Python Processus. D'autres controleurs de processus peuvent etre disponibles.

'''


class MGPProcessusControleur:

    def __init__(self):
        self.document_dao = None
        self.message_dao = None

    """
    Methode faite pour etre implementee. Retourne un dictionnaire de toutes les etapes avec la liste des
    etapes suivantes pour chaque etape.
    
    :returns: Dictionnaire de toutes les etapes supportees dans ce processus. 
    """
    def initialiser_processus(self):
        None

    """
    Demarre le processus - execute la premiere etape.
    
    :param message: Le message recu sur la Q, devrait contenir les identificateurs necessaires au
                    demarrage du processus.
    """
    def demarrer_procesus(self, message):
        None

    """ 
    Lance une erreur fatale pour ce message. Met l'information sur la Q d'erreurs. 
    
    :param message: Le message pour lequel l'erreur a ete generee.
    :param nom_etape: Nom complet de l'etape qui a genere l'erreur.
    :param detail_erreur: Optionnel, objet ErreurExecutionEtape.
    """
    def erreur_fatale(self, message, nom_etape, detail_erreur=None):
        None


    """
    :returns: Etape initialise prete a etre executee
    """
    def identifier_etape(self, message):
        None


    """
    Methode responsable de l'execution d'une etape et de l'enchainement de la 
    prochaine etape au besoin. S'occupe aussi de toute erreur qui survient durant l'execution
    d'une etape.
    
    :param etape: Etape a executer
    """
    def executer_etape(self, etape):
        None


''' 
Superclasse abstraite pour une etape d'un processus MilleGrilles. 
'''


class MGProcessusEtape:

    """
    :param controleur: Controleur de processus qui appelle l'etape
    :param nom_complet: Nom complet de l'etape (celui identifie dans le dictionnaire du processus
    :param message: Message recu qui a declenche l'execution de cette etape
    """
    def __init__(self, controleur, nom_complet, message):
        self._controleur = controleur
        self.nom_complet = nom_complet
        self.message = message

    """
    Execute l'etape.
    
    :raises ErreurExecutionEtape: Erreur fatale encontree lors de l'execution de l'etape
    """
    def executer(self):
        None


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

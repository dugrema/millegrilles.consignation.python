# Module de processus pour MilleGrilles

'''
Controleur des processus MilleGrilles. Identifie et execute les processus.

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
    def initialiser_liste_processus(self):
        None

    """
    Demarre le processus - execute la premiere etape.
    
    :param message: Le message recu sur la Q, devrait contenir les identificateurs necessaires au
                    demarrage du processus.
    """
    def demarrer_processus(self, message):
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
    :returns: Identifie le processus a executer
    """
    def identifier_processus(self, message):
        None


    """
    Methode responsable de l'execution d'une etape et de l'enchainement de la 
    prochaine etape au besoin. S'occupe aussi de toute erreur qui survient durant l'execution
    d'une etape.
    
    :param etape: Etape a executer
    """
    def executer_etape(self, processus):
        processus.identifier_etape()
        processus.executer_etape()


class MGProcessus:

    """
    :param controleur: Controleur de processus qui appelle l'etape
    :param nom_complet: Nom complet du processus (celui identifie dans le dictionnaire des processus)
    :param message: Message recu qui a declenche l'execution de cette etape
    """
    def __init__(self, controleur, nom_complet, message):
        self._controleur = controleur
        self.nom_complet = nom_complet
        self.message = message

    """
    :returns: Etape initialise prete a etre executee
    """
    def identifier_etape_courante(self):
        self._etape = None


    def identifier_etape_suivante(self):
        # Verifier que l'etape a ete executee avec succes. Retourner etape suivante.
        return None

    """
    Execute l'etape.

    :raises ErreurExecutionEtape: Erreur fatale encontree lors de l'execution de l'etape
    """
    def executer_etape(self):
        self._etape.executer()

    """
    Appeler lorsque l'etape a ete executee avec succes. Identifie la prochaine etape
    et transmet le message pour declencher son execution.
    """
    def preparer_etape_suivante(self):

        libelle_etape = self.identifier_etape_suivante()

        # Creer message sur la Q pour declencher l'execution de la prochaine etape


''' 
Superclasse abstraite pour une etape d'un processus MilleGrilles. 
'''


class MGProcessusEtape:

    """
    :param processus: Classe qui gere le processus
    """
    def __init__(self, processus):
        self.processus = processus
        self._controleur = processus._controleur

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

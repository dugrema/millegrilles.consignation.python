# Module pour les Noeuds (nodes) MilleGrilles

from millegrilles.Domaines import GestionnaireDomaine


class ConstantesNoeuds:

    COLLECTION_NOM = 'domaine_Noeuds'
    QUEUE_NOM = 'domaine.Noeuds'


class GestionnaireNoeuds(GestionnaireDomaine):
    """ Gestionnaire du domaine des noeuds MilleGrilles """

    def __init__(self, contexte):
        super().__init__(contexte)

    def traiter_transaction(self, ch, method, properties, body):
        pass

    def get_nom_queue(self):
        return ConstantesNoeuds.QUEUE_NOM

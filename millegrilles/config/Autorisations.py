# Contients des configurations sous forme de constantes

class ConstantesAutorisation:
    REGLE_DOMAINEACTIONS_PERMIS = 'domaineactions_permis'  # Domaine-actions toujours permis (date = message)
    REGLE_SIGNATURE_AUTORISATIONS = 'signature_autorisations'  # Domaine-actions toujours permis (date = message)


_autorisations_idmg = {
    "version:": 1,
    "z2W2ECnP9eauNXD628aaiURj6tJfSYiygTaffC1bTbCNHCtomhoR7s": {
        "description": "Signature pour les catalogues officiels MilleGrille",
        ConstantesAutorisation.REGLE_DOMAINEACTIONS_PERMIS: frozenset([
            "CatalogueApplications.majDomaine",
            "CatalogueApplications.catalogueDomaines",
            "CatalogueApplications.catalogueApplication"
        ]),
        ConstantesAutorisation.REGLE_SIGNATURE_AUTORISATIONS: True,
    }
}


def autorisations_idmg() -> dict:
    return _autorisations_idmg.copy()


class Constantes:
    REGLE_CERTIFICAT_DATE_MESSAGE = 'certificat_date_message'

# Contients des configurations sous forme de constantes

_autorisations_idmg = {
  "version:": 1,
  "QME8SjhaCFySD9qBt1AikQ1U7WxieJY2xDg2JCMczJST": {
    "description": "Catalogues",
    "domaines_permis": [
      "CatalogueApplications.majDomaine",
      "CatalogueApplications.catalogueDomaines",
      "CatalogueApplications.catalogueApplication"
    ]
  }
}


def autorisations_idmg():
    return _autorisations_idmg.copy()


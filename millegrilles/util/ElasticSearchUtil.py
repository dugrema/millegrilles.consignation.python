import logging

import requests
import json

CONST_HEADERS = {"Content-Type": "application/json"}

INDEX_GROSFICHIERS = {
    "index_patterns": ["grosfichiers"],
    "template": {
        "settings": {
            "analysis": {
                "analyzer": {
                    "filename_index": {
                        'tokenizer': 'filename_index',
                        'filter': ['asciifolding', 'lowercase', 'file_edge']
                    },
                    "filename_search": {
                        "tokenizer": "filename_index",
                        "filter": ['asciifolding', 'lowercase']
                    },
                },
                "tokenizer": {
                    "filename_index": {
                        "type": "pattern",
                        "pattern": "[\\W|_]+",
                        "lowercase": True
                    },
                },
                "filter": {
                    "file_edge": {
                        "type": "edge_ngram",
                        "min_gram": 3,
                        "max_gram": 16,
                        "token_chars": [
                            "letter",
                            "digit"
                        ]
                    },
                }
            }
        },
        "mappings": {
            "_source": {
                "enabled": False
            },
            "properties": {
                "contenu": {
                    "type": "text",
                },
                "nom_fichier": {
                    "type": "text",
                    "search_analyzer": "filename_search",
                    "analyzer": "filename_index"
                },
                "titre._combine": {
                    "type": "text",
                    "search_analyzer": "filename_search",
                    "analyzer": "filename_index"
                },
                "description._combine": {
                    "type": "text",
                    "search_analyzer": "filename_search",
                    "analyzer": "filename_index"
                },
                "mimetype": {"type": "keyword"},
                # "contenu": {"type": "text"},
                "date_v_courante": {"type": "date", "format": "strict_date_optional_time||epoch_second"},
            }
        },
    },
    "priority": 500,
    "version": 2,
    "_meta": {
        "description": "Index grosfichiers"
    }
}


class ESIndexHelper:

    def __init__(self, url: str):
        self.__url = url
        self.__index_pret = False

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def _preparer_index(self):

        templates = {'grosfichiers': INDEX_GROSFICHIERS}

        for k, template in templates.items():
            rep = requests.put(
                '%s/_index_template/%s' % (self.__url, k),
                data=json.dumps(template),
                headers=CONST_HEADERS,
                timeout=15
            )
            # Rep OK = 200 : {"acknowledged":true}
            rep.raise_for_status()
            self.__logger.debug("Reponse creation template 1 %d : %s" % (rep.status_code, rep.text))

        self.__index_pret = True

    def assurer_index_pret(self):
        if self.__index_pret is not True:
            self._preparer_index()

    def indexer(self, nom_index: str, id_doc: str, doc: dict):
        if self.__index_pret is False:
            self._preparer_index()

        rep = requests.put(
            '%s/%s/_doc/%s' % (self.__url, nom_index, id_doc),
            data=json.dumps(doc),
            headers=CONST_HEADERS,
            timeout=15
        )

        rep.raise_for_status()

        return rep.status_code

    def rechercher(self, nom_index: str, params: dict):
        mots_cles = params.get('mots_cles')
        from_idx = params.get('from_idx') or 0
        size = params.get('size') or 20

        should = list()

        if mots_cles is not None:
            should.extend([
                {'match': {
                    'contenu': mots_cles,
                }},
                {'match': {
                    'nom_fichier': mots_cles,
                }},
                {'match': {
                    'titre._combine': mots_cles,
                }},
                {'match': {
                    'description._combine': mots_cles,
                }},
            ])

        query = {
            'bool': {
                'should': should,
            }
        }

        doc_query = {'query': query}

        headers = {"Content-Type": "application/json"}
        rep = requests.get(
            '%s/%s/_search?from=%d&size=%d' % (self.__url, nom_index, from_idx, size),
            data=json.dumps(doc_query),
            headers=headers,
            timeout=15
        )

        rep.raise_for_status()

        return rep.json()

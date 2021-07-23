import requests

INDEX_GROSFICHIERS = {
    "index_patterns": ["grosfichiers"],
    "template": {
        "settings": {
            "analysis": {
                "analyzer": {
                    "filename_index": {
                        'tokenizer': 'filename_index',
                        'filter': ['lowercase', 'file_edge']
                    },
                    "filename_search": {
                        "tokenizer": "filename_index",
                        "filter": ["lowercase"]
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
                "enabled": True
            },
            "properties": {
                "nom_fichier": {
                    "type": "text",
                    "search_analyzer": "filename_search",
                    "analyzer": "filename_index"
                },
                "mimetype": {"type": "keyword"},
                "contenu": {"type": "text"},
                "date_v_courante": {"type": "date", "format": "strict_date_optional_time||epoch_second"},
            }
        },
    },
    "priority": 500,
    "version": 1,
    "_meta": {
        "description": "Index grosfichiers"
    }
}


class ESIndexHelper:

    def __init__(self, url: str):
        self.__url = url

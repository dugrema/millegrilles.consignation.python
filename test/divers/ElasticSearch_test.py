import requests
import json
import datetime

from millegrilles.util.ElasticSearchUtil import INDEX_GROSFICHIERS


CONST_HEADERS = {"Content-Type": "application/json"}


def creer_template_grosfichiers():
    """
    Generer template pour index
    :return:
    """
    rep = requests.put(
        'http://localhost:9200/_index_template/grosfichiers',
        data=json.dumps(INDEX_GROSFICHIERS),
        headers=CONST_HEADERS
    )
    # Rep OK = 200 : {"acknowledged":true}
    print("Reponse creation template 1 %d : %s" % (rep.status_code, rep.text))


def delete_template1():
    rep = requests.delete(
        'http://localhost:9200/grosfichiers'
    )
    print("Reponse delete %d : %s" % (rep.status_code, rep.text))


def creer_template_2():
    """
    Generer template pour index
    :return:
    """

    rep = requests.delete(
        'http://localhost:9200/template_2'
    )
    print("Reponse delete %d : %s" % (rep.status_code, rep.text))

    template_1 = {
      "index_patterns": ["template_2"],
      "template": {
        "settings": {
          "analysis": {
              "analyzer": {
                  "filename_index": {
                      'tokenizer': 'filename_index',
                      'filter': ['file_edge']
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
                  # "file_edge": {
                  #     "type": "edge_ngram",
                  #     "min_gram": 2,
                  #     "max_gram": 16,
                  #     "token_chars": [
                  #         "letter",
                  #         "digit"
                  #     ]
                  # },
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
              # "filter": {
              #     "edge_ngram": {
              #         "side": "front",
              #         "max_gram": 20,
              #         "min_gram": 1,
              #         "type": "edgeNGram"
              #     }
              # }
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
              # "titre": {"type": "text"},
              # "description": {"type": "text"},
              # "collections": {"type": "text"},
              "contenu": {"type": "text"},
              "date_v_courante": {"type": "date", "format": "epoch_second"},
          }
        },
        #"aliases": {
        #  "mydata": { }
        #}
      },
      "priority": 500,
      # "composed_of": ["component_template1", "runtime_component_template"],
      "version": 3,
      "_meta": {
        "description": "Index grosfichiers"
      }
    }

    rep = requests.put(
        'http://localhost:9200/_index_template/template_2',
        data=json.dumps(template_1),
        headers=CONST_HEADERS
    )
    # Rep OK = 200 : {"acknowledged":true}
    print("Reponse creation template 1 %d : %s" % (rep.status_code, rep.text))


def analyse_template2():
    data = {
        'analyzer': 'filename_index',
        'text': 'mon_fichier-deux-2020-02-01.AAjd.jpg',
    }
    rep = requests.post(
        'http://localhost:9200/template_2/_analyze',
        data=json.dumps(data),
        headers=CONST_HEADERS
    )
    print("Reponse analyzer %d %s" % (rep.status_code, json.dumps(rep.json(), indent=2)))


def ajouter_docs():
    date_courante = int(datetime.datetime.utcnow().timestamp())

    doc_1 = {
        'nom_fichier': 'Document 1.pdf',
        'mimetype': 'application/pdf',
        'date_v_courante': date_courante,
        'collections': ['a', 'b'],
        'titre': {
            'defaut': 'Document 1',
            'fr': 'Document 1 francais',
            '_combine': ['Document 1', 'Document 1 francais'],
        },
        'contenu': "Ceci est du contenu en free text.\nJ'ai plutot trouve autre chose, ye!"
    }
    doc_2 = {
        'nom_fichier': 'Document 2.pdf',
        'mimetype': 'application/pdf',
        'date_v_courante': date_courante,
        'contenu': "Du text supplementaire. Moui!"
    }
    doc_3 = {
        'nom_fichier': 'image.jpg',
        'mimetype': 'image/jpg',
        'date_v_courante': date_courante,
        'collections': ['a', 'c'],
    }
    doc_4 = {
        'nom_fichier': 'mon_fichier-image-2020-01-22.jpg',
        'mimetype': 'image/jpg',
        'date_v_courante': date_courante,
    }
    doc_5 = {
        'nom_fichier': 'mon_fichier-deux-image-2020-01-22.jpg',
        'mimetype': 'image/jpg',
        'date_v_courante': date_courante,
    }

    docs = [doc_1, doc_2, doc_3, doc_4, doc_5]
    doc_index = 34
    for d in docs:
        rep = put_doc(d, 'abcd-12%d' % doc_index)
        print('Reponse %d = %s' % (rep.status_code, rep.text))
        doc_index = doc_index + 1


def put_doc(doc, doc_id):

    # Reponse OK : 201  (created)
    # {"_index":"doc_test","_type":"_doc","_id":"XZBpznoBJPTyDUz4prir","_version":1,"result":"created","_shards":{"total":2,"successful":1,"failed":0},"_seq_no":0,"_primary_term":1}

    # Reponse OK : 200  (updated)
    # {"_index":"doc_test","_type":"_doc","_id":"abcd-1234","_version":2,"result":"updated","_shards":{"total":2,"successful":1,"failed":0},"_seq_no":3,"_primary_term":1}

    return requests.put(
        'http://localhost:9200/template_2/_doc/' + doc_id,
        data=json.dumps(doc),
        headers=CONST_HEADERS
    )


def search_1():

    req = {
        'query': {
            'query_string': {'query': 'imA'}
            # 'match_all': {},
            # 'bool': {
            #     'should': [
            #         # {'match': {
            #         #     'titre._combine': 'Document',
            #         # }},
            #         # {'match': {
            #         #     'contenu': 'trouve',
            #         # }},
            #         # {'match': {
            #         #     'collections': 'a',
            #         # }},
            #         {'match': {
            #             'nom_fichier': 'fichier ima',
            #         }},
            #         # {'match': {
            #         #     'mimetype': 'application/pdf',
            #         # }},
            #     ]
            # }
        },
        # 'fields': ['nom'],
        #'sort': {
        #    'nom': 'asc',
        #}
    }

    res = requests.get(
        'http://localhost:9200/template_2/_search?from=0&size=10',
        data=json.dumps(req),
        headers=CONST_HEADERS,
    )
    print("Resultat recherche %d\n%s" % (res.status_code, json.dumps(json.loads(res.text), indent=2)))


def search_grosfichiers():

    motscles = 'CIBC'

    req = {
        'query': {
            # 'match_all': {},
            'bool': {
                'should': [
                    # {'match': {
                    #     'contenu': motscles,
                    # }},
                    # {'match': {
                    #     'collections': 'a',
                    # }},
                    {'match': {
                        'nom_fichier': motscles,
                    }},
                    # {'match': {
                    #     'titre._combine': motscles,
                    # }},
                    # {'match': {
                    #     'description._combine': motscles,
                    # }},
                    # {'match': {
                    #     # 'mimetype': 'application/pdf',
                    #     'mimetype': 'video/mp4',
                    # }},
                ]
            }
        },
    }

    res = requests.get(
        'http://localhost:9200/grosfichiers/_search?from=0&size=10',
        data=json.dumps(req),
        headers=CONST_HEADERS,
    )
    print("Resultat recherche %d\n%s" % (res.status_code, json.dumps(json.loads(res.text), indent=2)))


def main():
    # delete_template1()
    # creer_template_grosfichiers()
    # creer_template_2()
    # ajouter_docs()
    # analyse_template2()
    search_1()
    # search_grosfichiers()


if __name__ == '__main__':
    main()

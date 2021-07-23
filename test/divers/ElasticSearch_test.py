import requests
import json
import datetime


CONST_HEADERS = {"Content-Type": "application/json"}


def creer_template_1():
    """
    Generer template pour index
    :return:
    """
    template_1 = {
      "index_patterns": ["grosfichiers"],
      "template": {
        #"settings": {
        #  "number_of_shards": 1
        #},
        "mappings": {
          "_source": {
            "enabled": True
          },
          "properties": {
              "nom_fichier": {"type": "text"},
              "mimetype": {"type": "keyword"},
              # "titre": {"type": "text"},
              # "description": {"type": "text"},
              # "collections": {"type": "text"},
              "contenu": {"type": "text"},
              "date_v_courante": {"type": "date", "format": "strict_date_optional_time||epoch_second"},
          }
        },
        #"aliases": {
        #  "mydata": { }
        #}
      },
      "priority": 500,
      # "composed_of": ["component_template1", "runtime_component_template"],
      "version": 1,
      "_meta": {
        "description": "Index grosfichiers"
      }
    }

    rep = requests.put(
        'http://localhost:9200/_index_template/grosfichiers',
        data=json.dumps(template_1),
        headers=CONST_HEADERS
    )
    # Rep OK = 200 : {"acknowledged":true}
    print("Reponse creation template 1 %d : %s" % (rep.status_code, rep.text))


def delete_template1():
    rep = requests.delete(
        'http://localhost:9200/_index_template/grosfichiers'
    )
    print("Reponse delete %d : %s" % (rep.status_code, rep.text))


def creer_template_2():
    """
    Generer template pour index
    :return:
    """
    template_1 = {
      "index_patterns": ["template_2"],
      "template": {
        "mappings": {
          "_source": {
            "enabled": True
          },
          "properties": {
              "nom_fichier": {"type": "text"},
              "mimetype": {"type": "keyword"},
              # "titre": {"type": "text"},
              # "description": {"type": "text"},
              # "collections": {"type": "text"},
              "contenu": {"type": "text"},
              "date_v_courante": {"type": "date", "format": "strict_date_optional_time||epoch_second"},
          }
        },
        #"aliases": {
        #  "mydata": { }
        #}
      },
      "priority": 500,
      # "composed_of": ["component_template1", "runtime_component_template"],
      "version": 1,
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


def ajouter_docs():
    date_courante = datetime.datetime.utcnow().timestamp()

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

    rep1 = put_doc(doc_1, 'abcd-1234')
    print('Reponse 1 %d = %s' % (rep1.status_code, rep1.text))

    rep2 = put_doc(doc_2, 'abcd-1235')
    print('Reponse 2 %d = %s' % (rep2.status_code, rep2.text))

    rep3 = put_doc(doc_3, 'abcd-1236')
    print('Reponse 3 %d = %s' % (rep3.status_code, rep3.text))


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
            # 'match_all': {},
            'bool': {
                'should': [
                    {'match': {
                        'titre._combine': 'Document',
                    }},
                    # {'match': {
                    #     'contenu': 'trouve',
                    # }},
                    # {'match': {
                    #     'collections': 'a',
                    # }},
                    # {'match': {
                    #     'nom_fichier': 'jpg',
                    # }},
                    # {'match': {
                    #     'mimetype': 'application/pdf',
                    # }},
                ]
            }
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

    motscles = 'Cuba'

    req = {
        'query': {
            'match_all': {},
            # 'bool': {
            #     'should': [
            #         {'match': {
            #             'contenu': motscles,
            #         }},
            #         # {'match': {
            #         #     'collections': 'a',
            #         # }},
            #         {'match': {
            #             'nom_fichier': motscles,
            #         }},
            #         {'match': {
            #             'titre._combine': motscles,
            #         }},
            #         {'match': {
            #             'description._combine': motscles,
            #         }},
            #         # {'match': {
            #         #     # 'mimetype': 'application/pdf',
            #         #     'mimetype': 'video/mp4',
            #         # }},
            #     ]
            # }
        },
    }

    res = requests.get(
        'http://localhost:9200/grosfichiers/_search?from=0&size=10',
        data=json.dumps(req),
        headers=CONST_HEADERS,
    )
    print("Resultat recherche %d\n%s" % (res.status_code, json.dumps(json.loads(res.text), indent=2)))


def main():
    # creer_template_1()
    # creer_template_2()
    # delete_template1()
    # ajouter_docs()
    # search_1()
    search_grosfichiers()


if __name__ == '__main__':
    main()

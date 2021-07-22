import requests
import json


CONST_HEADERS = {"Content-Type": "application/json"}


def creer_template():
    """
    Generer template pour index
    :return:
    """
    template_1 = {
      "index_patterns": ["doc_test"],
      "template": {
        #"settings": {
        #  "number_of_shards": 1
        #},
        "mappings": {
          "_source": {
            "enabled": True
          },
          "properties": {
            "nom": {
              "type": "text"
            },
            "valeur": {
              "type": "text"
            },
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
        "description": "Index document 1"
      }
    }

    rep = requests.put(
        'http://localhost:9200/_index_template/template_1',
        data=json.dumps(template_1),
        headers=CONST_HEADERS
    )
    # Rep OK = 200 : {"acknowledged":true}
    print("Reponse creation template 1 %d : %s" % (rep.status_code, rep.text))


def ajouter_docs():
    doc_1 = {'nom': 'Document 1', 'valeur': 'Valeur du document 1'}
    doc_2 = {'nom': 'Document 2', 'valeur': 'Valeur du document 2'}

    rep1 = put_doc(doc_1, 'abcd-1234')
    print('Reponse 1 %d = %s' % (rep1.status_code, rep1.text))

    rep2 = put_doc(doc_2, 'abcd-1235')
    print('Reponse 2 %d = %s' % (rep2.status_code, rep2.text))


def put_doc(doc, doc_id):

    # Reponse OK : 201  (created)
    # {"_index":"doc_test","_type":"_doc","_id":"XZBpznoBJPTyDUz4prir","_version":1,"result":"created","_shards":{"total":2,"successful":1,"failed":0},"_seq_no":0,"_primary_term":1}

    # Reponse OK : 200  (updated)
    # {"_index":"doc_test","_type":"_doc","_id":"abcd-1234","_version":2,"result":"updated","_shards":{"total":2,"successful":1,"failed":0},"_seq_no":3,"_primary_term":1}

    return requests.put(
        'http://localhost:9200/doc_test/_doc/' + doc_id,
        data=json.dumps(doc),
        headers=CONST_HEADERS
    )


def search_1():

    req = {
        'query': {
            # 'match_all': {},
            'bool': {
                'should': {
                    'match': {'valeur': 'document 1'}
                }
            }
        },
        # 'fields': ['nom'],
        #'sort': {
        #    'nom': 'asc',
        #}
    }

    res = requests.get(
        'http://localhost:9200/doc_test/_search?from=1&size=10',
        data=json.dumps(req),
        headers=CONST_HEADERS,
    )
    print("Resultat recherche %d\n%s" % (res.status_code, json.dumps(json.loads(res.text), indent=2)))


def main():
    # creer_template()
    # ajouter_docs()
    search_1()


if __name__ == '__main__':
    main()

import json
import datetime
from bson.objectid import ObjectId

from millegrilles.util.JSONMessageEncoders import DateFormatEncoder


class MongoJSONEncoder(DateFormatEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.timestamp()
        elif isinstance(obj, ObjectId):
            return str(obj)
        else:
            return super().default(obj)


class DocElemFilter:

    CHAMPS_DOC_TRANSACTION = ['_id', '_mg-libelle', '_evenements', '_origine']

    @staticmethod
    def retirer_champs_doc_transaction(doc: dict):
        copie_doc = doc.copy()
        for champ in DocElemFilter.CHAMPS_DOC_TRANSACTION:
            if copie_doc.get(champ) is not None:
                del copie_doc[champ]

        return copie_doc

import json
import datetime
import codecs
import math
from json.encoder import encode_basestring_ascii, encode_basestring, INFINITY, c_make_encoder, _make_iterencode



class DateFormatEncoder(json.JSONEncoder):
    """
    Permet de convertir les dates en format epoch automatiquement
    """

    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return int(obj.timestamp())

        # Let the base class default method raise the TypeError
        try:
            return json.JSONEncoder.default(self, obj)
        except TypeError:
            return str(obj)


class JSONHelper:

    def __init__(self):
        self.reader = codecs.getreader("utf-8")

    def dict_vers_json(self, enveloppe_dict: dict, encoding=DateFormatEncoder) -> str:
        if enveloppe_dict.get('_id') is not None:
            # On converti le MongoDB _id
            enveloppe_dict = enveloppe_dict.copy()
            enveloppe_dict['_id'] = str(enveloppe_dict['_id'])
        message_utf8 = json.dumps(enveloppe_dict, sort_keys=True, ensure_ascii=True, cls=encoding).encode('utf-8')
        return message_utf8

    def bin_utf8_json_vers_dict(self, json_utf8):
        message_json = json_utf8.decode("utf-8")
        dict = json.loads(message_json)
        return dict
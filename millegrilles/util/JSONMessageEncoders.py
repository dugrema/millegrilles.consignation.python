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

    def iterencode(self, o, _one_shot=False):
        """Encode the given object and yield each string
        representation as available.

        For example::

            for chunk in JSONEncoder().iterencode(bigobject):
                mysocket.write(chunk)

        """
        if self.check_circular:
            markers = {}
        else:
            markers = None
        if self.ensure_ascii:
            _encoder = encode_basestring_ascii
        else:
            _encoder = encode_basestring

        if (_one_shot and c_make_encoder is not None
                and self.indent is None):
            _iterencode = c_make_encoder(
                markers, self.default, _encoder, self.indent,
                self.key_separator, self.item_separator, self.sort_keys,
                self.skipkeys, self.allow_nan)
        else:
            _iterencode = _make_iterencode(
                markers, self.default, _encoder, self.indent, self.floatstr,
                self.key_separator, self.item_separator, self.sort_keys,
                self.skipkeys, _one_shot)
        return _iterencode(o, 0)

    def floatstr(self, o, allow_nan=False,
                 _repr=float.__repr__, _inf=INFINITY, _neginf=-INFINITY):
        print("FLOATY! %f" % o)
        # Check for specials.  Note that this type of test is processor
        # and/or platform-specific, so do tests which don't depend on the
        # internals.

        if o != o:
            text = 'NaN'
        elif o == _inf:
            text = 'Infinity'
        elif o == _neginf:
            text = '-Infinity'
        else:
            return _repr(o)

        if not allow_nan:
            raise ValueError(
                "Out of range float values are not JSON compliant: " +
                repr(o))

        return text

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
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

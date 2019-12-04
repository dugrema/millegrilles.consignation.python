import json
import datetime
from bson.objectid import ObjectId


class MongoJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.timestamp()
        elif isinstance(obj, ObjectId):
            return str(obj)

        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)
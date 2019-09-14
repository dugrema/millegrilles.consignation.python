import datetime
import pytz
import dateutil.parser

date = datetime.datetime.now(tz=pytz.UTC)

# print("Date: %s" % str(date))

# for tz in pytz.all_timezones:
#     print("%s" % str(tz))

tz = pytz.timezone("Canada/Eastern")
date_canada_eastern = date.astimezone(tz=tz)

# print("Date tz=%s: %s" % (str(tz), str(date_canada_eastern)))


date_str = '2018-12-16T21:00:41Z'
date_fromstring = dateutil.parser.parse(date_str)
# print("Date from string: %s" % str(date_fromstring))

now = datetime.datetime.utcnow()
epoch = datetime.datetime.utcnow().timestamp()
print("Temps courant epoch: %d" % epoch)

date_chargee = datetime.datetime.fromtimestamp(1568481806)
datetime_delta = datetime.timedelta(seconds=30)

date_verif = date_chargee + datetime_delta
print("Date expiration: %s" % str(date_verif))

expire = date_verif < now
print("Expire: %s" % expire)
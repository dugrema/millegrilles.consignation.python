import datetime
import pytz
import dateutil.parser

date = datetime.datetime.now(tz=pytz.UTC)

print("Date: %s" % str(date))

for tz in pytz.all_timezones:
    print("%s" % str(tz))

tz = pytz.timezone("Canada/Eastern")
date_canada_eastern = date.astimezone(tz=tz)

print("Date tz=%s: %s" % (str(tz), str(date_canada_eastern)))


date_str = '2018-12-16T21:00:41Z'
date_fromstring = dateutil.parser.parse(date_str)
print("Date from string: %s" % str(date_fromstring))
import datetime
import pytz

date = datetime.datetime.now(tz=pytz.UTC)

print("Date: %s" % str(date))

for tz in pytz.all_timezones:
    print("%s" % str(tz))

tz = pytz.timezone("Canada/Eastern")
date_canada_eastern = date.astimezone(tz=tz)

print("Date tz=%s: %s" % (str(tz), str(date_canada_eastern)))

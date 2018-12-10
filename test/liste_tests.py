import pytz
import datetime

liste1 = ['a', 'b', 'c']
liste2 = ['c', 'a']
elem1 = 'c'
elem2 = 'a'

if elem1 in liste1 and elem2 in liste1:
    print("Elem1 et 2 dans liste")
else:
    print("Elem1 et 2 pas dans liste")

tz = pytz.timezone("EST")
now = datetime.datetime.now(tz=tz)
print("Now: %s" % str(now))

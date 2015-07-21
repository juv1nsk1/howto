import riak
from random import randint
import datetime
import sys
import pprint

myClient = riak.RiakClient(pb_port=8087, protocol='pbc')

myBucket = myClient.bucket('swap')

try:
	#for i in range(0,10000):
	for i in range(0,1000):
		key = str(i)
		#tms = unicode(datetime.datetime.now())
		#key1 = myBucket.new(None, data=tms)
		#key1.store()
		fetched1 = myBucket.get('1')

except Exception as e:
        print("error: {0}".format(e))
        sys.exit(2)



print(fetched1);

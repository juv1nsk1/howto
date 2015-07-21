import riak
from random import randint
import datetime
import sys

myClient = riak.RiakClient(pb_port=8087, protocol='pbc')

myBucket = myClient.bucket('bench')

try:
	for i in range(0,10000):
		key = i
		tms = unicode(datetime.datetime.now())
		key1 = myBucket.new(None, data=tms)
		key1.store()

except Exception as e:
        print("error: {0}".format(e))
        sys.exit(2)


#fetched1 = myBucket.get('1')
#assert val1 == fetched1.data

#print(val1);

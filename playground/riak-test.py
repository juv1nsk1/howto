import riak
from random import randint
import datetime

myClient = riak.RiakClient(pb_port=8087, protocol='pbc')

myBucket = myClient.bucket('bench')

for i in range(0,10000):
	key = randint(0,99999) 
	val2 = str(datetime.datetime.now)
	key1 = myBucket.new(None, data=val2)
	key1.store()

#fetched1 = myBucket.get('1')
#assert val1 == fetched1.data

#print(val1);

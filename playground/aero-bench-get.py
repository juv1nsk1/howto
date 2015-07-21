# -*- coding: utf-8 -*-
from __future__ import print_function
import aerospike
import pprint
import sys
from random import randint
import datetime

try:
	config = {
	    'hosts': [
		( '127.0.0.1', 3000 )
	    ],
	    'policies': {
		'timeout': 1000 # milliseconds
	    }
	}

	client = aerospike.client(config).connect()

except Exception as e:
    print("error: {0}".format(e), file=sys.stderr)
    sys.exit(1)


try:

	pp = pprint.PrettyPrinter(indent=2)
	client = aerospike.client(config).connect()
			
	for i in range(0,1000):
		keyid = randint(0,10000) 	
		#tms = unicode(datetime.datetime.now())
		key = ('test', 'table', keyid)
		#bins = {'timestamp': tms} 
		(keyidr, meta, bins) = client.get(key)

	pp.pprint(i)
	pp.pprint(keyid)
	pp.pprint(meta)
	pp.pprint(bins)

except Exception as e:
	print("error: {0}".format(e), file=sys.stderr)
	client.close()
	sys.exit(2)




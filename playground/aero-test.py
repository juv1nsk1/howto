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
			
	for i in range(0,10000):
		idkey = randint(0,99999) 	
		key = ('test', 'table', i)

		bins = {
			'name': idkey,
			'serialnum': 2716057,
			'lastsentence': {
				'BBS': "Well, we're boned",
				'TBwaBB': 'I love you, meatbags!',
				'BG': 'Whip harder, Professor!',
				'ltWGY': 'Into the breach, meatbags. Or not, whatever'},
			'composition': [ "40% zinc", "40% titanium", "30% iron", "40% dolomite" ],
			'apartment': bytearray(b'\x24'),
			'quote_cnt': 47
		}
		client.put(key, bins, meta={'ttl':60})
		(key, meta, bins) = client.get(key)

	pp.pprint(key)
	pp.pprint(meta)
	pp.pprint(bins)

	print('-----------------------------------------------------------')
	client.prepend(key, 'name', 'Dr. ')
	client.append(key, 'name', ' Bending Rodriguez')
	client.increment(key, 'quote_cnt', 3, meta={'ttl':meta['ttl']})
	(key, meta, bins) = client.get(key)
	pp.pprint(meta)
	pp.pprint(bins)

	print('-----------------------------------------------------------')
	operations = [
	{
		'op' : aerospike.OPERATOR_INCR,
		'bin' : 'quote_cnt',
		'val' : -1
	},
	{
		'op' : aerospike.OPERATOR_READ,
		'bin' : 'quote_cnt'
	}
	]
	(key, meta, bins) = client.operate(key, operations, meta={'ttl': meta['ttl']})
	pp.pprint(meta)
	pp.pprint(bins)
	client.close()

except Exception as e:
	print("error: {0}".format(e), file=sys.stderr)
	client.close()
	sys.exit(2)




## Copyright (c) 2019 AT&T Intellectual Property. All rights reserved.

## read pyt and make gdb

import sys
from load_db import load_file, save_graph

if( len(sys.argv) != 2 ):
   print("enter one argument as date eg 2019.03.16")
   exit()
else:
   d = sys.argv[1]

filename = 'Data/svr.' + d + '.pyt'
try:
    f = open(filename)
    f.close()
except IOError:
    print('File {0} is not accessible'.format(filename))
    exit()

gfile = 'GraphDb/' + d + '.gdb'
one_day_graph = load_file(filename)
save_graph(one_day_graph, gfile)
print('processed {0} '.format(filename))

## Copyright (c) 2020 AT&T Intellectual Property. All rights reserved.

## read pyt and make gdb

import sys
from load_db import load_file, save_graph
from sbom_helpers import get_datapath
from sbom_helpers import get_gdbpath
from sbom_helpers import validate_file_access

if( len(sys.argv) != 2 ):
   print("enter one argument as date eg 2019.03.16")
   exit()
else:
   d = sys.argv[1]

datapath = get_datapath()
filename = datapath + 'svr.' + d + '.pyt'
## validate file access
validate_file_access([filename])

## get directory to put gdb in
gdbpath = get_gdbpath()
gfile = gdbpath + d + '.gdb'
one_day_graph = load_file(filename)
save_graph(one_day_graph, gfile)
print('processed {0} '.format(filename))

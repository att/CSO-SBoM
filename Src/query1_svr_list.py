## Copyright (c) 2020 AT&T Intellectual Property. All rights reserved.

import sys
from load_db import load_graph
from load_db import get_groups
from load_db import server_by_group
from sbom_helpers import get_gdbpath
from sbom_helpers import mypprint
from sbom_helpers import validate_file_access

if( len(sys.argv) != 2 ):
   print("There should be one argument, date eg 2019.03.16")
   exit()
else:
   d = sys.argv[1]

gfile = get_gdbpath() + d + '.gdb'
#validate gdb file exists
validate_file_access([gfile])

graphdata = load_graph(gfile)

groups = get_groups(graphdata)

svr_list = graphdata.neighbors('type_server')

svr_grp_dict = server_by_group(svr_list, groups, graphdata)

mypprint(svr_grp_dict)

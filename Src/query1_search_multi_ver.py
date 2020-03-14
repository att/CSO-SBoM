## Copyright (c) 2020 AT&T Intellectual Property. All rights reserved.

import sys
from load_db import load_graph
from sbom_helpers import mypprint
from load_db import svr_pkgs
from load_db import get_hostname
from sbom_helpers import get_gdbpath


## Load one day graph based on input parameter
## Search for servers with multiple versions of a given package


if( len(sys.argv) != 3 ):
   print("enter two arguments: date eg 2019.03.16 and package eg gzip.x86_64")
   exit()
else:
   d = sys.argv[1]
   p = sys.argv[2]

gfile = get_gdbpath() + d + '.gdb'
try:
    f = open(gfile)
    f.close()
except IOError:
    print('File {0} is not accessible'.format(gfile))
    exit()

graphdata = load_graph(gfile)

## initialize variable for number of servers without package
num_no_v = 0
## initialize variable for number of servers with one ver of package
num_one_v = 0
## initialize variable for number of servers with multiple ver of package
num_mul = 0

## initialize a dictionary for list of multiver servers
mvp = {}

## initialize a list for the one version
one_ver = []


## loop thru all servers
svrs = graphdata.neighbors("type_server")
for svr in svrs:
    ## get all packages, versions
    (num_pkg_vers, num_pkgs, pkg_ver_dict, pkg_multiver_dict) = svr_pkgs(graphdata, svr)
    ## make a list (from the iterator) of the packages
    pkgs = list( pkg_ver_dict.keys() )

    ## evaluate if package of interest on this server
    if p in pkgs:
        ## check if multiver
        if len(pkg_ver_dict[p]) > 1:
            ## multiple versions - store for later
            num_mul += 1
            mvp[svr] = {'versions' : pkg_ver_dict[p] }
            ## get hostname
            mvp[svr]['hostname'] = get_hostname(svr,graphdata)
        else:
            num_one_v += 1
            v = pkg_ver_dict[p]
            if v not in one_ver:
                one_ver.append(v)
    else:
        num_no_v += 1

print("Number of servers without {0} package: {1}".format(p,num_no_v) )
print("Number of servers with one version {0} package: {1}".format(p,num_one_v) )
mypprint(one_ver)
print("Number of servers with multiple versions {0} package: {1}".format(p,num_mul) )
mypprint(mvp)

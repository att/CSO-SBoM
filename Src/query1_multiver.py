## Copyright (c) 2020 AT&T Intellectual Property. All rights reserved.

import sys
from load_db import load_graph
from sbom_helpers import mypprint
from load_db import svr_pkgs
from load_db import get_hostname
from load_db import get_group
from sbom_helpers import get_gdbpath


## Load one day graph based on input parameter
## for each server, determine which packages have more than one version
##    make a dictionary and sort by most egregious
##    print histogram binning svrs by number of 'extras'


if( len(sys.argv) != 2 ):
   print("enter one argument as date eg 2019.03.16")
   exit()
else:
   d = sys.argv[1]

gfile = get_gdbpath() + d + '.gdb'
try:
    f = open(gfile)
    f.close()
except IOError:
    print('File {0} is not accessible'.format(gfile))
    exit()

graphdata = load_graph(gfile)

## count of number of servers with at no packages with multiple vers
clean_ver_count = 0
## put clean servers in a list
clean_ver_list = []

## count of number of servers with at least one package with multiple vers
multi_ver_count = 0

## histogram of number of extra versions per server
extra_hist = {}

## histogram of number of multi-ver packages per server
##    note a server could have one package with 3 extra versions
##       which would show as 3 on extra versions and 1 on this
pkg_hist = {}

## dict with key of multi-ver-packages and value of list of servers
mvp = {}

## loop thru all servers
svrs = graphdata.neighbors("type_server")
for svr in svrs:
    ## get all packages, versions
    (num_pkg_vers, num_pkgs, pkg_ver_dict, pkg_multiver_dict) = svr_pkgs(graphdata, svr)
    ## make a list (from the iterator) of muti-ver packages
    pkgs = list( pkg_multiver_dict.keys() )

    ## evaluate extras
    extra = num_pkg_vers - num_pkgs
    if(num_pkg_vers > num_pkgs):
        multi_ver_count += 1
    else:
        clean_ver_count += 1
        clean_ver_list += [svr]
    if extra in extra_hist:
        extra_hist[extra] += 1
    else:
        extra_hist[extra] = 1
    num_pkgs = len(pkgs)
    if num_pkgs in pkg_hist:
        pkg_hist[num_pkgs] += 1
    else:
        pkg_hist[num_pkgs] = 1

    for pkg in pkgs:
        ## make string from list (sorting first so diff svrs give same)
        ver_list = pkg_multiver_dict[pkg]
        ver_list.sort()
        pkg_ver_string = "{0}/{1}".format(pkg,ver_list)
        if pkg_ver_string in mvp:
            mvp[pkg_ver_string] += [svr]
        else:
            mvp[pkg_ver_string] = [svr]

print("Number of servers with no multiver pakages: {0}".format(clean_ver_count) )
print("Number of servers with at least one multi-ver-package: {0}".format(multi_ver_count) )
print("===============")
## print pseudo histogram of extras
nums = list(extra_hist.keys())
nums.sort()
for num in nums:
    out = "{0} servers has {1} extra package-versions".format(extra_hist[num], num)
    print(out)

print("===============")
## print pseudo histogram of multi-ver packages
nums = list(pkg_hist.keys())
nums.sort()
for num in nums:
    out = "{0} servers has {1} mult-ver packages".format(pkg_hist[num], num)
    print(out)

print("===============")
## print the servers with zero extras
out = "the following servers have zero extras:"
print(out)
annotated_clean_ver_list = [[ (get_group(s,graphdata),s,get_hostname(s,graphdata)) for s in clean_ver_list ]]
annotated_clean_ver_list.sort()
mypprint(annotated_clean_ver_list)

print("===============")
## print the histogram of number of servers with multi-ver packages
## make tuple list of # svrs, mult-ver-package-string
out = "the following is a server count by package-vers hi to low:"
print(out)
mvps_tup = [(len(mvp[a]),a) for a in mvp.keys() ]
mvps_tup.sort()
mvps_tup.reverse()
mypprint(mvps_tup)

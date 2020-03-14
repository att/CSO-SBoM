## Copyright (c) 2020 AT&T Intellectual Property. All rights reserved.

import sys
from load_db import load_graph
from load_db import svr_pkgs
from sbom_helpers import get_gdbpath
from sbom_helpers import get_datelist
from sbom_helpers import validate_file_access
from bar_img import bar_image

## Load each day graph
## for each server, sum how many extra package_versions
##    print histogram of number of 'extras'

## input is two environmental variables: GDBPATH, DATELIST
##    GDBPATH is path to graphdb directory
##    DATELIST is ascii text of python list of dates of form yyyy.mm.dd

## initialize from env
gdbpath = get_gdbpath()
datelist = get_datelist()

if( len(sys.argv) != 2 ):
   print("There should be one argument, filename for output image")
   exit()
else:
   outfile = sys.argv[1]

## validate all the files exist
##    so don't waste time processing a bunch to then have die
filelist = [ (d, gdbpath + d + ".gdb") for d in datelist ]
validate_file_access([f for (d,f) in filelist])

## count of number of extra packages
extra_sum = {}


## now process each file
for (d,filename) in filelist:
  extra_sum[d] = 0
  graphdata = load_graph(filename)

  ## loop thru all servers
  svrs = graphdata.neighbors("type_server")
  for svr in svrs:
    ## get all packages, versions
    (num_pkg_vers, num_pkgs, pkg_ver_dict, pkg_multiver_dict) = svr_pkgs(graphdata, svr)
    ## make a list (from the iterator) of muti-ver packages
    pkgs = list( pkg_multiver_dict.keys() )

    ## evaluate extras
    extra = num_pkg_vers - num_pkgs
    extra_sum[d] += extra

print(extra_sum)

params = {}
params['filename'] = outfile
params['title'] = 'Extra package_versions by Date'
params['ylabel'] = 'Number of extras'
params['xlabel'] = 'Dates'
bar_image(extra_sum, params)

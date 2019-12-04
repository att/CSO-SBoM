## Copyright (c) 2019 AT&T Intellectual Property. All rights reserved.

import sys
from load_db import load_graph
from sbom_helpers import mypprint
from load_db import svr_pkgs
from load_db import all_intermediates
from load_db import get_hostname
from load_db import get_group
from load_db import pkg_subset
from sbom_helpers import get_gdbpath
from sbom_helpers import get_datelist
from sbom_helpers import validate_file_access
from analyze_data import bar_image
from load_db import svr_cve_pkgs
from load_db import pkg_cve_supr

## Load each day graph
## for each server, sum how many supressed cve packages
##    print histogram

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

## count of number of supressed cve packages
supr = {}

## now process each file
for (d,filename) in filelist:
  supr[d] = 0
  graphdata = load_graph(filename)

  ## First make a list of pkg_ver_cve
  ##    i.e. all nodes connected to "type_supressed"
  pvc_list = graphdata.neighbors("type_suppressed")

  ## count all servers connected
  for pvc in pvc_list:
      svrs = all_intermediates(graphdata, pvc, "type_server")
      supr[d] += 1

print(supr)

params = {}
params['filename'] = outfile
params['title'] = 'Package_versions with supressed CVE, by Date'
params['ylabel'] = 'Package_versions with supressed CVE'
params['xlabel'] = 'Dates'
bar_image(supr, params)

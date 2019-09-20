## Copyright (c) 2019 AT&T Intellectual Property. All rights reserved.

import sys
from load_db import load_graph
from sbom_helpers import mypprint
from load_db import svr_pkgs
from load_db import intermediate
from load_db import get_hostname
from load_db import get_group
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
cve_hist = {}


## now process each file
for (d,filename) in filelist:
  print(d)
  cve_hist[d] = {'10':0, '<10 >=7':0, '<7 >=5':0, '<5':0}
  graphdata = load_graph(filename)

  ## loop thru all servers
  svrs = graphdata.neighbors("type_server")
  for svr in svrs:
    scp = svr_cve_pkgs(graphdata, svr)
    sup_cves = pkg_cve_supr(scp)
    ten_cves = pkg_cve_cvss_threshold(scp, 10, 100)
    cve_hist[d]['10'] += len(ten_cves)
    seven_cves = pkg_cve_cvss_threshold(scp, 7, 10)
    cve_hist[d]['<10 >=7'] += len(seven_cves)
    five_cves = len(pkg_cve_cvss_threshold(scp, 5, 7))
    cve_hist[d]['<7 >=5'] += len(five_cves)
    low_cves = len(pkg_cve_cvss_threshold(scp, 0, 5))
    cve_hist[d]['<5'] += len(low_cves)

mypprint(cve_hist)
stacked_bar_image(cve_hist, outfile)

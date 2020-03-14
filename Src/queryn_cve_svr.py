## Copyright (c) 2020 AT&T Intellectual Property. All rights reserved.

import sys
from load_db import load_graph
from sbom_helpers import mypprint
from load_db import pkg_subset
from load_db import svr_subset
from sbom_helpers import get_gdbpath
from sbom_helpers import get_datelist
from sbom_helpers import validate_file_access
from sbar_img import stacked_bar_image

## Load each day graph
## for each server, sum how many cve packages in each cvss bin
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
   outfilename = sys.argv[1]

## validate all the files exist
##    so don't waste time processing a bunch to then have die
filelist = [ (d, gdbpath + d + ".gdb") for d in datelist ]
validate_file_access([f for (d,f) in filelist])

## dict to hold the data
cvebins = {}


## now process each file
for (d,filename) in filelist:
  cvebins[d] = {}
  graphdata = load_graph(filename)

  ## First make a list of all cve nodes
  ##    i.e. all nodes connected to "type_cve"
  cves = graphdata.neighbors("type_cve")

  ## bin cve's by cvss score
  cve10 = [] # CVE's with cvss=10
  cve7 = []  # CVE's with cvss<10,>=7
  cve5 = []  # CVE's with cvss<7,>=5
  cve0 = []  # CVE's with cvss<5,>=0

  for cve in cves:
      ## put cve in bin
      cvss = graphdata.nodes[cve]['cvss']
      if(cvss == 10.0):
          cve10.append(cve)
      elif(cvss >= 7.0):
          cve7.append(cve)
      elif(cvss >= 5.0):
          cve5.append(cve)
      else:
          cve0.append(cve)

  ## find all packages for each bin
  pkg10 = pkg_subset(graphdata,cve10)
  pkg7 = pkg_subset(graphdata,cve7)
  pkg5 = pkg_subset(graphdata,cve5)
  pkg0 = pkg_subset(graphdata,cve0)

  ## find all servers for each bin
  svr10 = svr_subset(graphdata, pkg10)
  svr7 = svr_subset(graphdata, pkg7)
  svr5 = svr_subset(graphdata, pkg5)
  svr0 = svr_subset(graphdata, pkg0)

  cvebins[d]['1. Worst CVSS=10'] = len(svr10)
  cvebins[d]['2. Critical 7 <= CVSS <10'] = len(svr7)
  cvebins[d]['3. Medium 5 <= CVSS <7'] = len(svr5)
  cvebins[d]['4. Low 0 <= CVSS <5'] = len(svr0)


mypprint(cvebins)

params = {}
params['filename'] = outfilename
params['title'] = 'Servers With CVEs by Date'
params['ylabel'] = 'Number of Servers That Have 1 or more package-versions with a CVE'
params['xlabel'] = 'Dates'
params['colors'] = ['yellow', 'gold', 'orange', 'red']

stacked_bar_image(cvebins, params)

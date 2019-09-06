## Copyright (c) 2019 AT&T Intellectual Property. All rights reserved.

import sys
from load_db import load_graph
from load_db import intermediate
from load_db import all_intermediates
from load_db import svr_pkgs
from load_db import svr_cve_pkgs
from load_db import pkg_cve_supr
from load_db import pkg_cve_cvss_threshold
from load_db import pkgs_with_no_cve
from sbom_helpers import mypprint

if( len(sys.argv) != 3 ):
   print("There should be two arguments")
   print("first arg is date eg 2019.03.16")
   print("2nd arg is server eg 84a421cd887f11e887244dfe08192208")
   exit()
else:
   d = sys.argv[1]
   svr = sys.argv[2]

gfile = 'GraphDb/' + d + '.gdb'
try:
    f = open(gfile)
    f.close()
except IOError:
    print('File {0} is not accessible'.format(gfile))
    exit()

graphdata = load_graph(gfile)

print("+++ file {0} ".format(gfile))
print("++++ svr {0}".format(svr))

svr_grp = intermediate(graphdata, 'type_group', svr)
print("++++ grp {0}".format(svr_grp))

hostname = intermediate(graphdata, 'type_hostname', svr)
print("++++ hostname {0}".format(hostname))

(num_pkg_vers,
 num_pkgs,
 pkg_ver_dict,
 pkg_multiver_dict) = svr_pkgs(graphdata, svr)
print("+++++ {0} package/versions".format(num_pkg_vers))
print("+++++ {0} packages".format(num_pkgs))
mypprint(pkg_multiver_dict)

## print supressed cves
print("supressed cve's:")
scp = svr_cve_pkgs(graphdata, svr)
sup_cves = pkg_cve_supr(scp)
mypprint(sup_cves)

## print bins of cvss
no_cves = len(pkgs_with_no_cve(scp))
print("{0} packages with no cve's:".format(no_cves))
ten_cves = pkg_cve_cvss_threshold(scp, 10, 100)
l_ten_cves = len(ten_cves)
print("{0} packages with worst cve of cvss=10:".format(l_ten_cves))
mypprint(ten_cves)

seven_cves = pkg_cve_cvss_threshold(scp, 7, 10)
l_seven_cves = len(seven_cves)
print("{0} packages with worst cvss <10 and >=7".format(l_seven_cves))
mypprint(seven_cves)

five_cves = len(pkg_cve_cvss_threshold(scp, 5, 7))
print("{0} packages with worst cvss <7 and >=5".format(five_cves))
low_cves = len(pkg_cve_cvss_threshold(scp, 0, 5))
print("{0} packages with worst cvss <5 and >=0".format(low_cves))

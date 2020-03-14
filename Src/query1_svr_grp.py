## Copyright (c) 2020 AT&T Intellectual Property. All rights reserved.

import sys
from load_db import load_graph
from load_db import get_groups
from load_db import server_by_group
from load_db import intermediate
from load_db import svr_pkgs
from load_db import svr_cve_pkgs
from load_db import pkg_cve_supr
from load_db import pkg_cve_cvss_threshold
from load_db import pkgs_with_no_cve
from sbom_helpers import get_gdbpath
from sbom_helpers import mypprint
from sbom_helpers import validate_file_access

if( len(sys.argv) != 3 ):
   print("There should be two arguments")
   print("first arg is date eg 2019.03.16")
   print("2nd arg is server eg NameOfGroup1")
   exit()
else:
   d = sys.argv[1]
   svr_grp = sys.argv[2]

gfile = get_gdbpath() + d + '.gdb'
##validate gdb file exists
validate_file_access([gfile])
graphdata = load_graph(gfile)
##Header for the report with the name of the server group
print("#####################")
print("####", svr_grp, "####")
print("#####################")
groups = get_groups(graphdata)  
svr_list = graphdata.neighbors('type_server') 
svr_grp_dict = server_by_group(svr_list, groups, graphdata) 
sg = svr_grp_dict

## Parses dictionary to only include the one group specified (variable "svr_grp")
data = (sg[svr_grp])

##For loop to run through each server in the group specified using the variable
## entered in to the script "svr_grp" - output is server health report for every server in the entire group
for svr in data:
	## Print each servers health report - each server separated by *** above and below contents
	print("**************************************************************************************")
	print("+++ file {0} ".format(gfile))
	print("++++ group {0}".format(svr_grp))  
	print("++++ svr",svr)
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
	print("{0} packages with cvss <10 and >=7".format(l_seven_cves))
	mypprint(seven_cves)

	five_cves = pkg_cve_cvss_threshold(scp, 5, 7)
	l_five_cves = len(five_cves)
	print("{0} packages with cvss <7 and >=5".format(l_five_cves))
	mypprint(five_cves)

	low_cves = pkg_cve_cvss_threshold(scp, 0, 5)
	l_low_cves = len(low_cves)
	print("{0} packages with cvss <5 and >=0".format(l_low_cves))
	mypprint(low_cves)

	print("**************************************************************************************")
	print()


print('+++ End Of Report +++')

## Copyright (c) 2019 AT&T Intellectual Property. All rights reserved.

## given a list of gdb's, return number of servers by group and total

import sys
import numpy
from load_db import load_graph
from load_db import get_groups
from load_db import intermediate
import matplotlib.pyplot as plt
from sbom_helpers import get_gdbpath
from sbom_helpers import get_datelist
from sbom_helpers import get_anlpath
from sbom_helpers import validate_file_access
from analyze_data import multi_date_number_servers
from analyze_data import stacked_bar_image

## output will be a dictionary (date as key) of dictionaries
##    per-date dictionaries will have keys of groups and total

## input is two environmental variables: GDBPATH, DATELIST
##    GDBPATH is path to graphdb directory
##    DATELIST is ascii text of python list of dates of form yyyy.mm.dd

## command line should contain filename for output image

if( len(sys.argv) != 2 ):
   print("There should be one argument, filename for output image")
   exit()
else:
   f = sys.argv[1]


data = multi_date_number_servers()

params = {}
params['filename'] = f
params['title'] = 'Servers by Date'
params['ylabel'] = 'Number of Servers'
params['xlabel'] = 'Dates'
stacked_bar_image(data, params)

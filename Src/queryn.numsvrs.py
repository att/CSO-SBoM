## Copyright (c) 2020 AT&T Intellectual Property. All rights reserved.

## given a list of gdb's, return number of servers by group and total

import sys
from mdate_num_svrs import multi_date_number_servers
from sbar_img import stacked_bar_image

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
params['colors'] = ['lightsteelblue', 'plum', 'palegreen', 'khaki', 'cyan']
stacked_bar_image(data, params)

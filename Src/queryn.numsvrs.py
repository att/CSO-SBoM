## Copyright (c) 2019 AT&T Intellectual Property. All rights reserved.

## given a list of gdb's, return number of servers by group and total

from load_db import load_graph
from load_db import get_groups
from load_db import intermediate
import matplotlib.pyplot as plt
import numpy
from sbom_helpers import get_gdbpath
from sbom_helpers import get_datelist
from sbom_helpers import get_anlpath
from sbom_helpers import validate_file_access
from analyze_data import multi_date_number_servers

## output will be a dictionary (date as key) of dictionaries
##    per-date dictionaries will have keys of groups and total

## input is two environmental variables: GDBPATH, DATELIST
##    GDBPATH is path to graphdb directory
##    DATELIST is ascii text of python list of dates of form yyyy.mm.dd

data = multi_date_number_servers()


dates = list( data.keys() )
dates.sort()

groups = [ g for g in data[dates[0]].keys() if g != 'total' ]
groups.sort()


N = len(dates)
ind = numpy.arange(N)

## list of series of length equal to the number of groups
##    which each series of length equal to the number of dates

seriesList = []
for g in groups:
  this_group_series = []
  for d in dates:
    this_group_series.append( data[d][g] )
  this_group_tuple = tuple(this_group_series)
  seriesList.append( this_group_tuple )

## build the bottom of each bar based on previous series
bottoms = []
for s in seriesList:
  this_bottom_list = [0]
  for i in range(1, len(s)):
    this_bottom_list.append( this_bottom_list[i-1] + s[i-1] )
  bottoms.append( tuple(this_bottom_list) )

##initialize bottoms with zeros for each column
bottoms = []
this_list = []
ld = range( len(dates) )
for d in ld: this_list.append(0)
bottoms.append( this_list )

for s in range(1, len(seriesList) ):
  this_list = [ bottoms[s-1][d] + seriesList[s-1][d] for d in ld ]
  bottoms.append( this_list )

bars = []
for i in range(len(seriesList)):
  bars.append( plt.bar(ind, seriesList[i], bottom=bottoms[i] ) )

plt.title('Servers by Date')
plt.ylabel('Number of Servers')
plt.xlabel('Dates')
plt.xticks(ind, tuple(dates))
plt.legend(tuple( [ p[0] for p in bars ] ), tuple(groups))

plt.show()

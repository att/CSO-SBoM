## Copyright (c) 2020 AT&T Intellectual Property. All rights reserved.

## routine for supplying number of servers

from sbom_helpers import get_gdbpath
from sbom_helpers import get_datelist
from sbom_helpers import validate_file_access
from load_db import load_graph
from load_db import get_groups
from load_db import intermediate

def multi_date_number_servers():
    ## given a list of gdb's, return number of servers by group and total
    ## output will be a dictionary (date as key) of dictionaries
    ##    per-date dictionaries will have keys of groups and total

    ## input is two environmental variables: GDBPATH, DATELIST
    ##    GDBPATH is path to graphdb directory
    ##    DATELIST is ascii text of python list of dates of form yyyy.mm.dd

    ## initialize from env
    gdbpath = get_gdbpath()
    datelist = get_datelist()

    ## init output dict
    data = {}

    ## validate all the files exist
    ##    so don't waste time processing a bunch to then have die
    filelist = [ (d, gdbpath + d + ".gdb") for d in datelist ]
    validate_file_access([f for (d,f) in filelist])

    ## now process each file
    for (d,filename) in filelist:
      one_day_graph = load_graph(filename)

      ## init the day in output dictionary
      data[d] = {}
      data[d]['total'] = 0
      for g in get_groups(one_day_graph):
        data[d][g] = 0

      ## loop thru all the servers
      for svr in one_day_graph.neighbors("type_server"):
        data[d]['total'] += 1
        ## find group and inc
        g = intermediate(one_day_graph, 'type_group', svr)
        data[d][g] += 1
    return(data)


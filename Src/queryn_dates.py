## Copyright (c) 2020 AT&T Intellectual Property. All rights reserved.

import sys, os
from sbom_helpers import get_gdbpath
from sbom_helpers import get_datapath

## Look in DATAPATH for dates
## Look in GDBPATH for dates
## list dates in DATAPATH not in GDBPATH
## list dates in GDBPATH

## input is two environmental variables: GDBPATH, DATAPATH
##    GDBPATH is path to graphdb directory
##    DATAPATH is path to raw data directory

## initialize from env
gdbpath = get_gdbpath()
datapath = get_datapath()


if( len(sys.argv) != 1 ):
   print("There should be no arguments")
   exit()
dfilelist = os.listdir(datapath)
ddatelist = [ f[-14:-4] for f in dfilelist if(( f[-4:] == '.pyt') and (f[:4] == 'svr.') ) ]

gfilelist = os.listdir(gdbpath)

gdatelist = [ f[-14:-4] for f in gfilelist if(f[-4:] == '.gdb') ]

unpdates = list(set(ddatelist).difference(gdatelist))
unpdates.sort()

if(len(unpdates) == 0):
    print('All raw data dates processed into gdb')
else:
    print('Dates not yet processed into gdb:')
    print(unpdates)

print('gdb dates:')
gdatelist.sort()
print(gdatelist)

##Copyright (c) 2020 AT&T Intellectual Property. All rights reserved.

## helper routines in diff file to keep this top level simple
from sbom_helpers import initialize
from sbom_helpers import current_auth
from sbom_helpers import process_page_servers
from sbom_helpers import svr_grp_init
from sbom_helpers import print_servers
from sbom_helpers import data_dump


## assumes CLOUDPASSAGEDICT env variable set up with key dictionary

## Initialize
## loop thru groups
##      within each group, loop thru pages of servers
##        as part of each page, validate auth has not expired (renew if it has)
##        for each page, loop thru all the servers returned puting info in dict


## Initialize all necessary info into state (a dictionary for keeping state)
state = initialize()

## create server lists
## loop thru the groups
for group_name in state['group_names']:
	## initialize for group
	state = svr_grp_init(state, group_name)

	## process all the servers, one page worth a time
	while state['pages_left']:
		## check if auth current, if not then renew
		state = current_auth(state)
		print('.', end='', flush=True)   # print . per page so user knows working
		#print(state['page_num']) # print . per page so user knows working
		## process a page of servers
		state = process_page_servers(state)
	print()

## print status
print_servers(state)

## store off the data in a file
data_dump(state)

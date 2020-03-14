## Copyright (c) 2020 AT&T Intellectual Property. All rights reserved.

## routines used by sbom (in sep file to remove clutter)

import os, time, base64, requests, pprint, datetime
import pickle # for storing data blog - remove once going direct to db


def initialize():
	## initialize needed variables
	state = {}
	state['expires'] = -1 #to force auth renewal
	state['start'] = 0 # to force auth renewal
	state['access_token'] = "invalid"  # to force auth renewal
	state['group_auth'] = get_keys()   # initialize keys from env variables
	state['group_names'] = state['group_auth'].keys()
	state['BASE_URL'] = "https://api.aglet.cloudpassage.com"
	state['AUTH_URL'] = state['BASE_URL'] + "/oauth/access_token"
	state['SERVER_INFO_URL'] = state['BASE_URL'] + "/v1/servers"
	state['page_size'] = 5
	state['page_num'] = 1
	state['servers'] = {}
	state['total_items'] = 0 # items processed
	return(state)

def get_keys():
	key_dict = eval( os.environ["CLOUDPASSAGEDICT"] )
	return(key_dict)

def current_auth(state):
	## see if auth has expired
	now = time.time()
	start = state['start']
	expires = state['expires'] - 10 #make sure at least 10 seconds left
	diff = now - start #how long since last renewal
	if(diff >= expires):
		access_token, expires = get_auth(state)
		state['access_token'] = access_token
		state['expires'] = expires
		state['start'] = now
	return(state)

def get_auth(state):
	requests.packages.urllib3.disable_warnings()
	current_group = state['current_group']
	(group_id,user,passwd) = state['group_auth'][current_group]
	print(current_group) #shows current group being processed 
	auth = user + ":" + passwd
	auth_bin = auth.encode('ASCII')
	creds = base64.b64encode(auth_bin)
	basic_auth = "Basic " + creds.decode('ASCII')
	parameters = {'grant_type': 'client_credentials'}

	BASE_URL = "https://api.aglet.cloudpassage.com"
	AUTH_URL = BASE_URL + "/oauth/access_token"
	headers = { "Authorization": basic_auth }
	token_request = requests.post(AUTH_URL, headers=headers, params=parameters, verify=False)

	token = token_request.json()
	print(token_request) #shows HTTP Status 200 (OK) message if request being processed
	access_token =  token['access_token']
	expires = token['expires_in'] - 100

	return access_token, expires

def process_page_servers(state):
	## create creds from previously obtained access token
	bearer_creds = "Bearer " +  state['access_token']
	## create auth header from creds
	bearer_headers = { "Authorization": bearer_creds }
	## set up parameters
	server_info_params = {'state': 'active',
	                      'per_page': state['page_size'],
						  'page': state['page_num'],
						  }
	server_info_request = requests.get(state['SERVER_INFO_URL'],
									   headers=bearer_headers,
									   params=server_info_params,
									   verify=False
									   )
	server_info = server_info_request.json()
	state['total_items'] = server_info['count']
	curr_grp = state['current_group']  # shorthand variable

	for item in  server_info['servers']:
		server = item['id']
		## store returned info for the server in a dict for that group
		state['servers'][curr_grp][server] = item

		## pull software vulnerability management (svm) data for that server
		svm_url = state['SERVER_INFO_URL'] + '/' + server + '/svm'
		svm_info_request = requests.get(svm_url,
										headers=bearer_headers,
										verify=False
 									   )
		svm_info = svm_info_request.json()

		## add to server info
		state['servers'][curr_grp][server]['svm'] = svm_info

	## clean up for next time thru
	state['items_processed'] = len(state['servers'][curr_grp])
	state['page_num'] = state['page_num'] + 1
	if ( state['total_items'] > state['items_processed'] ):
		state['pages_left'] = True
	else:
		state['pages_left'] = False

	return(state)

def svr_grp_init(state, group_name):
	## initialize each loop thru groups
	state['current_group'] = group_name
	state['pages_left'] = True
	state['items_processed'] = 0 # initialize count for this group
	state['servers'][group_name] = {}  #initialize for servers for this group
	state['start'] = 0 # to force auth renewal
	state['expires'] = -1 #to force auth renewal
	state['page_num'] = 1

	return(state)

def iss_grp_init(state, group_name):
	## initialize each loop thru groups
	state['current_group'] = group_name
	state['pages_left'] = True
	state['items_processed'] = 0 # initialize count for this group
	state['start'] = 0 # to force auth renewal
	state['expires'] = -1 #to force auth renewal
	state['page_num'] = 1

	return(state)

def mypprint(whatever):
	pp = pprint.PrettyPrinter(indent=4)
	pp.pprint(whatever)

def print_servers(state):
	## print out how many servers in each group
	for group_name in state['group_names']:
		output = repr(len(state['servers'][group_name]))
		output += " servers listed in "
		output += repr(group_name)
		print(output)

def data_dump(state):
	svr_dict = state['servers']
	## get data directory
	datadir = get_datapath()
	## make filename of "now"
	d=datetime.datetime.utcnow()
	format = datadir + "svr.%Y.%m.%d.pyt"
	filename = d.strftime(format)
	print(filename)
	pickle_out = open(filename,"wb")
	pickle.dump(svr_dict, pickle_out)
	pickle_out.close()

def get_gdbpath():
    try:
        gdbpath = os.environ["GDBPATH"]
    except:
        print("Error with setup of env GDBPATH")
        exit()
    return(gdbpath)

def get_datelist():
    try:
        datelist = eval(os.environ["DATELIST"]  )
    except:
        print("Error with setup of env DATELIST")
        exit()
    return(datelist)

def get_anlpath():
    try:
        anlpath = os.environ["ANLPATH"]
    except:
        print("Error with setup of env ANLPATH")
        exit()
    return(anlpath)

def get_datapath():
    try:
        datapath = os.environ["DATAPATH"]
    except:
        print("Error with setup of env DATAPATH")
        exit()
    return(datapath)

def validate_file_access(filelist):
	## makes sure all files in filelist are openable
	for filename in filelist:
		try:
			f = open(filename)
			f.close()
		except IOError:
			print('File {0} is not accessible'.format(filename))
			exit()

def file_to_data(filename):
    ## open a pyt and return the data in it
    datafile = open(filename, 'rb')
    data = pickle.load(datafile)
    datafile.close()
    return(data)

Copyright (c) 2019 AT&T Intellectual Property. All rights reserved.

The routine is run using python3
and imports several modules from sbom_helpers.py
which in turn import several standard modules.
* python3 sbom.py
  * sbom_helpers:initialize
    * python3:os
  * sbom_helpers:current_auth
    * python3:time.time
  * sbom_helpers:process_page_servers
    * python3:requests.get
  * sbom_helpers:svr_grp_init
  * sbom_helpers:print_servers
  * sbom_helpers:data_dump
    * python3:datetime.datetime.utcnow()

sbom.py assumes CLOUDPASSAGEDICT is setup as an shell Environment variable in the form of a string representation of a python dictionary where the key is the name of the Cloud Passage group and the value is 3-tuple e.g. CLOUDPASSAGEDICT='{ "group1" : ("what", "key1", "000..0"), ..., "groupN" : ("what", "keyN", "000..0") }'

* 1. when python3 sbom.py is run, sbom() begins by calling sbom_helpers:initialize() to initialize a state dictionary.
* 2. sbom_helpers:initialize() initializes a state dictionary with 11 static key/value pairs and runs sbom_helpers:get_keys() to obtain the API keys and puts them also in the state dictionary.
* 3. using the python routing os, sbom_helpers:get_keys() gets the API keys from the environment variable CLOUDPASSAGEDICT after converting the string to a dict
* 4. sbom() loops thru the groups:
  * 4.1. sbom() initializes the state dictionary for this group using sbom_helpers:svr_grp_init()
  * 4.2. sbom() checks there are still servers to go and calls sbom_helpers:current_auth() to validate auth has not timed out
    * 4.2.1. sbom_helpers:current_auth() gets current time using python time.time() and compares to expire time which was stored in state dictionary each time sbom_helpers:get_auth() is reinitialized. If expired (or within 10s of expiring to minimize race conditions), sbom_helpers:current_auth() runs sbom_helpers:get_auth() to reinitialize.
  * 4.3 sbom() calls sbom_helpers:process_page_servers() to get another page of servers, printing a "." (without newline) for each page so user knows somehthing is happening
    * 4.3.1 sbom_helpers:process_page_servers() calls the CloudPassage API to pull a page of a list of servers using the python3:requests.get() module
    * 4.3.2 sbom_helpers:process_page_servers() loops thru the list of servers retrieved
      * 4.3.2.1 for each server on list sbom_helpers:process_page_servers() calls API using python3:requests.get() to get vuln data
      * 4.3.2.2 sbom_helpers:process_page_servers() stores retrieved info in state dict
* 5. sbom() calls sbom_helpers:print_servers() to print some summary info for the user
* 6. sbom() calls sbom_helpers:data_dump() to save the pyt file
  * 6.1 sbom_helpers:data_dump() uses datetime.datetime.utcnow() to create a filename based on today's date. Note UTC is used for defining today (so may be yesterday or tomorrow depending on timezone)
  * 6.2 sbom_helpers:data_dump() uses python3:pickle:dump() fo serialize the state dictionary and store in a file



  * sbom_helpers:iss_grp_init
  * sbom_helpers:mypprint

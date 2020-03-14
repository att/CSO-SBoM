## Copyright (c) 2020 AT&T Intellectual Property. All rights reserved.

## routines for loading data into db

from sbom_helpers import mypprint
from sbom_helpers import file_to_data
import networkx as nx
import matplotlib.pyplot as plt

def load_file(filename):
    ## initialize the graph and the top nodes
    one_day_graph = nx.Graph()
    one_day_graph.add_node("type_server")
    one_day_graph.add_node("type_group")
    one_day_graph.add_node("type_cve")
    one_day_graph.add_node("type_package")
    one_day_graph.add_node("type_version")
    one_day_graph.add_node("type_hostname")
    one_day_graph.add_node("type_server_label")
    one_day_graph.add_node("type_suppressed")
    one_day_graph.add_node("type_multi_ver")

    ## read in the data from the file
    data = file_to_data(filename)

    ## derive the groups and loop thru them
    groups = data.keys()
    for group in groups:
        if group in one_day_graph:
            print_already_err("group", group)
        else:
            one_day_graph.add_node(group)
            one_day_graph.add_edge(group, "type_group")
        ## iterate thru all the servers in this group
        servers = data[group].keys() # iterator over list of servers
        for server in servers:
            hostname = data[group][server]['hostname']
            if hostname in one_day_graph:
                print_already_err("hostname", hostname)
            elif hostname == None:
                print_already_err("no hostname for", server)
            else:
                one_day_graph.add_node(hostname)
                one_day_graph.add_edge(hostname, "type_hostname")

            server_label = data[group][server]['server_label']
            if server_label == None:
                print_already_err("no server_label, ie 'None', for", server)
            elif server_label in one_day_graph:
                print_already_err("server_label", server_label)
            else:
                one_day_graph.add_node(server_label)
                one_day_graph.add_edge(server_label, "type_server_label")

            if server in one_day_graph:
                print_already_err("server", server)
            else:
                one_day_graph.add_node(server)
                one_day_graph.add_edge(server, "type_server")
                one_day_graph.add_edge(server, group)
                one_day_graph.add_edge(server, hostname)
                one_day_graph.add_edge(server, server_label)

            ## grab the findings for this server
            findings = data[group][server]['svm']['scan']['findings']
            ## go thru each finding of this server and update package
            for finding in findings:
                package_name = finding['package_name']
                if package_name not in one_day_graph:
                    one_day_graph.add_node(package_name)
                    one_day_graph.add_edge(package_name, "type_package")
                relative_package_version = finding['package_version']
                ## make package_version fully qualified by package group_name
                package_version = package_name + ":" + relative_package_version
                if package_version not in one_day_graph:
                    one_day_graph.add_node(package_version)
                    one_day_graph.add_edge(package_name, package_version)
                    one_day_graph.add_edge("type_version", package_version)
                ## connect server to fully qualified package versions
                one_day_graph.add_edge(server, package_version)
                cve_entries = finding['cve_entries']
                for cve_entry in cve_entries:
                    cve = cve_entry['cve_entry']
                    cvss = cve_entry['cvss_score']
                    suppressed = cve_entry['suppressed'] #FW: handle per svr
                    if cve not in one_day_graph:
                        ## make attributes of cvss score and whether suppressed
                        one_day_graph.add_node(cve)
                        one_day_graph.add_edge(cve, "type_cve")
                        one_day_graph.nodes[cve]['cvss'] = cvss
                        one_day_graph.nodes[cve]['suppressed'] = suppressed
                    one_day_graph.add_edge(package_version, cve)
                    ## suppression is per server so special node
                    if suppressed:
                        ## package_version+CVE may be supressed in some servers
                        ##     and not others so need a node
                        pkg_ver_cve = (package_version, cve)
                        ## see if node already exists
                        if pkg_ver_cve not in one_day_graph:
                            ## not here, so create
                            one_day_graph.add_node(pkg_ver_cve)
                            one_day_graph.add_edge(pkg_ver_cve, "type_suppressed")
                        ## link pkg_ver_cve to server
                        one_day_graph.add_edge(pkg_ver_cve, server)
    return(one_day_graph)

def info_graph(one_day_graph):
    print("=================")
    mypprint(nx.info(one_day_graph))
    ## print some status
    ##    number of servers is number of edges to type_server
    num_svrs = len(one_day_graph.edges("type_server"))
    output = "number of server nodes = {0}".format(num_svrs)
    print(output)

    ## show number of servers by group
    groups = list(one_day_graph.neighbors("type_group"))
    for group in groups:
        ## number of servers is number of edges to group
        ##      minus 1 for link from group to type_group
        num_svrs = len(one_day_graph.edges(group)) - 1
        output = "   number of {0} servers = {1}".format(group,num_svrs)
        print(output)


    ##    number of unique packages is number of edges to type_package
    num_pkgs = len(one_day_graph.edges("type_package"))
    output = "number of package nodes = {0}".format(num_pkgs)
    print(output)
    ##    number of unique package/versions is number of edges to type_version
    num_versions = len(one_day_graph.edges("type_version"))
    output = "number of package version nodes = {0}".format(num_versions)
    print(output)
    ##    number of unique package/versions is number of edges to type_version
    num_cve = len(one_day_graph.edges("type_cve"))
    output = "number of cve nodes = {0}".format(num_cve)
    print(output)


def save_graph(one_day_graph,filename):
    nx.write_gpickle(one_day_graph,filename)

def load_graph(filename):
    return( nx.read_gpickle(filename) )

def print_graph(graph_to_print, filename):
    nx.draw(graph_to_print)
    plt.savefig(filename)

def cve_subset(graphdata,cvss_threshold):
    print(cvss_threshold)
    ## return list of cve nodes with a cvss_score >= threshold
    ## First make a list of all cve nodes
    ##    i.e. all nodes connected to "type_cve"
    cves = graphdata.neighbors("type_cve")
    #cves = list(graphdata.neighbors("type_cve"))
    ## reduce cve list to just those above cvss_threshold
    cves_subset = []
    supr_cves = []
    for cve in cves:
        cvss = graphdata.nodes[cve]['cvss']
        supr = graphdata.nodes[cve]['suppressed']
        if(cvss >= cvss_threshold):
            if(supr):
                supr_cves.append(cve)
            else:
                cves_subset.append(cve)
    cves_subset.sort()
    supr_cves.sort()
    return(cves_subset, supr_cves)

def pkg_subset(graphdata, cves):
    ## given a set of cve's, return connected packages
    pkgs = []
    for cve in cves:
        ## loop thru neighbors of cve
        ##    ignore type_cve, otherwise add to pkgs (if not already in)
        for item in graphdata.neighbors(cve):
            if( (item != "type_cve") and (item not in pkgs) ):
                pkgs.append(item)
    pkgs.sort()
    return(pkgs)

def svr_subset(graphdata, pkgs):
    ## given a list of packages, what servers are connected
    svrs = []  ## list to hold the eventual result
    for package in pkgs:
        ## loop thru neighbors of packages and add to svrs
        ##     if is a server and is not already in list
        for item in graphdata.neighbors(package):
            if( item in graphdata.neighbors('type_server') ):
                if(item not in svrs):
                    svrs.append(item)
    svrs.sort()
    return(svrs)


def svr_by_group(graphdata, svr_list):
    ## given a list of servers, separate them into groups
    for group in graphdata.neighbors('type_group'):
        print(group)
        for svr in svr_list:
            if svr in graphdata.neighbors(group):
                print(svr)

def intermediate(graphdata, top, bottom):
    ## find one intermediate node connecting top to bottom
    for outer in graphdata.neighbors(top):
        for inner in graphdata.neighbors(bottom):
            if outer == inner:
                return(inner)
    return(None)

def all_intermediates(graphdata, top, bottom):
    ## find all one hop intermediate nodes connecting top to bottom
    answer = []
    for outer in graphdata.neighbors(top):
        for inner in graphdata.neighbors(bottom):
            if outer == inner:
                answer.append(outer)
    return(answer)

def svr_pkgs(graphdata, svr):
    ## find all packages in a server, and what versions of each
    ## return # of pkg/vers, # of pkgs, package dict, multi-ver package dict
    pkg_versions = all_intermediates(graphdata, svr, 'type_version')
    num_pkg_vers = len(pkg_versions)
    pkg_ver_dict = {}
    for pv in pkg_versions:
        pkg = intermediate(graphdata,pv,'type_package')
        ver = pv[len(pkg):]
        if pkg in pkg_ver_dict:
            ## pkg in dict, so add new version
            pkg_ver_dict[pkg].append(ver)
        else:
            ## first version for this package
            pkg_ver_dict[pkg] = [ ver ]
    pkgs = list(pkg_ver_dict.keys())
    num_pkgs = len(pkgs)
    pkg_multiver_dict = {}
    for pkg,verList in pkg_ver_dict.items():
        if len(verList) > 1:
            pkg_multiver_dict[pkg] = verList

    return(num_pkg_vers, num_pkgs, pkg_ver_dict, pkg_multiver_dict)

def svr_cve_pkgs(graphdata, svr):
    ## find all packages/version on a server, and find what cve's affect them
    ## find all package/versions
    pkg_versions = all_intermediates(graphdata, svr, 'type_version')
    ## for each pkg/ver, find linked cves and put in dict
    ## pkg_cve[pkg] = list of cve's where cve is a tuple of (cve,cvss,supressed)
    pkg_cve = {}
    for pv in pkg_versions:
        pkg_cve[pv] = []
        cves = all_intermediates(graphdata, pv, 'type_cve')
        ## get info on each cve and enter tuples
        for cve in cves:
            cvss = graphdata.nodes[cve]['cvss']
            supr = graphdata.nodes[cve]['suppressed']
            pkg_cve[pv].append( (cve, cvss, supr) )
    return(pkg_cve)

def pkg_cve_supr(pkg_cve):
    ## given a dict from svr_cve_pkgs, return list of pkgs with supressed cve's
    supr_list = []
    for pv in pkg_cve:
        for (cve, cvss, supr) in pkg_cve[pv]:
            if supr:
                supr_list.append( (pv,cve, cvss) )
    return(supr_list)

def pkg_cve_cvss_threshold(pkg_cve, min, max):
    ## given a dict from svr_cve_pkgs, return list of pkgs with cve's
    ##    whose cvss is >=min and <max
    output = []
    for pv in pkg_cve:
        if( len(pkg_cve[pv]) > 0):
            (cve, cvss, supr) = top_cvss(pkg_cve[pv])
            if( (cvss >= min) and (cvss < max) ):
                output.append( (pv,cve, cvss) )
    return(output)

def pkgs_with_no_cve(pkg_cve):
    ## given a dict from svr_cve_pkgs, return list of pkgs with no cve's
    output = []
    for pv in pkg_cve:
        if(len(pkg_cve[pv]) == 0):
            output.append(pv)
    return(output)

## return hostname of a server
def get_hostname(server, graphdata):
    return( intermediate(graphdata, 'type_hostname', server) )

## return group of a server
def get_group(server, graphdata):
    return( intermediate(graphdata, 'type_group', server) )

## return list of groups
def get_groups(graphdata):
    return( list(graphdata.neighbors("type_group")) )

## divide a list of servers by groups
def server_by_group(server_list, group_list,graphdata):
    # return a dictionary key=group, value=list of servers
    svr_grp_dict = {}
    for group in group_list:
        svr_grp_dict[group] = []
    for svr in server_list:
        grp = get_group(svr, graphdata)
        svr_grp_dict[grp].append(svr)
    return(svr_grp_dict)

## local helper routines

def print_already_err(item_type, item):
    err = item_type
    err += " "
    err += str(item)
    err += " already in Graph. Why???"
    print(err)

def top_cvss(tuplelist):
    ## given a non-zero list of (cve, cvss, supr)
    ##   return one with largest cvss
    if( len(tuplelist) == 0 ):
        return(None)
    out_cve = None
    out_cvss = -1
    out_supr = False
    for (cve, cvss, supr) in tuplelist:
        if( cvss > out_cvss ):
            out_cve = cve
            out_cvss = cvss
            out_supr = supr
    return( (out_cve, out_cvss, out_supr) )

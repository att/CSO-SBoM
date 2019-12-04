## Copyright (c) 2019 AT&T Intellectual Property. All rights reserved.

## routines for analyzing data

import pickle
from sbom_helpers import mypprint
from sbom_helpers import get_gdbpath
from sbom_helpers import get_datelist
from sbom_helpers import validate_file_access
from sbom_helpers import file_to_data
from sbom_helpers import get_anlpath
from load_db import load_graph
from load_db import get_groups
from load_db import intermediate
import numpy
import matplotlib.pyplot as plt

def print_dict_struc(data):
    groups = data.keys()
    grp1 = list(groups)[0]
    servers = data[grp1].keys()
    server1name = list(servers)[0]
    server1data = data[grp1][server1name]
    s1txt = "\tdata['{0}']['{1}']".format(grp1,server1name)
    hstname = s1txt + "['hostname']"
    svm = s1txt + "['svm']"
    scan = svm + "['scan']"
    cfc = scan + "['critical_findings_count']"
    ncfc = scan + "['non_critical_findings_count']"
    okfc = scan + "['ok_findings_count']"
    fin = scan + "['findings']"
    fin1 = fin + "[0]"
    pkgn = fin1 + "['package_name']"
    pkgn1 = server1data['svm']['scan']['findings'][0]['package_name']
    pkgv = fin1 + "['package_version']"
    pkgv1 = server1data['svm']['scan']['findings'][0]['package_version']

    output = "from sbom_helpers import file_to_data"
    print(output)
    output = 'data = file_to_data("svr.{somedate}.pyt")'
    print(output)
    output = "Groups: {0}".format(groups)
    print(output)
    print("second level is servers by name")
    print(s1txt)
    output = "example 3rd level is hostname "
    print(output)
    print(hstname)
    output = "example 3rd level is svm "
    print(output)
    print(svm)
    output = "example svm 4th level is scan "
    print(output)
    print(scan)
    output = "example scan 5th level is critical_findings_count "
    print(output)
    print(cfc)
    output = "example scan 5th level is non_critical_findings_count "
    print(output)
    print(ncfc)
    output = "example scan 5th level is ok_findings_count "
    print(output)
    print(okfc)
    output = "example scan 5th level is findings "
    print(output)
    output = "\t{0} findings".format(len(fin))
    print(output)
    print(fin1)
    print(pkgn)
    print(pkgn1)
    print(pkgv)
    print(pkgv1)

def server_count(data):
    groups = data.keys()
    total_servers = 0
    for group in groups:
        number_servers = len ( list(data[group].keys()) )
        output = "{0} servers in {1}".format(number_servers,group)
        print(output)
        total_servers += number_servers
    output = "{0} total servers".format(total_servers)
    print(output)

def count_findings(data):
    outdata = {}
    outdata['number_servers'] = 0
    outdata['totals'] = {}
    outdata['totals']['ok'] = 0
    outdata['totals']['critical'] = 0
    outdata['totals']['noncritical'] = 0
    groups = data.keys()
    for group in groups:
        outdata[group] = {}
        outdata[group]['ok'] = 0
        outdata[group]['critical'] = 0
        outdata[group]['noncritical'] = 0
        outdata[group]['number_servers'] = 0
        for server in data[group].keys():
            outdata['number_servers'] += 1
            outdata[group]['number_servers'] += 1
            this_server = data[group][server]['svm']['scan']
            ## bin by if any critical, then noncritical, then ok
            if this_server['critical_findings_count'] > 0:
                outdata[group]['critical'] += 1
            elif this_server['non_critical_findings_count'] > 0:
                outdata[group]['noncritical'] += 1
            else:
                outdata[group]['ok'] += 1
        outdata['totals']['ok'] += outdata[group]['ok']
        outdata['totals']['critical'] += outdata[group]['critical']
        outdata['totals']['noncritical'] += outdata[group]['noncritical']
    return(outdata)

def list_packages(filename):
    data = file_to_data(filename)
    package_dict = {}
    ## dictionary of packages containing package name as top level key
    ##      second level is also dict with key = package package_version
    ##      third level is dict with group
    ##      fourth level is dict with servers
    ##         fifthlevel is dates as dict with cve's in list as values
    ##         FW: datelist is dates that contain this point
    ##         FW: add cve
    server_count = {}
    ## dictionary of servers as top level key
    ##      second level key is either group or count both of which tie to value at 3rd level
    groups = data.keys()  #iterator on servers
    for group in groups:
        server_count[group] = {}
        servers = data[group].keys() # iterator over list of servers
        for server in servers:
            hostname = data[group][server]['hostname']
            ## shorthand for findings of this particular server
            findings = data[group][server]['svm']['scan']['findings']
            ## init and fill in server count for this server
            server_count[group][server] = {}
            server_count[group][server]['hostname'] = hostname
            server_count[group][server]['package_count'] = len(findings)
            ## go thru each finding of this server and update package dict
            for finding in findings:
                package_name = finding['package_name']
                if package_name not in package_dict.keys():
                    package_dict[package_name] = {}
                package_version = finding['package_version']
                if package_version not in package_dict[package_name]:
                    package_dict[package_name][package_version] = {}
                if group not in package_dict[package_name][package_version]:
                    package_dict[package_name][package_version][group] = {}
                if server not in package_dict[package_name][package_version][group]:
                    package_dict[package_name][package_version][group][server] = {}
                    package_dict[package_name][package_version][group][server]['dates'] =  [ ]
                    package_dict[package_name][package_version][group][server]['cve'] = ['TBD']
                package_dict[package_name][package_version][group][server]['dates'].append(filename)
    print("===============")
    mypprint(server_count)
    print("===============")
    mypprint(package_dict)
    ## make a distribuation of package counts
    pkg_cnt = []
    for group in groups:
        servers = data[group].keys()
        for server in servers:
            pkg_cnt.append(server_count[group][server]['package_count'])
    pkg_cnt.sort()
    print(pkg_cnt)
    ## which package versions on how many machines
    package_names = package_dict.keys()
    package_count_dict = {}
    for package in package_names:
        package_count_dict[package] = {}
        versions = package_dict[package].keys()
        for version in versions:
            package_count_dict[package][version] = 0
            groups = package_dict[package][version].keys()
            for group in groups:
                servers = package_dict[package][version][group].keys()
                for server in servers:
                    package_count_dict[package][version] += 1
    mypprint(package_count_dict)


def critical_servers(data):
    ## go thru servers and output dict of [group][server]
    ##      which have critical cve's
    ##      FW: add cve's as value in dict
    ##      FW: make cve dict of relevant cve's
    crit = {}
    groups = data.keys()  #iterator on servers
    for group in groups:
        crit[group] = {}
        for server in data[group].keys():
            this_server = data[group][server]['svm']['scan']
            if this_server['critical_findings_count'] > 0:
                crit[group][server] = {}
                findings = this_server['findings']
                for finding in findings:
                    ## if critical add to crit
                    if finding['critical']:
                        package_name = finding['package_name']
                        package_version = finding['package_version']
                        if package_name not in crit[group][server]:
                            crit[group][server][package_name] = {}
                        crit[group][server][package_name][package_version] = {'crit_cve' : finding['cve_entries']}
    for group in crit:
        numcs = len(crit[group])
        output = "group {0} has {1} servers with critical CVE".format(group,numcs)
    for group in crit:
        output = "========== {0} ===========".format(group)
        print(output)
        for server in crit[group]:
            hostname = data[group][server]['hostname']
            server_label = data[group][server]['server_label']
            output = "  ----- {0} - {1} - {2} -----".format(server, hostname, server_label)
            print(output)
            for package in crit[group][server]:
                for ver in crit[group][server][package]:
                    output = "    ++++++ {0},{1} +++++++++++".format(package,ver)
                    print(output)
                    mypprint(crit[group][server][package][ver]['crit_cve'])

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

def stacked_bar_image(data, params):
    ## from input data, create a stacked bar chart image, store in outfile
    filename = params['filename']
    outfile = get_anlpath() + filename
    img_title = params['title']
    img_ylabel = params['ylabel']
    img_xlabel = params['xlabel']
    colors = params['colors']

    dates = list( data.keys() )
    dates.sort()

    groups = [ g for g in data[dates[0]].keys() if g != 'total' ]
    groups.sort()
    groups.reverse()


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
    ##     initialize bottoms with zeros for each column
    bottoms = []
    this_list = []
    ld = range( len(dates) )
    for d in ld: this_list.append(0)
    bottoms.append( this_list )
    ##     fill in with bottom + prev value
    for s in range(1, len(seriesList) ):
      this_list = [ bottoms[s-1][d] + seriesList[s-1][d] for d in ld ]
      bottoms.append( this_list )

    plt.figure(figsize=(10,8))
    bars = []
    for i in range(len(seriesList)):
      bars.append( plt.bar(ind, seriesList[i], bottom=bottoms[i], color=colors[i] ) )

    plt.title(img_title)
    plt.ylabel(img_ylabel)
    plt.xlabel(img_xlabel)
    plt.xticks(ind, tuple(dates))
    plt.legend(tuple( [ p[0] for p in bars ] ), tuple(groups))

    plt.savefig(outfile)

def bar_image(data, params):
    ## from input data, create a bar chart image, store in outfile
    filename = params['filename']
    outfile = get_anlpath() + filename
    img_title = params['title']
    img_ylabel = params['ylabel']
    img_xlabel = params['xlabel']

    keys_values = list(data.items())
    keys_values.sort()

    x_labels = [a for (a,b) in keys_values]
    x_pos = numpy.arange(len(x_labels))

    y_data = [b for (a,b) in keys_values]

    plt.figure(figsize=(10,8))
    plt.bar(x_pos, y_data)


    # zip joins x and y coordinates in pairs
    for x,y in zip(x_pos,y_data):

        label = "{:.0f}".format(y)

        plt.annotate(label, # this is the text
                     (x,y), # this is the point to label
                     textcoords="offset points", # how to position the text
                     xytext=(0,10), # distance from text to points (x,y)
                     ha='center') # horizontal alignment can be left, right or center

    plt.title(img_title)
    plt.ylabel(img_ylabel)
    plt.xlabel(img_xlabel)
    plt.xticks(x_pos, tuple(x_labels))

    plt.savefig(outfile)

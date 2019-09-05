## Copyright (c) 2019 AT&T Intellectual Property. All rights reserved.

## Given a list of CVE's, Draw a cve/pkg/svr pic
from load_db import load_file
from load_db import pkg_subset
from load_db import svr_subset
import networkx as nx
import matplotlib.pyplot as plt
from networkx.drawing.nx_agraph import write_dot, graphviz_layout

def draw_digraph(infile,cves,outfile):
    data = load_file(infile)
    pkgs = pkg_subset(data, cves)
    svrs = svr_subset(data, pkgs)

    label = {}

    G = nx.DiGraph()
    for cve in cves:
        G.add_node(cve)
        cvss = data.nodes[cve]['cvss']
        supressed = data.nodes[cve]['suppressed']
        label[cve] = "{0}\n cvss={1}".format(cve,cvss)
        if supressed:
            label[cve] += "\n/supressed"
        for pkg in pkgs:
            G.add_node(pkg)
            label[pkg] = pkg
            if pkg in data.neighbors(cve):
                G.add_edge(cve, pkg)
        for svr in svrs:
            G.add_node(svr)
            ## find group & hostname for label
            for neighbor in data.neighbors(svr):
                if neighbor in data.neighbors('type_group'):
                    group = neighbor
                elif neighbor in data.neighbors('type_hostname'):
                    hostname = neighbor
            label[svr] = "{0}\n{1}\n{2}".format(group,hostname,svr)
            for pkg in pkgs:
                if svr in data.neighbors(pkg):
                    G.add_edge(pkg, svr)
    pos=graphviz_layout(G, prog='dot')

    nx.draw_networkx_nodes(G,
                           pos,
                           nodelist = cves,
                           node_color = 'r',
                           node_size = 500,
                           alpha = 0.8)

    nx.draw_networkx_nodes(G,
                           pos,
                           nodelist = pkgs,
                           node_color = 'b',
                           node_size = 400,
                           alpha = 0.8)
    nx.draw_networkx_nodes(G,
                           pos,
                           nodelist = svrs,
                           node_color = '#DDDDDD',
                           node_size = 300,
                           alpha = 0.8)
    nx.draw_networkx_edges(G, pos)
    nx.draw_networkx_labels(G,pos,label, font_size = 10)

    plt.axis('off')
    plt.savefig(outfile)

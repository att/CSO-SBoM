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
import matplotlib as mpl


def line_image(data, params):
    ## from input data, create a line graph image, store in outfile
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

    plt.figure(figsize=(17,11))
    plt.plot(x_pos, y_data)
    
    # zip joins x and y coordinates in pairs
    for x,y in zip(x_pos,y_data):

        label = "{:.0f}".format(y)

        plt.annotate(label, # this is the text
                     (x,y), # this is the point to label
                     textcoords="offset points", # how to position the text
                     fontweight=1000, # boldness of text
                     xytext=(0,10), # distance from text to points (x,y)
                     rotation=300, # rotation in degrees of the label text
                     rotation_mode='anchor', # text will be first aligned to horiz and vert axis before rotation
                     ha='center') # horizontal alignment can be left, right or center
    plt.title(img_title)
    plt.ylabel(img_ylabel)
    plt.xlabel(img_xlabel)
    plt.xticks(x_pos, tuple(x_labels),rotation=90)

    plt.savefig(outfile)

## Copyright (c) 2020 AT&T Intellectual Property. All rights reserved.

## routine for creating stacked bar graph

from sbom_helpers import get_anlpath
import numpy
import matplotlib.pyplot as plt
import matplotlib as mpl


def multi_line_image(data, params):
    ## from input data, create a stacked bar chart image, store in outfile
    filename = params['filename']
    outfile = get_anlpath() + filename
    img_title = params['title']
    img_ylabel = params['ylabel']
    img_xlabel = params['xlabel']
    colors = params['colors']
    linestyle = params['linestyle']

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
        this_group_series.append(data[d][g] )
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
      this_list = [seriesList[s-1][d] for d in ld ]
      bottoms.append( this_list )

    fig = plt.figure(figsize=(17,11))
    ax = fig.add_subplot(111)
#    fig, (ax1, ax2) = plt.subplot(1, 2)
    lines = []

    for i in range(len(seriesList)):
      lines.append( plt.plot(ind, seriesList[i], color=colors[i], linestyle=linestyle[i], linewidth=5) )    # 

    slna = numpy.array(seriesList)


# search all of the bar segments and annotate
#    for j in range(len(lines)):
#        print(len(lines))
#        for i, patch in enumerate(lines[j]):
#            print(lines[j])# returned [<matplotlib.lines.Line2D object at 0x7fd389667048>] 5 times LEFT OFF HERE 05/04/2020
#            bl = patch.get_xy() 
#            y = 0.5*patch.get_width() + bl[0] 
#            x = 0.5*patch.get_height() + bl[1] 
#            mpl.rcParams['text.color'] = 'black'
#            mpl.rcParams['font.size'] = 11 
#            mpl.rcParams['font.weight'] = 700
#            ax.text(ind,N, (slna[j,i]), ha='center') 

    plt.title(img_title)
    plt.ylabel(img_ylabel)
    plt.xlabel(img_xlabel)
    plt.xticks(ind, tuple(dates),rotation=90) 
    plt.legend(tuple([ p[0] for p in lines ] ), tuple(groups), loc='upper right', bbox_to_anchor=(1.1, 1.14))
#    plt.show()
    plt.savefig(outfile)

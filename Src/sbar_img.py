## Copyright (c) 2020 AT&T Intellectual Property. All rights reserved.

## routine for creating stacked bar graph

from sbom_helpers import get_anlpath
import numpy
import matplotlib.pyplot as plt
import matplotlib as mpl


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

    fig = plt.figure(figsize=(10,8))
    ax = fig.add_subplot(111)
    bars = []
    for i in range(len(seriesList)):
      bars.append( plt.bar(ind, seriesList[i], bottom=bottoms[i], color=colors[i] ) )    

    slna = numpy.array(seriesList)
# search all of the bar segments and annotate
    for j in range(len(bars)):
        for i, patch in enumerate(bars[j].get_children()): 
            bl = patch.get_xy() 
            y = 0.5*patch.get_width() + bl[0] 
            x = 0.5*patch.get_height() + bl[1] 
            mpl.rcParams['text.color'] = 'black'
            mpl.rcParams['font.size'] = 11 
            mpl.rcParams['font.weight'] = 700  
            ax.text(y,x, (slna[j,i]), ha='center') 

    plt.title(img_title)
    plt.ylabel(img_ylabel)
    plt.xlabel(img_xlabel)
    plt.xticks(ind, tuple(dates)) 
    plt.legend(tuple( [ p[0] for p in bars ] ), tuple(groups))

    plt.savefig(outfile)


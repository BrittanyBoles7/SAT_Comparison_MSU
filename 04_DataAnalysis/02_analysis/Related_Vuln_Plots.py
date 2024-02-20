import sys
from pathlib import Path

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import os
import requests
import math


def get_data():
    G_CPE = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/CPEG0_73_0.csv", na_filter=False)
    # G_CPE = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/G0_73_0.csv", na_filter=False)


    #we wanted related count
    df_g = pd.DataFrame(columns=['image_name', 'vuln_id', 'severity', 'count', 'related_vuln', 'r_count'])

    co = 0
    for i, a, image, vuln_id, severity, count, related_vuln in G_CPE.itertuples(): # tuples are faster

        if related_vuln == "NA":  # there's not a related vulnerability, so we don't include in the analysis
            pass
        elif "," in related_vuln:
            things = related_vuln.split(",")  # sometimes there is multiple related vulnerabilities, get count of each of them.
            for t in range(1, len(things)):
                hold = things[t]
                new_row = [image, vuln_id, severity, int(count), hold, 0] # start with related count at zero, if other vuln is found update count
                for j, ra, rimage, rvuln_id, rseverity, rcount, rrelated_vuln in G_CPE.itertuples():
                    if rimage == image:
                        if rvuln_id == hold:
                            new_row = [image, vuln_id, severity, int(count), hold, rcount]

                            co = co + 1
                    else:
                        pass
                df_g.loc[len(df_g.index)] = new_row

        else:
            new_row = [image, vuln_id, severity, int(count), related_vuln, 0]
            for j, ra, rimage, rvuln_id, rseverity, rcount, rrelated_vuln in G_CPE.itertuples():
                  # start with related count at zero, if other vuln is found update count
                if rimage == image:
                    if rvuln_id == related_vuln:
                        new_row = [image, vuln_id, severity,int(count), related_vuln, rcount]

                        co = co + 1
                else:
                    pass
            df_g.loc[len(df_g.index)] = new_row

    df_g.to_csv("/home/brittanyboles/msusel-SATComparison-Pipe/04_DataAnalysis/02_analysis/"+ 'Grype_CPE_related.csv',index = False)


def graph():
    df_g = pd.read_csv("/home/brittanyboles/msusel-SATComparison-Pipe/04_DataAnalysis/02_analysis/"+ 'Grype_related.csv', na_filter=False)
    x =df_g.get('count').values
    y =df_g.get('r_count').values

    plt.figure(figsize=(8, 8))
    plt.scatter(x, y, marker='o', edgecolor='none', color=(0.5, 0.7, 0.95))

    df_g2 = pd.read_csv(
        "/home/brittanyboles/msusel-SATComparison-Pipe/04_DataAnalysis/02_analysis/" + 'Grype_CPE_related.csv',
        na_filter=False)
    x2 = df_g2.get('count').values
    y2 = df_g2.get('r_count').values


    plt.scatter(x2, y2, marker='o', edgecolor='none', color=(0.5, 0.7, 0.95))

    # Legend outside of the figure
    custom_legend = [
        plt.Line2D([0], [0], color=(0.5, 0.7, 0.95), lw=4, label='Grype'),
        plt.Line2D([0], [0], color='blue', lw=4, label='Grype CPE'),
    ]
    plt.legend(handles=custom_legend, loc='upper left', fontsize='large', bbox_to_anchor=(1, 1))

    plt.xlabel("Vulnerability Per Image", fontsize='large')
    plt.ylabel("Related Vulnerability Per Image", fontsize='large')

    plt.axis('equal')  # Ensures equal aspect ratio
    plt.xticks(range(0, max(max(x), max(y)) + 1, 5))  # Set x-axis ticks from 0 to 30 with a step of 5
    plt.yticks(range(0, max(max(x), max(y)) + 1, 5))  # Set y-axis ticks from 0 to 30 with a step of 5
    plt.tick_params(axis='both', which='major', labelsize='large')  # Increase tick label size

    # Adjust axis limits to improve alignment
    max_value = max(max(x), max(y)) + 5
    plt.xlim(-.1, max_value)
    plt.ylim(-.1, max_value)

    plt.show()
    print("check")


get_data()
#graph()
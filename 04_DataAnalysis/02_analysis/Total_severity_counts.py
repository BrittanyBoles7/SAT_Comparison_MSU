import sys
from pathlib import Path
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt


def severity_difference():
    G_73 = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/G0_73_0.csv", na_filter=False)
    T_49 = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Trivy/T0_49_0.csv", na_filter=False)

    G_73 = G_73[G_73['image_name'] != "golang:1.4rc1"]

    T_49 = T_49[T_49['image_name'] != "alpine:3.17.1"]
    T_49 = T_49[T_49['image_name'] != "alpine:3.18.5"]
    T_49 = T_49[T_49['image_name'] != "alpine:3.18.2"]

    # Convert 'count' columns to numeric to ensure they are integers
    G_73['count'] = pd.to_numeric(G_73['count'], errors='coerce')
    T_49['count'] = pd.to_numeric(T_49['count'], errors='coerce')

    image_names = np.unique(G_73['image_name'])

    plot_stacked_bar(image_names, G_73, T_49)

    plt.show()

def plot_stacked_bar(data, g, t):
    # summing up severities of top ten images for Grype

    negligible_g = []
    unknown_g = []
    low_g = []
    medium_g = []
    high_g = []
    critical_g = []
    sum_top_ten = 0
    for i in data:

        hold = g[g['image_name'] == i]
        sum_top_ten = sum_top_ten + np.sum(hold['count'])

        n_count = hold[hold['severity'] == 'Negligible']
        negligible_g.append((np.sum(n_count['count'])))

        u_count = hold[hold['severity'] == 'Unknown']
        unknown_g.append(np.sum(u_count['count']))

        l_count = hold[hold['severity'] == 'Low']
        low_g.append(np.sum(l_count['count']))

        m_count = hold[hold['severity'] == 'Medium']
        medium_g.append(np.sum(m_count['count']))

        h_count = hold[hold['severity'] == 'High']
        high_g.append(np.sum(h_count['count']))

        c_count = hold[hold['severity'] == 'Critical']
        critical_g.append(np.sum(c_count['count']))

    # check to make sure we didn't miss a label.
    check = sum_top_ten - np.sum(unknown_g) - np.sum(low_g) - np.sum(medium_g) - np.sum(high_g) - np.sum(critical_g)
    if check != 0:
        print("wrong we missed a severity type: ", check)
    print("neg: ", np.sum(negligible_g), " unknown: ", np.sum(unknown_g),
          " low: ", np.sum(low_g), " medium: ", np.sum(medium_g), " high: ",
          np.sum(high_g), " critical: ", np.sum(critical_g))


    # summing up top ten vulnerabilities for Trivy
    unknown = []
    negligible = []
    low = []
    medium = []
    high = []
    critical = []
    sum_top_ten = 0
    for i in data:
        hold = t[t['image_name'] == i]
        sum_top_ten = sum_top_ten + np.sum(hold['count'])

        n_count = hold[hold['severity'] == 'Negligible']
        negligible_g.append((np.sum(n_count['count'])))

        u_count = hold[hold['severity'] == 'UNKNOWN']
        unknown.append(np.sum(u_count['count']))

        l_count = hold[hold['severity'] == 'LOW']
        low.append(np.sum(l_count['count']))

        m_count = hold[hold['severity'] == 'MEDIUM']
        medium.append(np.sum(m_count['count']))

        h_count = hold[hold['severity'] == 'HIGH']
        high.append(np.sum(h_count['count']))

        c_count = hold[hold['severity'] == 'CRITICAL']
        critical.append(np.sum(c_count['count']))

        # check to make sure we didn't miss a label.
    check = sum_top_ten - np.sum(unknown) - np.sum(low) - np.sum(medium) - np.sum(high) - np.sum(critical)
    if check != 0:
        print("wrong we missed a severity type: ", check)
    print("neg: ", np.sum(negligible), " unknown: ", np.sum(unknown),
          " low: ", np.sum(low), " medium: ", np.sum(medium), " high: ",
          np.sum(high), " critical: ", np.sum(critical))




severity_difference()

import sys
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns



def get_related_counts():
    df = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/G0_73_0.csv", na_filter=False)
    df = df[df['image_name'] != "golang:1.4rc1"]
    # filtering data
    df_r = df[df['related_vuln'] != "NA"]

    # we wanted related count
    df_g = pd.DataFrame(columns=['image_name', 'vuln_id', 'severity', 'count', 'related_vuln', 'r_count'])

    for i, a, image, vuln_id, severity, count, related_vuln in df_r.itertuples():  # tuples are faster
        df_image = df[df['image_name'] == image]
        if "," in related_vuln:
            things = related_vuln.split(
                ",")  # sometimes there is multiple related vulnerabilities, get count of each of them.
            for t in range(1, len(things)):
                hold = things[t]
                new_row = [image, vuln_id, severity, int(count), hold,0]  # start with related count at zero, if other vuln is found update count
                for j, ra, rimage, rvuln_id, rseverity, rcount, rrelated_vuln in df_image.itertuples():
                    if rvuln_id == hold:
                        new_row = [image, vuln_id, severity, int(count), hold, rcount]

                df_g.loc[len(df_g.index)] = new_row

        else:
            new_row = [image, vuln_id, severity, int(count), related_vuln, 0]
            for j, ra, rimage, rvuln_id, rseverity, rcount, rrelated_vuln in df_image.itertuples():
                # start with related count at zero, if other vuln is found update count

                if rvuln_id == related_vuln:
                    new_row = [image, vuln_id, severity, int(count), related_vuln, rcount]

            df_g.loc[len(df_g.index)] = new_row

    df_g.to_csv(
        "/home/brittanyboles/msusel-SATComparison-Pipe/04_DataAnalysis/02_analysis/" + 'FGrype_73_related.csv',
        index=False)
    print("nothing")

# graph different related vulnerability graph against each other.
def graph_side_by_side():
    # Read the CSV files
    df_g_CPE = pd.read_csv(
        "/home/brittanyboles/msusel-SATComparison-Pipe/04_DataAnalysis/02_analysis/FGrype_69_related.csv",
        na_filter=False)
    df_g = pd.read_csv(
        "/home/brittanyboles/msusel-SATComparison-Pipe/04_DataAnalysis/02_analysis/FGrype_73_related.csv",
        na_filter=False)

    # for version 73
    x = df_g.get('count').values
    y = df_g.get('r_count').values
    df = count_per_combo(x, y)

    # Extract x and y coordinates and count of occurrences
    x_coords = [pair[0] for pair in df['(x, y)']]
    y_coords = [pair[1] for pair in df['(x, y)']]
    counts = df['count']

    # for version 69 with cpe matching
    x_cpe = df_g_CPE.get('count').values
    y_cpe = df_g_CPE.get('r_count').values
    df_cpe = count_per_combo(x_cpe, y_cpe)

    # Extract x and y coordinates and count of occurrences
    x_coords_cpe = [pair[0] for pair in df_cpe['(x, y)']]
    y_coords_cpe = [pair[1] for pair in df_cpe['(x, y)']]
    counts_cpe = df_cpe['count']

    # Create two subplots side by side
    fig, axes = plt.subplots(1, 2, figsize=(20, 8))

    max_value = max(max(max(x_cpe), max(x)), max(max(y_cpe), max(y)))
    # max_value = 40

    #sns.kdeplot(x=x_coords_cpe, y=y_coords_cpe, alpha=0.5, c="blue", ax= axes[0])
    sns.kdeplot(x=x_coords_cpe, y=y_coords_cpe, alpha=0.5, cmap='viridis_r', fill=True, ax=axes[0])
    sc1 = axes[0].scatter(x_coords_cpe, y_coords_cpe, s=50, c=counts_cpe, cmap='viridis_r', alpha=1, edgecolors='k',
                          vmax=max(max(counts), max(counts_cpe)), vmin=min(min(counts_cpe), min(counts)))

    axes[0].plot([0, max_value], [0, max_value], color='blue', linestyle='-', linewidth=2)
    axes[0].set_title('Grype V0.69.0', fontsize=20)
    #axes[0].set_xlabel('Vendor Vulnerability Count', fontsize=20)
    axes[0].set_ylabel('Related Vulnerability Count', fontsize=22)
    plt.xticks(rotation=45, ha='right')

    # setting axis so that both graphs have the same bounds
    axes[0].set_xticks(range(0, max_value + 5, 10))
    axes[0].set_yticks(range(0, max_value + 5, 10))
    axes[0].tick_params(labelsize=18)  # Increase tick label size

    axes[0].set_xlim(-1, max_value + 1)
    axes[0].set_ylim(-1, max_value + 1)
    axes[0].set_aspect('equal')  # Set aspect ratio to be equal

    #sns.kdeplot(x=x_coords, y=y_coords, alpha=0.5, c="blue", ax=axes[1])
    sns.kdeplot(x=x_coords, y=y_coords, alpha=0.5, cmap='viridis_r', fill=True,ax=axes[1])
    sc2 = axes[1].scatter(x_coords, y_coords, s=50, c=counts, edgecolors='k', cmap='viridis_r',
                          vmax=max(max(counts), max(counts_cpe)), vmin=min(min(counts_cpe), min(counts)), alpha=1)


    # Diagonal line of expect values
    axes[1].plot([0, max_value], [0, max_value], color='blue', linestyle='-', linewidth=2)
    axes[1].set_title('Grype v0.73.0', fontsize=20)
    #axes[1].set_xlabel('Vulnerability Per Image', fontsize=20)
    plt.xticks(rotation=45, ha='right')

    # setting axis so that both graphs have the same bounds
    axes[1].set_xticks(range(0, max_value + 5, 10))
    axes[1].set_yticks(range(0, max_value + 5, 10))
    axes[1].tick_params(labelsize=18)  # Increase tick label size

    axes[1].set_xlim(-1, max_value + 1)
    axes[1].set_ylim(-1, max_value + 1)
    axes[1].set_aspect('equal')  # Set aspect ratio to be equal

    # Hide x labels and tick labels for top plots and y ticks for right plots.
    for ax in axes.flat:
        ax.label_outer()

    # Add common x-axis label centered between the two graphs
    fig.text(0.45, 0.06, 'Vulnerability Count', ha='center', fontsize=20)

    # Add color bar
    cbar = plt.colorbar(sc2, ax=axes.ravel().tolist())
    cbar.set_label(label='Number of Occurrences', size=20)
    cbar.ax.tick_params(labelsize=18)

    custom_legend = [
        plt.Line2D([0], [0], color='blue', lw=4, label='Expected Values')
    ]
    plt.legend(handles=custom_legend, loc='upper right')

    plt.show()
    print("check")

def sum_total_vulns():
    # Read the CSV files
    df_69 = pd.read_csv(
        "/home/brittanyboles/msusel-SATComparison-Pipe/04_DataAnalysis/02_analysis/FGrype_69_related.csv",
        na_filter=False)
    df_73 = pd.read_csv(
        "/home/brittanyboles/msusel-SATComparison-Pipe/04_DataAnalysis/02_analysis/FGrype_73_related.csv",
        na_filter=False)
   #new branch
    grype = df_69[df_69['r_count'] != 0]
    add = []
    for g in grype.iterrows():
        #print(g[1]['image_name'])
        add.append(g[1]['image_name'])
    a = set(add)
    print(a)
    # hold = np.array(df_69['r_count']).astype(float)
    # total = hold.sum()
    # print("69 number related reported: ", total)
    # hold = np.array(df_73['r_count']).astype(float)
    # total = hold.sum()
    # print("73 number related reported: ", total)
    # a = df_69['r_count'].max()
    # filter = df_69[df_69['r_count'] == df_69['count']]
    # print(len(filter), " the percent: ", len(filter)/30182)
    # filter = df_73[df_73['r_count'] == df_73['count']]
    # print(len(filter), " the percent: ", len(filter) / 30519)




# we want to see the number of times a certain ratio of related to regular vulnerabilities occur.
def count_per_combo(x, y):
    # Create a dictionary to count occurrences of each unique (x, y) pair
    pair_count = {}
    for i in range(len(x)):
        pair = (x[i], y[i])
        pair_count[pair] = pair_count.get(pair, 0) + 1

    # Convert the dictionary to a DataFrame
    df = pd.DataFrame(list(pair_count.items()), columns=['(x, y)', 'count'])
    return df

#get_related_counts()
sum_total_vulns()
#graph_side_by_side()


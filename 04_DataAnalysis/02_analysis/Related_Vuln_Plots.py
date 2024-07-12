import sys
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns


def main():
    # only do once
    #get_related_counts3(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/CPE_G0_73_0test.csv","Grype_CPE_relatedtest.csv")
    #get_related_counts3(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/G0_73_0test.csv", "Grype_73_relatedtest.csv")

    # scatter plots of the differences between Grypes configurations and related vulnerability counts
    #graph_side_by_side2()
    #check they don't get reported
    # total number of vulnerabilities reported with related vulnerabilities ( not unique)
    sum_total_vulns()

def get_related_counts(tool_path, output_path):
    """Runs and gets the total number of times related vulnerabilities occur and saves out to file. """
    df = pd.read_csv(tool_path, na_filter=False)
    df = df[df['image_name'] != "golang:1.4rc1"]
    # filtering data
    df_r = df[df['related_vuln'] != "NA"]

    # we wanted related count
    df_g = pd.DataFrame(columns=['image_name', 'vuln_id', 'severity', 'count', 'related_vuln', 'r_count'])

    for i, a, image, vuln_id, severity, count, related_vuln in df_r.itertuples():  # tuples are faster
        df_image = df[df['image_name'] == image]
        if "," in related_vuln:
            things = related_vuln.split(",")  # sometimes there is multiple related vulnerabilities, get count of each of them.

            for t in range(1, len(things)):
                hold = things[t]
                new_row = [image, vuln_id, severity, int(count), hold, 0]  # start with related count at zero, if other vuln is found update count
                for j, ra, rimage, rvuln_id, rseverity, rcount, rrelated_vuln in df_image.itertuples():
                    if rvuln_id == hold:
                        new_row = [image, vuln_id, severity, int(count), hold, rcount]
                    if len(things) > 2 and rvuln_id == hold:
                        print(new_row)

                df_g.loc[len(df_g.index)] = new_row

        else:
            new_row = [image, vuln_id, severity, int(count), related_vuln, 0]
            for j, ra, rimage, rvuln_id, rseverity, rcount, rrelated_vuln in df_image.itertuples():
                # start with related count at zero, if other vuln is found update count

                if rvuln_id == related_vuln:
                    new_row = [image, vuln_id, severity, int(count), related_vuln, rcount]

            df_g.loc[len(df_g.index)] = new_row

    df_g.to_csv(
        "/home/brittanyboles/msusel-SATComparison-Pipe/04_DataAnalysis/02_analysis/" + output_path,
        index=False)
    print("nothing")

def get_related_counts2(tool_path, output_path):
    """Runs and gets the total number of times related vulnerabilities occur and saves out to file. """

    # reading in and cleaning up dataframe
    df = pd.read_csv(tool_path, na_filter=False)
    df = df[df['image_name'] != "golang:1.4rc1"]
    df = df.drop('Unnamed: 0', axis=1)
    h = df[df['vuln_id'] != 'NA']
    list_counts = h['count'].values

    sum_counts = sum([int(i) for i in list_counts])

    # filtering data
    df_r = df[df['related_vuln'] != "NA"]

    list_counts = df_r['count'].values
    sum_counts = sum([int(i) for i in list_counts])

    # we wanted related count
    df_g = pd.DataFrame(columns=['image_name', 'vuln_id', 'vuln_source', 'severity', 'count', 'related_vuln', 'related_vuln_source', 'r_count'])

    # given a vulnerability, look for if there was a related one reported in the same image.
    for i,  image, vuln_id, vuln_source, severity, count, related_vuln, related_vuln_source in df_r.itertuples():
        df_image = df[df['image_name'] == image]

        if "," in related_vuln:
            multiple_related_vuln = related_vuln.split(",")  # sometimes there is multiple related vulnerabilities, get count of each of them.

            for t in range(1, len(multiple_related_vuln)):
                related_vuln_current = multiple_related_vuln[t]
                new_row = [image, vuln_id, vuln_source, severity, int(count), related_vuln_current, related_vuln_source, 0]

                for j, rimage, rvuln_id, rvuln_source, rseverity, rcount, rrelated_vuln, rrelated_vuln_source in df_image.itertuples():
                    if rvuln_source != related_vuln_source:
                        pass
                    elif rvuln_source == related_vuln_source:
                        pass
                    # make sure they aren't the same thing
                    if rvuln_id == related_vuln_current and rvuln_source != related_vuln_source and related_vuln_current == vuln_id:
                        new_row = [image, vuln_id, vuln_source, severity, int(count), related_vuln_current, related_vuln_source, rcount]
                    elif rvuln_id == related_vuln_current and related_vuln_current != vuln_id:
                        new_row = [image, vuln_id, vuln_source, severity, int(count), related_vuln_current, related_vuln_source, rcount]
                    if len(multiple_related_vuln) > 2 and rvuln_id == related_vuln_current:
                        print(new_row)

                df_g.loc[len(df_g.index)] = new_row

        else:
            new_row = [image, vuln_id, vuln_source, severity, int(count), related_vuln, related_vuln_source, 0]
            for j, rimage, rvuln_id, rvuln_source, rseverity, rcount, rrelated_vuln, rrelated_vuln_source in df_image.itertuples():
                # start with related count at zero, if other vuln is found update count
                if rvuln_source != related_vuln_source:
                    pass
                elif rvuln_source == related_vuln_source:
                    pass
                if rvuln_id == related_vuln and rvuln_source != related_vuln_source and related_vuln == vuln_id:
                    new_row = [image, vuln_id, vuln_source, severity, int(count), related_vuln, related_vuln_source, rcount]
                elif rvuln_id == related_vuln and related_vuln != vuln_id:
                    new_row = [image, vuln_id, vuln_source, severity, int(count), related_vuln, related_vuln_source,
                               rcount]

            df_g.loc[len(df_g.index)] = new_row

    df_g.to_csv(
        "/home/brittanyboles/msusel-SATComparison-Pipe/04_DataAnalysis/02_analysis/" + output_path,
        index=False)
    print("nothing")

def get_related_counts3(tool_path, output_path):
    """Runs and gets the total number of times related vulnerabilities occur and saves out to file. """

    # reading in and cleaning up dataframe
    df = pd.read_csv(tool_path, na_filter=False)
    df = df[df['image_name'] != "golang:1.4rc1"]
    df = df.drop('Unnamed: 0', axis=1)
    h = df[df['vuln_id'] != 'NA']

    list_counts = h['count'].values
    sum_counts = sum([int(i) for i in list_counts])

    # filtering data
    df_r = h[h['related_vuln'] != "NA"]

    list_counts = df_r['count'].values
    sum_counts = sum([int(i) for i in list_counts])

    # we wanted related count
    df_g = pd.DataFrame(columns=['image_name', 'vuln_id', 'vuln_source', 'severity', 'count', 'related_vuln', 'related_vuln_source', 'r_count'])

    # given a vulnerability, look for if there was a related one reported in the same image.
    for i,  image, vuln_id, vuln_source, severity, count, related_vuln, related_vuln_source in df_r.itertuples():
        df_image = h[h['image_name'] == image]

        if "," in related_vuln:

            multiple_related_vuln = related_vuln.split(",")  # sometimes there is multiple related vulnerabilities, get count of each of them.
            multiple_related_source = related_vuln_source.split(",")
            for t in range(1, len(multiple_related_vuln)):
                related_vuln_current = multiple_related_vuln[t]
                related_source_current = multiple_related_source[t]
                new_row = search_related_vuln(image,vuln_id,vuln_source,severity,count,related_vuln_current,related_source_current,df_image)

                df_g.loc[len(df_g.index)] = new_row

        else:
            new_row = search_related_vuln(image, vuln_id, vuln_source, severity, count,related_vuln,
                                          related_vuln_source, df_image)
            df_g.loc[len(df_g.index)] = new_row

    df_g.to_csv(
        "/home/brittanyboles/msusel-SATComparison-Pipe/04_DataAnalysis/02_analysis/" + output_path,
        index=False)
    print("nothing")

def search_related_vuln(image, vuln_id, vuln_source, severity, count, related_vuln_current, related_vuln_source,df_image):

    new_row = [image, vuln_id, vuln_source, severity, int(count), related_vuln_current, related_vuln_source, 0]

    df_vuln = df_image[df_image['vuln_id'] == related_vuln_current] # get only ids in this image, which have the same id as the related one
    if len(df_vuln) == 0: # no related ids in the same image
        pass
    else:
        for r,i, vi, vs, s, c, rv, rs in df_vuln.itertuples():
            if related_vuln_current != vuln_id: # if they are related but different ids
                new_row = [image, vuln_id, vuln_source, severity, int(count), related_vuln_current, related_vuln_source, c]
            elif vs == related_vuln_source: # if they are related with same id but different data sources
                new_row = [image, vuln_id, vuln_source, severity, int(count), related_vuln_current, related_vuln_source, c]

    return new_row
def graph_side_by_side2():
    """ graph different related vulnerability graph against each other."""
    # Read the CSV files
    df_g_CPE = pd.read_csv(
        "/home/brittanyboles/msusel-SATComparison-Pipe/04_DataAnalysis/02_analysis/Grype_CPE_relatedtest.csv",
        na_filter=False)
    df_g = pd.read_csv(
        "/home/brittanyboles/msusel-SATComparison-Pipe/04_DataAnalysis/02_analysis/Grype_73_relatedtest.csv",
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

    # sns.kdeplot(x=x_coords_cpe, y=y_coords_cpe, alpha=0.5, c="blue", ax= axes[0])
    sns.kdeplot(x=x_coords_cpe, y=y_coords_cpe, alpha=0.5, cmap='viridis_r', fill=True, ax=axes[0])
    sc1 = axes[0].scatter(x_coords_cpe, y_coords_cpe, s=50, c=counts_cpe, cmap='viridis_r', alpha=1, edgecolors='k',
                          vmax=max(max(counts), max(counts_cpe)), vmin=min(min(counts_cpe), min(counts)))

    axes[0].plot([0, max_value], [0, max_value], color='blue', linestyle='-', linewidth=2)
    axes[0].set_title('Grype With CPE Matching', fontsize=20)
    # axes[0].set_xlabel('Vendor Vulnerability Count', fontsize=20)
    axes[0].set_ylabel('Related Vulnerability Count', fontsize=22)
    plt.xticks(rotation=45, ha='right')

    # setting axis so that both graphs have the same bounds
    axes[0].set_xticks(range(0, max_value + 5, 10))
    axes[0].set_yticks(range(0, max_value + 5, 10))
    axes[0].tick_params(labelsize=18)  # Increase tick label size

    axes[0].set_xlim(-1, max_value + 1)
    axes[0].set_ylim(-1, max_value + 1)
    axes[0].set_aspect('equal')  # Set aspect ratio to be equal

    # sns.kdeplot(x=x_coords, y=y_coords, alpha=0.5, c="blue", ax=axes[1])
    sns.kdeplot(x=x_coords, y=y_coords, alpha=0.5, cmap='viridis_r', fill=True, ax=axes[1])
    sc2 = axes[1].scatter(x_coords, y_coords, s=50, c=counts, edgecolors='k', cmap='viridis_r',
                          vmax=max(max(counts), max(counts_cpe)), vmin=min(min(counts_cpe), min(counts)), alpha=1)

    # Diagonal line of expect values
    axes[1].plot([0, max_value], [0, max_value], color='blue', linestyle='-', linewidth=2)
    axes[1].set_title('Grype Without CPE Matching', fontsize=20)
    # axes[1].set_xlabel('Vulnerability Per Image', fontsize=20)
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

def graph_side_by_side():
    """ graph different related vulnerability graph against each other."""
    # Read the CSV files
    df_g_CPE = pd.read_csv(
        "/home/brittanyboles/msusel-SATComparison-Pipe/04_DataAnalysis/02_analysis/Grype_CPE_related.csv",
        na_filter=False)
    df_g = pd.read_csv(
        "/home/brittanyboles/msusel-SATComparison-Pipe/04_DataAnalysis/02_analysis/Grype_73_related.csv",
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

    # sns.kdeplot(x=x_coords_cpe, y=y_coords_cpe, alpha=0.5, c="blue", ax= axes[0])
    sns.kdeplot(x=x_coords_cpe, y=y_coords_cpe, alpha=0.5, cmap='viridis_r', fill=True, ax=axes[0])
    sc1 = axes[0].scatter(x_coords_cpe, y_coords_cpe, s=50, c=counts_cpe, cmap='viridis_r', alpha=1, edgecolors='k',
                          vmax=max(max(counts), max(counts_cpe)), vmin=min(min(counts_cpe), min(counts)))

    axes[0].plot([0, max_value], [0, max_value], color='blue', linestyle='-', linewidth=2)
    axes[0].set_title('Grype With CPE Matching', fontsize=20)
    # axes[0].set_xlabel('Vendor Vulnerability Count', fontsize=20)
    axes[0].set_ylabel('Related Vulnerability Count', fontsize=22)
    plt.xticks(rotation=45, ha='right')

    # setting axis so that both graphs have the same bounds
    axes[0].set_xticks(range(0, max_value + 5, 10))
    axes[0].set_yticks(range(0, max_value + 5, 10))
    axes[0].tick_params(labelsize=18)  # Increase tick label size

    axes[0].set_xlim(-1, max_value + 1)
    axes[0].set_ylim(-1, max_value + 1)
    axes[0].set_aspect('equal')  # Set aspect ratio to be equal

    # sns.kdeplot(x=x_coords, y=y_coords, alpha=0.5, c="blue", ax=axes[1])
    sns.kdeplot(x=x_coords, y=y_coords, alpha=0.5, cmap='viridis_r', fill=True, ax=axes[1])
    sc2 = axes[1].scatter(x_coords, y_coords, s=50, c=counts, edgecolors='k', cmap='viridis_r',
                          vmax=max(max(counts), max(counts_cpe)), vmin=min(min(counts_cpe), min(counts)), alpha=1)

    # Diagonal line of expect values
    axes[1].plot([0, max_value], [0, max_value], color='blue', linestyle='-', linewidth=2)
    axes[1].set_title('Grype Without CPE Matching', fontsize=20)
    # axes[1].set_xlabel('Vulnerability Per Image', fontsize=20)
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
    df_73 = pd.read_csv("/home/brittanyboles/msusel-SATComparison-Pipe/04_DataAnalysis/02_analysis/Grype_CPE_relatedtest.csv",na_filter=False)
    #df_70 = pd.read_csv("/home/brittanyboles/msusel-SATComparison-Pipe/03_Processing/04_product/Grype/CPE_G0_73_0test.csv", na_filter=False)
    #df_73 = pd.read_csv(
     #   "/home/brittanyboles/msusel-SATComparison-Pipe/04_DataAnalysis/02_analysis/Grype_73_relatedtest.csv",na_filter=False)

    #hold = np.array(df_69['count']).astype(float)
    #total = hold.sum()
    #print("69 number related reported: ", total)

    hold = np.array(df_73['r_count']).astype(float)
    total1 = hold.sum()
    print("73 number related reported: ", total1)

    check = df_73[df_73['r_count'] != 0]

    #vuln_count_69 = np.array(df_69['count']).astype(float)
    #total_vuln = vuln_count_69.sum()
    #print("69 number vuln reported: ", total_vuln)

    vuln_count_73 = np.array(df_73['count']).astype(float)
    total_vuln_73 = vuln_count_73.sum()
    print("73 number vuln reported: ", total_vuln_73)

    #a = df_69[df_69['r_count'] == 95]

    #filter = df_69[df_69['r_count'] == df_69['count']]
    #print(len(filter), " the percent: ", len(filter) / total)
    filter = df_73[df_73['r_count'] == df_73['count']]
    print(len(filter), " the percent: ", len(filter) / total1)


def count_per_combo(x, y):
    """ we want to see the number of times a certain ratio of related to regular vulnerabilities occur."""
    # Create a dictionary to count occurrences of each unique (x, y) pair
    pair_count = {}
    for i in range(len(x)):
        pair = (x[i], y[i])
        pair_count[pair] = pair_count.get(pair, 0) + 1

    # Convert the dictionary to a DataFrame
    df = pd.DataFrame(list(pair_count.items()), columns=['(x, y)', 'count'])
    return df


main()

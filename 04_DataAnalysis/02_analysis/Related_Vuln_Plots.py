import sys
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt

# need to get counts of related vulnerabilities in the same image, we save this out in a csv file
# lets move this earlier in the process later?
def get_data():
    G_CPE = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/G0_69_0.csv", na_filter=False)
    # G_CPE = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/G0_73_0.csv", na_filter=False)

    # we wanted related count
    df_g = pd.DataFrame(columns=['image_name', 'vuln_id', 'severity', 'count', 'related_vuln', 'r_count'])

    co = 0
    for i, a, image, vuln_id, severity, count, related_vuln in G_CPE.itertuples():  # tuples are faster

        if related_vuln == "NA":  # there's not a related vulnerability, so we don't include in the analysis
            pass
        elif "," in related_vuln:
            things = related_vuln.split(
                ",")  # sometimes there is multiple related vulnerabilities, get count of each of them.
            for t in range(1, len(things)):
                hold = things[t]
                new_row = [image, vuln_id, severity, int(count), hold,
                           0]  # start with related count at zero, if other vuln is found update count
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
                        new_row = [image, vuln_id, severity, int(count), related_vuln, rcount]

                        co = co + 1
                else:
                    pass
            df_g.loc[len(df_g.index)] = new_row

    df_g.to_csv("/home/brittanyboles/msusel-SATComparison-Pipe/04_DataAnalysis/02_analysis/" + 'NGrype_69_related.csv',
                index=False)

# graph different related vulnerability graph against each other.
def graph_side_by_side():
    # Read the CSV files
    df_g_CPE = pd.read_csv(
        "/home/brittanyboles/msusel-SATComparison-Pipe/04_DataAnalysis/02_analysis/NGrype_69_related.csv",
        na_filter=False)
    df_g = pd.read_csv(
        "/home/brittanyboles/msusel-SATComparison-Pipe/04_DataAnalysis/02_analysis/NGrype_73_related.csv",
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
    # Add topology lines using kernel density estimation
    # sns.kdeplot(x=x, y=y, alpha=0.5, cmap='viridis_r', fill=True)
    # sns.kdeplot(x=x, y=y, alpha=0.5, c = "blue")

    sc1 = axes[0].scatter(x_coords_cpe, y_coords_cpe, s=50, c=counts_cpe, cmap='viridis', alpha=1, edgecolors='k',
                          vmax=max(max(counts),max(counts_cpe)), vmin=min(min(counts_cpe), min(counts)))
    axes[0].plot([0, max_value], [0, max_value], color='blue', linestyle='-', linewidth=2)
    axes[0].set_title('Grype with CPE Matching', fontsize=20)
    axes[0].set_xlabel('Vulnerability Per Image', fontsize=20)
    axes[0].set_ylabel('Related Vulnerability Per Image', fontsize=22)

    # setting axis so that both graphs have the same bounds
    axes[0].set_xticks(range(0, max_value + 5, 5))
    axes[0].set_yticks(range(0, max_value + 5, 5))
    axes[0].tick_params(labelsize=18)  # Increase tick label size

    axes[0].set_xlim(-1, max_value + 1)
    axes[0].set_ylim(-1, max_value + 1)

    sc2 = axes[1].scatter(x_coords, y_coords, s=50, c=counts, edgecolors='k', cmap='viridis',
                          vmax=max(max(counts),max(counts_cpe)), vmin=min(min(counts_cpe), min(counts)), alpha=1)
    # plt.scatter(x_coords, y_coords, s=50, c= counts, alpha=0.9)

    # Diagonal line of expect values
    axes[1].plot([0, max_value], [0, max_value], color='blue', linestyle='-', linewidth=2)
    axes[1].set_title('Grype Without CPE Matching', fontsize = 20)
    axes[1].set_xlabel('Vulnerability Per Image' ,fontsize = 20)
   # axes[1].set_ylabel('Related Vulnerability Per Image', fontsize = 22)

    # setting axis so that both graphs have the same bounds
    axes[1].set_xticks(range(0, max_value + 5, 5))
    axes[1].set_yticks(range(0, max_value + 5, 5))
    axes[1].tick_params(labelsize=18)  # Increase tick label size

    axes[1].set_xlim(-1, max_value + 1)
    axes[1].set_ylim(-1, max_value + 1)
    #
    # Hide x labels and tick labels for top plots and y ticks for right plots.
    for ax in axes.flat:
        ax.label_outer()


    #plt.xlabel("Vulnerability Per Image", fontsize = 22)
    #plt.ylabel('Related Vulnerability Per Image', fontsize = 22)
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

get_data()
graph_side_by_side()




# def graph():
#     df_g_CPE = pd.read_csv(
#         "/home/brittanyboles/msusel-SATComparison-Pipe/04_DataAnalysis/02_analysis/" + 'NGrype_69_related.csv',
#         na_filter=False)
#     df_g = pd.read_csv(
#         "/home/brittanyboles/msusel-SATComparison-Pipe/04_DataAnalysis/02_analysis/" + 'NGrype_73_related.csv',
#         na_filter=False)
#
#     x = df_g.get('count').values
#     y = df_g.get('r_count').values
#     df = count_per_combo(x, y)
#
#     plt.figure(figsize=(20, 20))
#
#     # Extract x and y coordinates and count of occurrences
#     x_coords = [pair[0] for pair in df['(x, y)']]
#     y_coords = [pair[1] for pair in df['(x, y)']]
#     counts = df['count']
#
#     # Add topology lines using kernel density estimation
#     # sns.kdeplot(x=x, y=y, alpha=0.5, cmap='viridis_r', fill=True)
#     # sns.kdeplot(x=x, y=y, alpha=0.5, c = "blue")
#
#     plt.scatter(x_coords, y_coords, s=50, c=counts, cmap='viridis_r', alpha=1)
#     # plt.scatter(x_coords, y_coords, s=50, c= counts, alpha=0.9)
#     # Add a blue diagonal line through the scatter plot
#
#     # Diagonal line of expect values
#     max_value = max(max(x), max(y))
#     plt.plot([0, max_value], [0, max_value], color='blue', linestyle='-',
#              linewidth=2)  # Adjust line properties as needed
#
#     # Add color bar
#     cbar = plt.colorbar(label='Number of Occurrences', extend='min')
#     cbar.set_label(label='Number of Occurrences', size=20)
#     cbar.ax.tick_params(labelsize=18)
#
#     custom_legend = [
#         plt.Line2D([0], [0], color='blue', lw=4, label='Expected Values')
#     ]
#     plt.legend(handles=custom_legend, loc='upper right')
#
#     # labeling x and y axis
#     plt.xlabel("Vulnerability Per Image", fontsize=22)
#     plt.ylabel("Related Vulnerability Per Image", fontsize=22)
#
#     # setting axis
#     plt.xticks(range(0, max(max(x), max(y)) + 5, 5))
#     plt.yticks(range(0, max(max(x), max(y)) + 5, 5))
#     plt.tick_params(labelsize=20)  # Increase tick label size
#
#     plt.xlim(-1, max_value + 1)
#     plt.ylim(-1, max_value + 1)
#
#     plt.show()
#     print("check")

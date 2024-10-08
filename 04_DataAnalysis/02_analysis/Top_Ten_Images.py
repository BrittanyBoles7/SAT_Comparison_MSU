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

    Top_10_Image_and_Count = Total_Count(G_73, T_49)
    plot_stacked_bar(Top_10_Image_and_Count, G_73, T_49)

    plt.show()


def Total_Count(g, t):
    combined = pd.concat([g, t], ignore_index=True)
    image_sum = combined.groupby('image_name')['count'].sum()
    top_images = image_sum.nlargest(10)
    return top_images.reset_index(name='count')


def plot_stacked_bar(data, g, t):
    # summing up severities of top ten images for Grype
    unknown_g = []
    negligible_g = []
    low_g = []
    medium_g = []
    high_g = []
    critical_g = []
    sum_top_ten = 0
    for z, i, c in data.itertuples():
        hold = g[g['image_name'] == i]
        sum_top_ten = sum_top_ten + np.sum(hold['count'])

        n_count = hold[hold['severity'] == 'Negligible']
        negligible_g.append(np.sum(n_count['count']))

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

    # summing up top ten vulnerabilities for Trivy
    unknown = []
    negligible = []
    low = []
    medium = []
    high = []
    critical = []
    sum_top_ten = 0
    for z, i, c in data.itertuples():
        hold = t[t['image_name'] == i]
        sum_top_ten = sum_top_ten + np.sum(hold['count'])

        u_count = hold[hold['severity'] == 'UNKNOWN']
        unknown.append(np.sum(u_count['count']))

        n_count = hold[hold['severity'] == 'Negligible']
        negligible.append(np.sum(n_count['count']))

        l_count = hold[hold['severity'] == 'LOW']
        low.append(np.sum(l_count['count']))

        m_count = hold[hold['severity'] == 'MEDIUM']
        medium.append(np.sum(m_count['count']))

        h_count = hold[hold['severity'] == 'HIGH']
        high.append(np.sum(h_count['count']))

        c_count = hold[hold['severity'] == 'CRITICAL']
        critical.append(np.sum(c_count['count']))

    # stacked side by side, bar plots for the top 10 images, stacks separated out by severities.
    index = np.arange(len(data))
    bar_width = 0.35  # Width of each bar
    gap = 0.1  # Gap between the two sets of bars

    fig, ax = plt.subplots(figsize=(16, 8))

    # Grype bars

    plt.bar(index - bar_width / 2 - gap, low_g, bar_width, color='#2ca02c', label='Low')
    plt.bar(index - bar_width / 2 - gap, medium_g, bottom=low_g, width=bar_width, color='#1f77b4',
            label='Medium')
    plt.bar(index - bar_width / 2 - gap, high_g, bottom=np.add(low_g, medium_g), width=bar_width, color='#ff7f0e',
            label='High')
    plt.bar(index - bar_width / 2 - gap, critical_g, bottom=np.add(np.add(low_g, medium_g), high_g), width=bar_width,
            color='#d62728', label='Critical')
    plt.bar(index - bar_width / 2 - gap, negligible_g,
            bottom=np.add(np.add(np.add(low_g, medium_g), high_g), critical_g),
            width=bar_width, color='#8c564b', label='Negligible')  # Include Negligible severity

    # Trivy bars
    plt.bar(index + bar_width / 2 + gap, low, bar_width, color='#2ca02c')
    plt.bar(index + bar_width / 2 + gap, medium, bottom=low, width=bar_width, color='#1f77b4')
    plt.bar(index + bar_width / 2 + gap, high, bottom=np.add(low, medium), width=bar_width, color='#ff7f0e')
    plt.bar(index + bar_width / 2 + gap, critical, bottom=np.add(np.add(low, medium), high), width=bar_width,
            color='#d62728')
    plt.bar(index + bar_width / 2 + gap, negligible, bottom=np.add(np.add(np.add(low, medium), high), critical),
            width=bar_width, color='#8c564b')  # Include Negligible severity

    # labels
    plt.xlabel("Top 10 Most Vulnerable Docker images", fontsize=20)
    plt.ylabel("Vulnerability Counts", fontsize=20)
    plt.xticks(index, data['image_name'], rotation=20, ha='right', fontsize=18)
    plt.yticks(fontsize=18)  # Increase font size of y-axis labels
    plt.legend(["Low", "Medium", "High", "Critical", "Negligible", "Unknown"], fontsize=18,
               loc='upper left')  # Include "Negligible"
    plt.title("Top 10 images and severities", fontsize=20)
    plt.tight_layout()

    # Add vertical lines between images
    for i in range(len(data) - 1):
        plt.axvline(x=i + 0.5, color='black', linestyle='--', linewidth=0.5)
    plt.show()



severity_difference()

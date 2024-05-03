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

    g_Top_10_Image_and_Count = Total_Count(G_73)
    t_Top_10_Image_and_Count = Total_Count(T_49)

    plot_stacked_bar(g_Top_10_Image_and_Count, G_73)
    plot_stacked_barT(t_Top_10_Image_and_Count, T_49)

    plt.show()


def Total_Count(g):
    image_sum = g.groupby('image_name')['count'].sum()
    top_images = image_sum.nlargest(10)
    return top_images.reset_index(name='count')

def plot_stacked_bar(data, tool):
    unknown = []
    low = []
    medium = []
    high = []
    critical = []
    for z,i,c in data.itertuples():
        hold = tool[tool['image_name'] ==i]

        u_count = hold[hold['severity'] == 'Unknown']
        unknown.append(np.sum(u_count['count']))

        l_count = hold[hold['severity'] == 'Low']
        low.append(np.sum(l_count['count']))

        m_count = hold[hold['severity'] == 'Medium']
        medium.append(np.sum(m_count['count']))

        h_count = hold[hold['severity'] == 'High']
        high.append(np.sum(h_count['count']))

        c_count = hold[hold['severity'] == 'Critical']
        critical.append(np.sum(c_count['count']))

    plt.bar(data['image_name'], low, color = '#2ca02c')
    plt.bar(data['image_name'], medium, bottom= low, color= '#1f77b4')
    plt.bar(data['image_name'], high, bottom = np.add(low,medium), color = '#ff7f0e')
    plt.bar(data['image_name'], critical, bottom = np.add(np.add(low, medium),high), color = '#d62728')
    plt.bar(data['image_name'], unknown, bottom = np.add(np.add(np.add(low, medium),high),critical), color = '#9467bd')

    plt.xlabel("Top 10 Images", fontsize=20)
    plt.ylabel("Vulnerability Counts", fontsize=20)
    plt.xticks(rotation=20, ha='right', fontsize=18)  # Tilt x-axis labels
    plt.yticks(fontsize=12)  # Increase font size of y-axis labels
    plt.legend(["Low", "Medium", "High", "Critical", "Unknown"], fontsize=18)
    plt.title("Top 10 images and severities", fontsize=20)
    plt.show()

def plot_stacked_barT(data, tool):
    unknown = []
    low = []
    medium = []
    high = []
    critical = []
    for z,i,c in data.itertuples():
        hold = tool[tool['image_name'] ==i]

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

    plt.bar(data['image_name'], low, color = '#2ca02c')
    plt.bar(data['image_name'], medium, bottom= low, color= '#1f77b4')
    plt.bar(data['image_name'], high, bottom = np.add(low,medium), color = '#ff7f0e')
    plt.bar(data['image_name'], critical, bottom = np.add(np.add(low, medium),high), color = '#d62728')
    plt.bar(data['image_name'], unknown, bottom = np.add(np.add(np.add(low, medium),high),critical), color = '#9467bd')

    plt.xlabel("Top 10 Images", fontsize=20)
    plt.ylabel("Vulnerability Counts", fontsize=20)
    plt.xticks(rotation=20, ha='right', fontsize=18)  # Tilt x-axis labels
    plt.yticks(fontsize=12)  # Increase font size of y-axis labels
    plt.legend(["Low", "Medium", "High", "Critical", "Unknown"], fontsize=18)
    plt.title("Top 10 images and severities", fontsize=20)
    plt.show()

severity_difference()
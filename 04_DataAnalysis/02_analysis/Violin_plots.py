import math
import sys
from pathlib import Path

import numpy as np
import seaborn as sns
import pandas as pd
import matplotlib.pyplot as plt

def label_type():
    G_69 = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/G0_69_0.csv", na_filter=False)
    G_73 = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/G0_73_0.csv", na_filter=False)
    T_49 = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Trivy/T0_49_0.csv", na_filter=False)

    G_73 = G_73[G_73['image_name'] != "golang:1.4rc1"]
    G_69 = G_69[G_69['image_name'] != "golang:1.4rc1"]

    #G_69 = G_69[G_69['related_vuln'] != "NA"]
    #G_73 = G_73[G_73['related_vuln'] != "NA"]

    GHSA = []
    CVE = []
    ALAS = []
    DLA = []
    DSA = []
    NSWG = []
    count = 0
    # image_name,vuln_id,severity,count,related_vuln
    for indx, j, i, v, s, c in T_49.itertuples():
        if 'GHSA' in v:
            GHSA.append(c)
            count = count + float(c)
        elif 'CVE' in v:
            CVE.append(c)
            count = count + float(c)
        elif 'ALAS' in v:
            ALAS.append(c)
            count = count + float(c)
        elif 'DLA' in v:
            DLA.append(c)
            count = count + float(c)
        elif 'DSA' in v:
            DSA.append(c)
            count = count + float(c)
        elif 'NSWG' in v:
            NSWG.append(c)
            count = count + float(c)
        elif 'NA' in v:
            pass
        else:
            count = count + float(c)
            print(v)
    print(" Tri GHSA count", np.array(GHSA).astype(float).sum() / count)
    print(" Tri CVE count", np.array(CVE).astype(float).sum() / count)
    print(" Tri ALAS count", np.array(ALAS).astype(float).sum() / count)
    print(" Tri DLA count", np.array(DLA).astype(float).sum() / count)
    print(" Tri DSA count", np.array(DSA).astype(float).sum() / count)
    print(" Tri NSWG count", np.array(NSWG).astype(float).sum() / count)
    print(" Tri total count = ", count)

    GHSA = []
    CVE = []
    ALAS=[]
    DLA = []
    DSA = []
    NSWG = []
    count = 0
    #image_name,vuln_id,severity,count,related_vuln
    for indx, j, i, v, s, c in T_49.itertuples():
        if 'GHSA' in v:
            GHSA.append(c)
            count = count + float(c)
        elif 'CVE' in v:
            CVE.append(c)
            count = count + float(c)
        elif 'ALAS' in v:
            ALAS.append(c)
            count = count + float(c)
        elif 'DLA' in v:
            DLA.append(c)
            count = count + float(c)
        elif 'DSA' in v:
            DSA.append(c)
            count = count + float(c)
        elif 'NSWG' in v:
            NSWG.append(c)
            count = count + float(c)
        elif 'NA' in v:
            pass
        else:
            print(v)
    print(" Trivy GHSA count", np.array(GHSA).astype(float).sum()/count)
    print(" Trivy CVE count", np.array(CVE).astype(float).sum()/count)
    print(" Trivy ALAS count", np.array(ALAS).astype(float).sum()/count)
    print(" Trivy DLA count", np.array(DLA).astype(float).sum()/count)
    print(" Trivy DSA count", np.array(DSA).astype(float).sum()/count)
    print(" Trivy NSWG count", np.array(NSWG).astype(float).sum()/count)
    print(" Trivy total count = ", count)

    GHSA = []
    CVE = []
    ALAS = []
    DLA = []
    DSA = []
    NSWG = []
    ELSA = []
    count = 0
    # image_name,vuln_id,severity,count,related_vuln
    for indx, j, i, v, s, c, r in G_73.itertuples():
        if 'GHSA' in v:
            GHSA.append(c)
            count = count + float(c)
        elif 'CVE' in v:
            CVE.append(c)
            count = count + float(c)
        elif 'ALAS' in v:
            ALAS.append(c)
            count = count + float(c)
        elif 'DLA' in v:
            DLA.append(c)
            count = count + float(c)
        elif 'DSA' in v:
            DSA.append(c)
            count = count + float(c)
        elif 'NSWG' in v:
            NSWG.append(c)
            count = count + float(c)
        elif 'ELSA' in v:
            ELSA.append(c)
            count = count + float(c)
        elif 'NA' in v:
            pass
        else:
            print(v)
    print(" Grype GHSA count", np.array(GHSA).astype(float).sum()/count)
    print(" Grype CVE count", np.array(CVE).astype(float).sum()/count)
    print(" Grype ALAS count", np.array(ALAS).astype(float).sum()/count)
    print(" Grype DLA count", np.array(DLA).astype(float).sum()/count)
    print(" Grype DSA count", np.array(DSA).astype(float).sum()/count)
    print(" Grype NSWG count", np.array(NSWG).astype(float).sum()/count)
    print(" Grype ELSA count", np.array(ELSA).astype(float).sum()/count)
    print(" Grype total count = ", count)

    GHSA = []
    CVE = []
    ALAS = []
    DLA = []
    DSA = []
    NSWG = []
    ELSA = []
    count = 0
    # image_name,vuln_id,severity,count,related_vuln
    for indx, j, i, v, s, c, r in G_69.itertuples():
        if 'GHSA' in v:
            GHSA.append(c)
            count = count + float(c)
        elif 'CVE' in v:
            CVE.append(c)
            count = count + float(c)
        elif 'ALAS' in v:
            ALAS.append(c)
            count = count + float(c)
        elif 'DLA' in v:
            DLA.append(c)
            count = count + float(c)
        elif 'DSA' in v:
            DSA.append(c)
            count = count + float(c)
        elif 'NSWG' in v:
            NSWG.append(c)
            count = count + float(c)
        elif 'ELSA' in v:
            ELSA.append(c)
            count = count + float(c)
        elif 'NA' in v:
            pass
        else:
            print(v)
    print(" Grype 69 GHSA count", np.array(GHSA).astype(float).sum()/count)
    print(" Grype 69 CVE count", np.array(CVE).astype(float).sum()/count)
    print(" Grype 69 ALAS count", np.array(ALAS).astype(float).sum()/count)
    print(" Grype 69 DLA count", np.array(DLA).astype(float).sum()/count)
    print(" Grype 69 DSA count", np.array(DSA).astype(float).sum()/count)
    print(" Grype 69 NSWG count", np.array(NSWG).astype(float).sum()/count)
    print(" Grype 69 ELSA count", np.array(ELSA).astype(float).sum()/count)
    print(" Grype 69 total count = ", count)

def severity_difference():
    G_69 = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/G0_69_0.csv", na_filter=False)
    G_73 = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/G0_73_0.csv", na_filter=False)
    T_49 = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Trivy/T0_49_0.csv", na_filter=False)

    # for i in range(0, len(G_73['image_name']) - 100):
    #     if G_73.loc[i]['image_name'] == "golang:1.4rc1":
    #         G_73 = G_73.drop(i)
    G_73 = G_73[G_73['image_name'] != "golang:1.4rc1"]
    G_69 = G_69[G_69['image_name'] != "golang:1.4rc1"]

    t_49 = distribution(T_49)

    for i in t_49['image_name']:
        filtered_G_73 = G_73[G_73['image_name'] == i]
        filtered_T_49 = T_49[T_49['image_name'] == i]

        # Get the set of unique vuln_id values in each filtered dataframe
        vuln_ids_G_73 = set(filtered_G_73['vuln_id'])
        vuln_ids_T_49 = set(filtered_T_49['vuln_id'])

        common_vuln_ids = vuln_ids_G_73.intersection(vuln_ids_T_49)

        # Write code to check if severities agree for common vulnerabilities
        for vuln_id in common_vuln_ids:
            # Filtered rows for the current vulnerability in G_73 and T_49
            row_G_73 = filtered_G_73[filtered_G_73['vuln_id'] == vuln_id]
            row_T_49 = filtered_T_49[filtered_T_49['vuln_id'] == vuln_id]

            # Get severity values
            severity_G_73 = row_G_73['severity'].iloc[0].lower()
            severity_T_49 = row_T_49['severity'].iloc[0].lower()

            # Check if severities agree
            if severity_G_73 == severity_T_49 or severity_G_73 == 'negligible':
                pass
                # print(f"Agreed severity for vulnerability {vuln_id}: {severity_G_73}")
            else:
                print(
                    f"Disagreed severity for vulnerability {vuln_id}: G_73 - {severity_G_73}, T_49 - {severity_T_49}")

def get_data_difference_vulns():
    G_69 = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/G0_69_0.csv", na_filter=False)
    G_73 = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/G0_73_0.csv", na_filter=False)
    T_49 = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Trivy/T0_49_0.csv", na_filter=False)

    # for i in range(0, len(G_73['image_name']) - 100):
    #     if G_73.loc[i]['image_name'] == "golang:1.4rc1":
    #         G_73 = G_73.drop(i)

    G_73 = G_73[G_73['image_name'] != "golang:1.4rc1"]
    G_69 = G_69[G_69['image_name'] != "golang:1.4rc1"]

    t_49 = distribution(T_49)

    average_num_agreed = []
    average_num_trivy = []
    average_num_grype = []

    for i in t_49['image_name']:

        filtered_G_73 = G_73[G_73['image_name'] == i]
        filtered_T_49 = T_49[T_49['image_name'] == i]

        # Get the set of unique vuln_id values in each filtered dataframe
        vuln_ids_G_73 = set(filtered_G_73['vuln_id'])
        vuln_ids_T_49 = set(filtered_T_49['vuln_id'])

        if len(vuln_ids_T_49) == len(vuln_ids_G_73):
            print(i, vuln_ids_T_49, vuln_ids_G_73)

        common_vuln_ids = vuln_ids_G_73.intersection(vuln_ids_T_49)
        count_common_vuln_ids = len(common_vuln_ids)
        average_num_agreed.append(count_common_vuln_ids)
        average_num_grype.append((len(vuln_ids_G_73)))
        average_num_trivy.append((len(vuln_ids_T_49)))
    agreed = np.array(average_num_agreed)
    gr = np.array(average_num_grype)
    tr = np.array(average_num_trivy)
    print("average agreed: ", np.median(agreed), "std: ", agreed.std())
    print("average grype: ", np.median(gr), "std: ", gr.std())
    print("average trivy: ", np.median(tr), "std: ", tr.std())

def get_data_difference():
    G_73= pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/G0_69_0.csv", na_filter=False)
    T_49 = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/G0_73_0.csv", na_filter=False)
    G_69 = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Trivy/T0_49_0.csv", na_filter=False)

    G_73 = G_73[G_73['image_name'] != "golang:1.4rc1"]
    G_69 = G_69[G_69['image_name'] != "golang:1.4rc1"]

    g_73 = distribution(G_73)
    t_49 = distribution(T_49).reset_index()
    t_max = max(t_49['count'])
    g_max = max(g_73['count'])

    # Calculate average difference
    avg_difference = np.mean(g_73['count'])
    std_dev_difference = np.std(g_73['count'])

    print(
        "On average, the count of vulnerabilities reported by G_73 was {:.2f} higher than T_49.".format(avg_difference))
    print("Standard deviation of the difference:", std_dev_difference)

    # Calculate average difference
    avg_difference = np.mean(t_49['count'])
    std_dev_difference = np.std(t_49['count'])

    print(
        "On average, the count of vulnerabilities reported by G_73 was {:.2f} higher than T_49.".format(avg_difference))
    print("Standard deviation of the difference:", std_dev_difference)

    # Sample DataFrame (replace this with your actual DataFrame)
    data = {
        'Image_Name': g_73['image_name'],
        'Diff': g_73['count'].subtract(t_49['count'])
    }

    df_difference = pd.DataFrame(data)

    # Calculate average difference
    avg_difference = np.mean(df_difference['Diff'])
    std_dev_difference = np.std(df_difference['Diff'])

    print(
        "On average, the count of vulnerabilities reported by G_73 was {:.2f} higher than T_49.".format(avg_difference))
    print("Standard deviation of the difference:", std_dev_difference)

    # Count the number of images where both t_49 and g_73 found counts of 0
    num_images_both_tools_count_zero = len(df_difference[(t_49['count'] == 0) & (g_73['count'] == 0)])
    print("Number of images where both tools found zero vulnerabilities:", num_images_both_tools_count_zero)

    # Count the number of images where t_49 found counts of 0
    num_images_t_49_count_zero = len(t_49[t_49['count'] == 0])

    # Count the number of images where g_73 found counts of 0
    num_images_b_73_count_zero = len(g_73[g_73['count'] == 0])

    print("Number of images with count 0 in t_49:", num_images_t_49_count_zero)
    print("Number of images with count 0 in g_73:", num_images_b_73_count_zero)

    # Filter rows where the absolute difference in counts is greater than 2000
    diff_greater_than_2000 = df_difference[abs(df_difference['Diff']) > 500]
    num_images_diff_greater_than_2000 = len(diff_greater_than_2000)
    print("Number of images with a difference count greater than 500:", num_images_diff_greater_than_2000)

    # Filter rows where the absolute difference in counts is greater than 2000
    diff_greater_than_2000 = df_difference[abs(df_difference['Diff']) > 100]
    num_images_diff_greater_than_2000 = len(diff_greater_than_2000)
    print("Number of images with a difference count greater than 100:", num_images_diff_greater_than_2000)

    # Filter rows where the absolute difference in counts is greater than 2000
    diff_greater_than_2000 = df_difference[abs(df_difference['Diff']) > 0]
    num_images_diff_greater_than_2000 = len(diff_greater_than_2000)
    print("Number of images with a difference count at 0:", num_images_diff_greater_than_2000)

    # Filter rows where both Grype and Trivy have counts not equal to 0
    filtered_df = df_difference[(g_73['count'] != 0) & (t_49['count'] != 0)]
    f_t = t_49[(t_49['count'] != 0)]
    f_g = g_73[(g_73['count'] != 0)]
    # Find the row with the maximum difference in counts
    max_diff_row = filtered_df.loc[filtered_df['Diff'].idxmax()]

    print("Image with the maximum difference where counts are not 0:")
    trivy = f_t.loc[filtered_df['Diff'].idxmax(), 'count']
    grype = f_g.loc[filtered_df['Diff'].idxmax(), 'count']
    print("Image Name:", max_diff_row['Image_Name'])
    print("Difference in Counts:", max_diff_row['Diff'], " Grype: ", grype, " Trivy: ", trivy,)


    # max counts of Grype and Trivy difference
    min_diff = min(g_73['count'].subtract(t_49['count']))
    max_diff = max(g_73['count'].subtract(t_49['count']))

    # largest difference in counts
    max_diff_index = df_difference['Diff'].idxmax()
    image_name_largest_diff = df_difference.loc[max_diff_index, 'Image_Name']
    trivy = t_49.loc[max_diff_index, 'count']
    grype = g_73.loc[max_diff_index, 'count']
    print("Image name with the largest difference in counts:", image_name_largest_diff, " Grype: ", grype, " Trivy: ",
          trivy, " diff: ", max_diff)

    # Define custom color palette
    custom_palette = {'Diff': (0.4, 1.0, 0.8)}
    df = pd.DataFrame(data)

    # Melt the DataFrame to create a long-form DataFrame
    df_melted = pd.melt(df, id_vars=['Image_Name'], var_name='Tool', value_name='Vulnerabilities')

    # Create violin plots for each tool
    plt.figure(figsize=(12, 14))
    ax = sns.violinplot(x='Tool', y='Vulnerabilities', data=df_melted, inner='quartile', palette=custom_palette, cut=0)

    plt.xlabel('Grype v0.73.0 minus Trivy v0.49.0', fontsize='40')
    plt.ylabel('Vulnerability Count Difference ', fontsize='40')
    plt.xticks(fontsize=20)
    plt.yticks(fontsize=20)
    plt.ylim(min_diff - min_diff % 1000, max_diff + 1000 - (max_diff % 1000))
    # Set light gray background
    ax.set_facecolor('#E0E0E0')

    # Add horizontal lines for y ticks
    plt.gca().yaxis.grid(True)
    plt.gca().xaxis.grid(False)
    plt.gca().set_axisbelow(True)

    plt.show()

def get_data():
    G_69 = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/G0_69_0.csv", na_filter=False)
    G_73 = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/G0_73_0.csv", na_filter=False)
    T_49 = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Trivy/T0_49_0.csv", na_filter=False)

    # Trivy didn't process this image for some reason, remove from results
    G_73 = G_73[G_73['image_name'] != "golang:1.4rc1"]
    G_69 = G_69[G_69['image_name'] != "golang:1.4rc1"]

    b_73 = distribution(G_73).reset_index()
    t_49 = distribution(T_49).reset_index()
    t_max = max(t_49['count'])
    g_max = max(b_73['count'])

    for i in range(0, len(b_73['image_name'])):
        if b_73.loc[i]['image_name'] != t_49.loc[i]['image_name']:
            print(b_73.loc[i]['image_name'], t_49.loc[i]['image_name'])

    # Sample DataFrame (replace this with your actual DataFrame)
    data = {
        'Image_Name': b_73['image_name'],
        'Trivy v0.49.0': t_49['count'],
        'Grype v0.73.0': b_73['count'],
    }

    # Define custom color palette
    custom_palette = {'Trivy v0.49.0': (0.8, 0.95, 0.7), 'Grype v0.73.0': (0.5, 0.7, 0.95)}
    df = pd.DataFrame(data)

    # Melt the DataFrame to create a long-form DataFrame
    df_melted = pd.melt(df, id_vars=['Image_Name'], var_name='Tool', value_name='Vulnerabilities')

    # Create violin plots for each tool
    plt.figure(figsize=(12, 14))
    ax = sns.violinplot(x='Tool', y='Vulnerabilities', data=df_melted, inner='quartile', palette=custom_palette, cut=0)

    plt.xlabel('Static Analysis Tool', fontsize='22')
    plt.ylabel('Vulnerabilities Per Image', fontsize='22')
    plt.xticks(fontsize=20)
    plt.yticks(fontsize=20)

    # Set light gray background
    ax.set_facecolor('#E0E0E0')

    # Add horizontal lines for y ticks
    plt.gca().yaxis.grid(True)
    plt.gca().xaxis.grid(False)
    plt.gca().set_axisbelow(True)

    plt.show()


def distribution(df):
    # Replace 'NA' strings with actual NaN values
    df.replace('NA', pd.NA, inplace=True)

    # Convert 'count' column to numeric
    df['count'] = pd.to_numeric(df['count'], errors='coerce')

    # Group by 'image_name' and sum the 'count' for each image
    image_counts = df.groupby('image_name')['count'].sum()

    # Reset index to convert the result into a DataFrame
    image_counts_df = image_counts.reset_index()

    # If there are NaN values in the 'count' column, replace them with 0
    image_counts_df['count'] = image_counts_df['count'].fillna(0)

    return image_counts_df

#severity_difference()
#get_data_difference_vulns()

#label_type()
get_data_difference()
# get_data()

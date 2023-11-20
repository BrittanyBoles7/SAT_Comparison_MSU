import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import os
import requests
import datetime


def Grype_Plots():
    g_data = pd.read_csv(
        "/home/brittanyboles/msusel-SATComparison-Pipe/04_DataAnalysis/01_input/Grype_v_d - Sheet1.csv")
    versions_dates = g_data.values

    G_versions_csvs = os.listdir("/home/brittanyboles/msusel-SATComparison-Pipe/03_Processing/04_product/Grype")

    G_versions_results = []
    for v in G_versions_csvs:
        g_data = pd.read_csv("/home/brittanyboles/msusel-SATComparison-Pipe/03_Processing/04_product/Grype/" + v)
        version = v[:v.index(".") + len(".") - 1]  # parsing sting to just have version
        v_date = [a[1] for a in versions_dates if a[0] == version]  # get date of versions
        hold = dict(version=version, info=g_data.values, date=v_date)  # datetime now is a hold value
        G_versions_results.append(hold)

    sort(G_versions_results)

    # ['image_name', 'vuln_id', 'severity', 'count']


def Trivy_Plots():
    t_data = pd.read_csv(
        "/home/brittanyboles/msusel-SATComparison-Pipe/04_DataAnalysis/01_input/Trivy_v_d - Sheet1.csv")
    versions_dates = t_data.values

    t_versions_csvs = os.listdir("/home/brittanyboles/msusel-SATComparison-Pipe/03_Processing/04_product/Trivy")

    t_versions_results = []
    for v in t_versions_csvs:
        t_data = pd.read_csv("/home/brittanyboles/msusel-SATComparison-Pipe/03_Processing/04_product/Trivy/" + v)
        version = v[:v.index(".") + len(".") - 1]  # parsing sting to just have version
        v_date = [a[1] for a in versions_dates if a[0] == version]  # get date of versions
        hold = dict(version=version, info=t_data.values, date=v_date)  # datetime now is a hold value
        t_versions_results.append(hold)

    nothing = t_versions_results


def sort(list_dicts):
    # just getting a list of all the vulnerabilities:
    list_images = list()

    for d in list_dicts:

        for data in d['info']:
            if 0 == len(list_images) or not list_images.__contains__(data[1]):
                list_images.append(data[1])

    results = []  # each images vuln counts in each versions.
    for i in range(0, len(list_images)):
        result = pd.DataFrame(list(zip([0] * len(list_dicts), [0] * len(list_dicts), [0] * len(list_dicts))),
                              columns=['version', 'date', 'count'])
        for j in range(0, len(list_dicts)):
            d = list_dicts[j]

            c = [a[4] for a in d['info'] if a[1] == list_images[i]]
            result.loc[j, 'count'] = c  # num of times the vuln occurred in this version.
            result.loc[j, 'version'] = d['version']
            result.loc[j, 'date'] = d['date']

        results.append(results)
    return results

def plot_counts_per_image_per_version(tool_versions, release_dates, data):
    # Sample data (replace this with your actual data)
    tool_versions = ["1.0", "1.1", "1.2", "1.3"]
    release_dates = ["2023-01-01", "2023-02-01", "2023-03-01", "2023-04-01"]
    total_vulnerabilities = [10, 15, 8, 20]

    # Convert release dates to datetime objects
    release_dates = [datetime.datetime.strptime(date, "%m-%d-%y") for date in release_dates]

    # Plotting
    plt.plot(release_dates, total_vulnerabilities, marker='o')
    plt.title('Total Count of Vulnerabilities Over Tool Versions')
    plt.xlabel('Release Dates')
    plt.ylabel('Total Count of Vulnerabilities')
    plt.xticks(rotation=45)
    plt.tight_layout()

    # Show the plot
    plt.show()


def vuln_relation_investigation(df, difference_array):
    """
    Here we look into the vulns from either grype or trivy and investigate how they handle them/ mainly grype
    :param difference_array:
    :param df:pd.DataFrame(columns=['image_name', 'vuln_id', 'severity', 'count'])
    """
    for i, vuln in df.iterrows():  # for each vuln in the image
        if 'CVE' not in vuln['vuln_id'] and 'NA' not in vuln[
            'vuln_id']:  # we want cve form and na is fine as well so skip over if vuln is one
            # if 'NA' not in vuln['vuln_id']:
            # gets info on the vuln from the open source vulnerabilities databases
            response = requests.get("https://api.osv.dev/v1/vulns/" + vuln['vuln_id']).text
            if 'aliases' in response:  # if there is an aliases for this vuln, we want to replace this vuln with its aliases or at least check it out
                list_things = response.split(",")  # response long string of info about the vuln
                for s in list_things:
                    if 'aliases' in s:  # we only want to info about related vulns
                        # just the tedious work of splitting a string
                        aliases_list = (s.split(":", 1)[1]
                                        .replace('[', '').replace(']', '')
                                        .replace('"', '')
                                        .split(','))
                        if len(aliases_list) > 1:
                            print(aliases_list)  # just a check if there ever is multiple aliases for the same vuln
                        for a in aliases_list:  # occasionally there is more than one aliases for the same vuln, we go through all of them
                            # if this goes off then the same vuln might be getting reported under different names
                            if a in df.values:
                                index_vuln_id = df[df['vuln_id'] == a].index
                                current_vuln = df.loc[index_vuln_id]

                                # for a bar graph counting quantities at different disagreements, we add 50 because that's where the "zero" count will be.
                                difference_array[50 + vuln['count'] - current_vuln['count'].values[0]] = \
                                    difference_array[50 + vuln['count'] - current_vuln['count'].values[0]] + 1
                                if vuln['count'] != current_vuln['count'].values[
                                    0]:  # I expected same number but might not be true.
                                    print("vuln:    " + str(vuln['vuln_id']) + " count: " + str(vuln['count']))
                                    print("aliases: " + current_vuln['vuln_id'].values[0] + " count: " + str(
                                        current_vuln['count'].values[0]))
                                    print(" ")

            else:
                pass
                # print(vuln['vuln_id'] + " has no aliases")
        else:
            pass
            # print(vuln['vuln_id'])
    return difference_array


def graph_differences(values):
    difference_array = np.arange(-50, 50)
    # creating the dataset
    values[50] = 0
    fig = plt.figure(figsize=(10, 5))

    # creating the bar plot
    plt.bar(difference_array, values, color='maroon',
            width=0.4)

    plt.xlabel("difference between vendor count and aliases count")
    plt.ylabel("number of times difference occurred")
    plt.title("Difference in counts of same vuln in same image")
    plt.show()
    return


# Trivy_Plots()
Grype_Plots()

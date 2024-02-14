import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import os
import requests



def Grype_Plots():


    G_versions_csvs = os.listdir("/home/brittanyboles/msusel-SATComparison-Pipe/03_Processing/04_product/Grype")

    G_versions_results = []
    for v in G_versions_csvs:
        g_data = pd.read_csv("/home/brittanyboles/msusel-SATComparison-Pipe/03_Processing/04_product/Grype/" + v)
        version = v[:v.index(".") + len(".") - 1]  # parsing sting to just have version
        hold = dict(version=version, info=g_data.values)  # datetime now is a hold value
        G_versions_results.append(hold)



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

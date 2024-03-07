import os

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from pandas import DataFrame
from skbio.stats.ordination import pcoa
from skbio import DistanceMatrix
import sys
from pathlib import Path


def PCO_Organization(df_trivy, df_grype):
    # to start lets just get a list of all the vulnerabilities and images
    unique_vulns = []
    u_images = []
    for i, a, image, vuln_id, severity, count in df_trivy.itertuples():
        cimage = image + '_T'
        if vuln_id not in unique_vulns and vuln_id != "NA":
            unique_vulns.append(vuln_id)
        if cimage not in u_images:
            u_images.append(cimage)

    for i, a, image, vuln_id, severity, count, related_vuln in df_grype.itertuples():
        cimage = image + '_G'
        if vuln_id not in unique_vulns and vuln_id != "NA":
            unique_vulns.append(vuln_id)
        if cimage not in u_images:
            u_images.append(cimage)

    if 'NA' in unique_vulns:
        print("wtf")

    dicts = {}
    keys = unique_vulns
    for i in keys:
        dicts[i] = np.zeros(len(u_images))

    # Create a dataFrame using dictionary
    df = pd.DataFrame(dicts, index = u_images)
    # Change the column names
    df.columns = unique_vulns

    # Change the row indexes
    # df.index = u_images

    for i, a, image, vuln_id, severity, count, related_vuln in df_grype.itertuples():
        cimage = image + '_G'
        if vuln_id != "NA":
            df[vuln_id][cimage] = count

    for i, a, image, vuln_id, severity, count in df_trivy.itertuples():
        cimage = image + '_T'
        if vuln_id != "NA":
            df[vuln_id][cimage] = count

    df.to_csv("/home/brittanyboles/msusel-SATComparison-Pipe/04_DataAnalysis/02_analysis/" + 'DistanceThang.csv', index = True)
    return


def main():
    df_trivy = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Trivy/T0_47_0.csv", na_filter=False)
    df_grype = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/G0_73_0.csv", na_filter=False)
    if not os.path.isfile(
            "/home/brittanyboles/msusel-SATComparison-Pipe/04_DataAnalysis/02_analysis/DistanceThang.csv"):
        PCO_Organization(df_trivy, df_grype)

    df = pd.read_csv(str(Path(sys.path[0]).absolute()) + "/DistanceThang.csv", na_filter=False)

    # Perform PCO
    dm = DistanceMatrix(df)
    pcoa_results = pcoa(dm)

    # Plot the results
    plt.figure(figsize=(8, 6))

    # Plot data from df_grype
    plt.scatter(pcoa_results.samples.loc[df_grype.index, 'PC1'],
                pcoa_results.samples.loc[df_grype.index, 'PC2'],
                c='blue', label='Grype')

    # Plot data from df_trivy
    plt.scatter(pcoa_results.samples.loc[df_trivy.index, 'PC1'],
                pcoa_results.samples.loc[df_trivy.index, 'PC2'],
                c='green', label='Trivy')

    plt.title('Principal Coordinate Analysis (Excluding Severity)')
    plt.xlabel('PC1')
    plt.ylabel('PC2')
    plt.legend()
    plt.grid(True)
    plt.show()


    print("hi")
main()

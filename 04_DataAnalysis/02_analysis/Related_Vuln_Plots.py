import sys
from pathlib import Path

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import os
import requests
import math


def get_data():
    G_CPE = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/CPEG0_73_0.csv", na_filter=False)
    G_73 = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/G0_73_0.csv", na_filter=False)


    # we wanted related count
    df_g = pd.DataFrame(columns=['image_name', 'vuln_id', 'severity', 'count', 'related_vuln', 'r_count'])

    count = 0
    for i, g in G_CPE.iterrows():
        count = count + 1
        if g['related_vuln'] == "NA":
            pass
        else:
            for j, r in G_CPE.iterrows():
                if r['image_name'] == g['image_name']:
                    if "," in g['related_vuln']:
                        print("fix this")
                        pass
                    else:
                        if r['vuln_id'] == g['related_vuln']:
                            new_row = [g['image_name'], g['vuln_id'], g['severity'], g['count'], g['related_vuln'], r['count']]
                            df_g.loc[len(df_g.index)] = new_row
                else:
                    pass

    x = df_g.columns['count']
    y = df_g.columns['r_count']
    plt.scatter(x, y, alpha=0.5)
    plt.xlabel("Vulnerability Per Image")
    plt.ylabel("Related Vulnerability Per Image")
    plt.show()
    print("check")





get_data()
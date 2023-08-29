import os
import json
import sys
import pandas as pd
import requests
from pathlib import Path


def vs_thething():  # df_t = pd.DataFrame(columns=['image_name', 'vuln_id', 'severity', 'count'])
    grype_info = pd.read_csv(
        "/media/reu2023/extradrive1/msusel-SATComparison/03_Processing/03_incremental/connectedVulnerabilityIDs.csv")
    for vuln in grype_info.values:
        # print(vuln[0])
        response = requests.get("https://api.osv.dev/v1/vulns/" + vuln[0]).text  # gets info on the vuln from the open source vulnerabilities databases
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
                        if vuln[1] == a:
                            pass
                            # print("they agree")
                            # print("vuln: " + vuln[0])
                            # print("Aliases: " + a)
                            # print("")
                        else:
                            print("interesting")
                            print("vuln: " + vuln[0])
                            print("Aliases: " + a)


        else:
            pass
            print(vuln[0] + " has no aliases")


vs_thething()

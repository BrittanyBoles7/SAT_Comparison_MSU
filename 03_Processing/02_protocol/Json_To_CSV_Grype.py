import os
import sys
from pathlib import Path
import pandas as pd
from Converting_Json_CSV import Json_To_CSV
import numpy as np
import matplotlib.pyplot as plt


class Json_To_CSV_Grype(Json_To_CSV):

    def __init__(self, path):
        super().__init__(path)
        self.create_data_frame(self.df_json)

    def create_data_frame(self, df_json):
        # for i, a, image, vuln_id, severity, count, related_vuln in G_CPE.itertuples():
        # make sure indexes pair with number of rows
        for index, ver, json_list in df_json.itertuples():

            df_g = pd.DataFrame(columns=['image_name', 'vuln_id', 'vuln_source', 'severity', 'count', 'related_vuln',
                                         'related_vuln_source'])  # for each version get a data frame
            for i in json_list:
                df_image = self.image_vuln_info_test(i)  # data frame with images vuln info [vuln_id, severity, count]

                name_list = [i['source']['target']['userInput']] * len(df_image)  # list of the image name repeated for master_DataFrame

                df_image.insert(0, 'image_name', np.array(name_list), True)

                df_g = pd.concat([df_g, df_image])  # building one data frame with info of all images run through this version

            self.save_data_to_file(ver, "Grype", df_g)

        return

    @staticmethod
    def image_vuln_info_test(i):
        df_image = pd.DataFrame(columns=['vuln_id', 'vuln_source', 'severity', 'count', 'related_vuln', 'related_vuln_source'])

        if len(i['matches']) > 0:  # some images might not have any matches, meaning there wasn't any vulns
            for v in i['matches']:
                current = v['vulnerability']
                filter_ids = df_image[df_image['vuln_id'] == current['id']]


                # if we have not already found this vuln id we need to add it.
                if (len(filter_ids) == 0) or (len(filter_ids) > 0 and current['dataSource'] not in filter_ids['vuln_source'].values):
                    r_current = v['relatedVulnerabilities']

                    # related vulnerability info we want to collect to add to our info about this current vuln only when they have different labels
                    related_vuln = "NA"
                    related_source = "NA"

                    # if there is one related vulnerability
                    if len(r_current) == 1:
                        related_vuln = r_current[0]['id']
                        related_source = r_current[0]['dataSource']
                    # if there is more than one related vulnerability

                    elif len(r_current) > 1:
                        related_vuln = ""
                        for rv in r_current:
                            related_vuln = related_vuln + "," + rv['id']
                            related_source = related_source + "," +rv['dataSource']

                    # no related vulnerabilities don't worry about it
                    else:
                        pass

                    # making a new row of our data frame with vuln id, severity and the total count of times it was found in this image
                    new_row = [current['id'], current['dataSource'], current['severity'], int(1), related_vuln, related_source]
                    df_image.loc[len(df_image.index)] = new_row
                    df_image.reset_index()

                # if we already found this vuln in this image, just update the count, make sure we have the right vuln source
                elif len(filter_ids) > 0 and current['dataSource'] in filter_ids['vuln_source'].values:

                    index_vuln_id = 'nothing'
                    for index, ids in filter_ids.iterrows():

                        a = ids['vuln_source']
                        b = current['dataSource']
                        if a == b:
                            index_vuln_id = index
                    if index_vuln_id == 'nothing':
                        print("???")
                    # get the current info for this vulns id from the data frame
                    current_vuln_count = df_image.loc[index_vuln_id]['count']

                    row = df_image.loc[index_vuln_id]
                    new_row_who_dis = [row['vuln_id'], row['vuln_source'],
                                                   row['severity'], current_vuln_count + 1,
                                                   row['related_vuln'], row['related_vuln_source']]

                    # reset the row with an updated count
                    df_image.loc[index_vuln_id] = new_row_who_dis
                    #df_image.reset_index()

                else:
                    print("checking we didn't miss a case")



        else:  # this image had no results/ vulns so enter NA
            df_image.loc[0] = ['NA', 'NA', 'NA', "NA", 'NA', 'NA']

        return df_image


def main():
    jc = Json_To_CSV_Grype(str(Path(sys.path[0]).absolute().parent.parent)
                           + "/02_DataAcquisition/04_product/Grype/")


main()

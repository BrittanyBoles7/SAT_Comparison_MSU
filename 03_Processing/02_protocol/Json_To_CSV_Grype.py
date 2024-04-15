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

            df_g = pd.DataFrame(columns=['image_name', 'vuln_id', 'severity', 'count','related_vuln'])  # for each version get a data frame
            for i in json_list:

                df_image = self.image_vuln_info(i)  # data frame with images vuln info [vuln_id, severity, count]

                name_list = [i['source']['target']['userInput']] * len(df_image)  # list of the image name repeated for master_DataFrame

                df_image.insert(0, 'image_name', np.array(name_list), True)

                df_g = pd.concat([df_g, df_image])  # building one data frame with info of all images run through this version

            self.save_data_to_file(ver, "Grype", df_g)

        return

    def create_data_frame2(self, df_json):
        # for i, a, image, vuln_id, severity, count, related_vuln in G_CPE.itertuples():
        # make sure indexes pair with number of rows
        for index, row in df_json.iterrows():
            #difference_array = np.zeros(100)
            df_g = pd.DataFrame(columns=['image_name', 'vuln_id', 'severity', 'count','related_vuln'])  # for each version get a data frame
            for i in row['json_list']:

                df_image = self.image_vuln_info(i)  # data frame with images vuln info [vuln_id, severity, count]
                #difference_array = self.vuln_relation_investigation(df_image, difference_array)  # just looking at related vulns and how they are handled

                name_list = [i['source']['target']['userInput']] * len(df_image)  # list of the image name repeated for master_DataFrame

                df_image.insert(0, 'image_name', np.array(name_list), True)

                df_g = pd.concat([df_g, df_image])  # building one data frame with info of all images run through this version

            self.save_data_to_file(row['version'], "Grype", df_g)

        return

    @staticmethod
    def image_vuln_info(i):
        df_image = pd.DataFrame(columns=['vuln_id', 'severity', 'count', 'related_vuln'])

        if len(i['matches']) > 0:  # some images might not have any matches, meaning there wasn't any vulns
            for v in i['matches']:
                current = v['vulnerability']

                if current['id'] in df_image['vuln_id'].values:  # if we already found this vuln in this image, just update the count
                    index_vuln_id = df_image[df_image['vuln_id'] == current['id']].index  # get index of the vuln in the data frame
                    current_vuln_count = df_image.loc[index_vuln_id]['count'].values[0]  # get the current info for this vulns id from the data frame
                    df_image.loc[index_vuln_id] = [current['id'], current['severity'], current_vuln_count + 1, df_image.loc[index_vuln_id]['related_vuln'].values[0]]  # reset the row with an updated count

                else:
                    # related vulnerability info we want to collect to add to our info about this current vuln
                    related_vuln = "NA"
                    if len(v['relatedVulnerabilities']) == 1:
                        if v['relatedVulnerabilities'][0]['id'] != current['id']:
                            related_vuln = v['relatedVulnerabilities'][0]['id']
                    elif len(v['relatedVulnerabilities']) > 1:
                        related_vuln = ""
                        for rv in v['relatedVulnerabilities']:
                            related_vuln = related_vuln + ","+rv['id']
                        # print("that's odd we have multiple relations")

                    # making a new row of our data frame with vuln id, severity and the total count of times it was found in this image
                    new_row = [current['id'], current['severity'], int(1), related_vuln]
                    df_image.loc[len(df_image.index)] = new_row

        else:  # this image had no results/ vulns so enter NA
            df_image.loc[0] = ['NA', 'NA', 'NA', "NA"]

        return df_image




def main():
    jc = Json_To_CSV_Grype(str(Path(sys.path[0]).absolute().parent.parent)
                           + "/02_DataAcquisition/04_product/Grype/")


main()

import sys
from pathlib import Path
import pandas as pd
import requests

from Converting_Json_CSV import Json_To_CSV
import numpy as np


class Json_To_CSV_Grype(Json_To_CSV):

    def __init__(self, path):
        super().__init__(path)
        self.create_data_frame(self.df_json)

    def create_data_frame(self, df_json):

        # make sure indexes pair with number of rows
        for index, row in df_json.iterrows():
            df_g = pd.DataFrame(columns=['image_name', 'vuln_id', 'severity', 'count'])  # for each version get a data frame
            for i in row['json_list']:

                df_image = self.image_vuln_info(i)  # data frame with images vuln info [vuln_id, severity, count]
                self.vuln_relation_investigation(df_image)  # just looking at related vulns and how they are handled

                name_list = [i['source']['target']['userInput']] * len(df_image)  # list of the image name repeated for master_DataFrame

                df_image.insert(0, 'image_name', np.array(name_list), True)

                df_g = pd.concat([df_g, df_image])  # building one data frame with info of all images run through this version

            self.save_data_to_file(row['version'], "Grype", df_g)

    @staticmethod
    def image_vuln_info(i):
        df_image = pd.DataFrame(columns=['vuln_id', 'severity', 'count'])

        if len(i['matches']) > 0:  # some images might not have any matches, meaning there wasn't any vulns
            for v in i['matches']:
                current = v['vulnerability']
                if current['id'] in df_image.values:  # if we already found this vuln in this image, just update the count
                    index_vulnId = df_image[df_image['vuln_id'] == current['id']].index  # get index of the vuln in the data frame
                    current_vuln_count = df_image.loc[index_vulnId]['count'].values[0]  # get the current info for this vulns id from the data frame
                    df_image.loc[index_vulnId] = [current['id'], current['severity'], current_vuln_count + 1]  # reset the row with an updated count

                    # reu students found that some severities varied for the same vuln. This is just a check to see if it happens again
                    if current['severity'] != df_image.loc[index_vulnId]['severity'].values[0]:
                        print("wtf")
                        print(current)  # a check for later if this ever happens got to go back and change this statement

                else:
                    # making a new row of our data frame with vuln id, severity and the total count of times it was found in this image
                    new_row = [current['id'], current['severity'], int(1)]
                    df_image.loc[len(df_image.index)] = new_row

        else:  # this image had no results/ vulns so enter NA
            df_image.loc[0] = ['NA', 'NA', 'NA']

        return df_image

    @staticmethod
    def vuln_relation_investigation(df):
        """
        Here we look into the vulns from either grype or trivy and investigate how they handle them/ mainly grype
        :param df:pd.DataFrame(columns=['image_name', 'vuln_id', 'severity', 'count'])
        """
        for i, vuln in df.iterrows():  # for each vuln in the image
            if 'CVE' not in vuln['vuln_id'] and 'NA' not in vuln[
                'vuln_id']:  # we want cve form and na is fine as well so skip over if vuln is one

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
                                    index_vulnId = df[df['vuln_id'] == a].index
                                    current_vuln = df.loc[index_vulnId]

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


def main():
    jc = Json_To_CSV_Grype(str(Path(sys.path[0]).absolute().parent)
                           + "/01_input/Grype/")


main()


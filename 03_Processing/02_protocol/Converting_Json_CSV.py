"""
This is a parent class that just has helpful functions that can be used in the processing of either tools .json file
Here helps sort the versions and their set of images vulnerability sets. It also holds a function to write the data frames to a csv file.
"""

import os
import json
import sys
import pandas as pd
from pathlib import Path
import requests

from GlobalFunctions.Symbolic_Link import link


class Json_To_CSV:
    df_json = pd.DataFrame()

    def __init__(self, path):
        self.df_json = self.version_image_json(path)

    @staticmethod
    def version_image_json(path: str):
        # gets list of versions
        version_list = os.listdir(path)

        version_image_json_list = list()  # list of each version's list of jsons created by running each image
        for v in version_list:
            # gets all jsons in this versions folder
            path_to_json_files = path + v
            image_jsons_list = [filename for filename in os.listdir(path_to_json_files) if filename.endswith('.json')]

            json_per_image_list = list()  # list of all the json texts for one version
            for image_json in image_jsons_list:
                try:
                    # open this version, this images json file that holds info about the vuln this versions found in this image
                    with open(os.path.join(path_to_json_files, image_json), 'r') as json_file:
                        a = json.loads(json_file.read())
                        json_per_image_list.append(a)
                except:
                    print(os.path.join(path_to_json_files, image_json))
            version_image_json_list.append(json_per_image_list)

        # creating a data frame with the versions and their corresponding list(list()) of each images json.
        df = pd.DataFrame(list(zip(version_list, version_image_json_list)),
                          columns=['version', 'json_list'])

        return df

    @staticmethod
    def save_data_to_file(v: str, tool: str, df: pd.DataFrame):

        outpath_directory = str(Path(sys.path[0]).absolute().parent) + '/04_product/' + tool + '/'

        # if the directory doesn't exist yet create it
        if not os.path.exists(outpath_directory):
            os.makedirs(outpath_directory)

        df.to_csv(outpath_directory + v + '.csv')

        # link this output to the input of next step iff not already done, which we check by seeming if shadow folder exists because it's created when linked
        path = str(Path(sys.path[0]).absolute().parent) + '/04_product/' + tool + '/'
        shadow_path = str(Path(sys.path[0]).absolute().parent.parent) + "/04_DataAnalysis/01_input/"+tool
        if not os.path.exists(shadow_path):
            link(path, shadow_path)

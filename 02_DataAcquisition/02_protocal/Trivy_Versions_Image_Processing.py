#!/usr/bin/env python3

"""
Here we run every docker image,
through every version of Trivy and save the json files,
which contain info, specifically a list of vulnerabilities.
"""

from GlobalFunctions.Symbolic_Link import link
import os
import subprocess as sp
import sys
from pathlib import Path


class TrivyImageProcessing:
    def __init__(self):
        # list of the different Trivy versions
        self.TVs = os.listdir(
            str(Path(sys.path[0]).absolute().parent) + "/01_input/Trivy/")

        # list of the different Docker Images (note this comes out as a list of bytes
        self.images = sp.check_output("docker images --format '{{.Repository}}:{{.Tag}}'", shell=True).splitlines()

    def processing(self):
        """goes through each version of trivy and runs every docker image through it. Saves output as json"""

        for t in self.TVs:  # foreach versions of trivy
            trivy_version_filepath = str(Path(sys.path[0]).absolute().parent) + "/01_input/Trivy/" + t
            # self.images = [x for x in self.images if not x.decode('utf-8').__contains__("latest")]  # "don't care"(these aren't images were using for the research)

            for i in self.images:  # for each docker image
                # image comes out as a byte and we need string form
                image = i.decode('utf-8')

                # if the directory doesn't exist yet create it
                if not os.path.exists(str(Path(sys.path[0]).absolute().parent) + '/04_product/Trivy/' + t):
                    os.makedirs(str(Path(sys.path[0]).absolute().parent) + '/04_product/Trivy/' + t)

                # where we want to save the json that contains vulnerability info from the image run through the trivy version
                output_path = (
                            str(Path(sys.path[0]).absolute().parent) + "/04_product/Trivy/" + t + "/" + image + ".json")

                if not os.path.exists(output_path):  # remove if you want to run all images, only here to save time and not rerun data
                    # command line to run the image through the trivy version
                    #./T0_35_0 image --skip-update --format json --output result.json xwiki:15.7

                    cmd = [trivy_version_filepath, "image --timeout 30m --skip-update --format json --output", output_path, image]
                    sp.run(" ".join(cmd), shell=True, check=True)

    def processing_control_database(self):
        """goes through each version of trivy and runs every docker image through it. Saves output as json"""

        for t in self.TVs:  # foreach versions of trivy
            trivy_version_filepath = str(Path(sys.path[0]).absolute().parent) + "/01_input/Trivy/" + t

            for i in self.images:  # for each docker image

                # image comes out as a byte and we need string form
                image = i.decode('utf-8')

                # if the directory doesn't exist yet create it
                if not os.path.exists(str(Path(sys.path[0]).absolute().parent) + '/04_product/Trivy/' + t):
                    os.makedirs(str(Path(sys.path[0]).absolute().parent) + '/04_product/Trivy/' + t)

                # where we want to save the json that contains vulnerability info from the image run through the trivy version
                output_path = (
                            str(Path(sys.path[0]).absolute().parent) + "/04_product/Trivy/" + t + "/" + image + ".json")

                if not os.path.exists(
                        output_path):  # remove if you want to run all images, only here to save time and not rerun data
                    # command line to run the image through the trivy version
                    repo_home = str(Path(sys.path[0]).absolute().parent.parent) + "/GlobalFunctions/nvd_database.json"
                    cmd = [trivy_version_filepath, "image --db-repository", repo_home, "-f json -o", output_path, image]
                    # cmd = [trivy_version_filepath, "image --vuln-type all --vuln-db", repo_home, "-f json -o", output_path, image]
                    sp.run(" ".join(cmd), shell=True, check=True)

                    # trivy image --skip-update image


def main():
    ti = TrivyImageProcessing()
    ti.processing()

    # link this output to the input of next step iff not already done, which we check by seeming if shadow folder exists because it's created when linked
    path = str(Path(sys.path[0]).absolute().parent) + "/04_product/Trivy"
    shadow_path = str(Path(sys.path[0]).absolute().parent.parent) + "/03_Processing/01_input/Trivy"
    if not os.path.exists(shadow_path):
        link(path, shadow_path)


main()

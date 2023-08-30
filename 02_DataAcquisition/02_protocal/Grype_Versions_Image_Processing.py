#!/usr/bin/env python3

"""
Here we run every docker image,
through every version of Grype and save the json files,
which contain info, specifically a list of vulnerabilities.
"""

import os
import subprocess as sp
import sys
from pathlib import Path
from GlobalFunctions.Symbolic_Link import link


class GrypeImageProcessing:
    """class where we process images through grype versions"""

    def __init__(self):
        # list of the different Grype versions
        self.GVs = os.listdir(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/")

        # list of the different images (note this comes out as a list of bytes)
        self.images = sp.check_output("docker images --format '{{.Repository}}:{{.Tag}}'", shell=True).splitlines()

    def processing(self):
        """goes through each version of Grype and runs every docker image through it. Saves output as json"""
        # for each grype version
        for g in self.GVs:

            grype_version_filepath = str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/" + g
            # for each docker image
            for i in self.images:
                # image comes out as a byte and we need string form
                image = i.decode('utf-8')

                # if the directory doesn't exist yet create it
                if not os.path.exists(str(Path(sys.path[0]).absolute().parent) + '/04_product/Grype/' + g):
                    os.makedirs(str(Path(sys.path[0]).absolute().parent) + '/04_product/Grype/' + g)

                # where we want to save the json that contains vulnerability info from the image run through the grype version
                output_path = str(
                    Path(sys.path[0]).absolute().parent) + "/04_product/Grype/" + g + "/" + image + ".json"

                if not os.path.exists(output_path):  # remove if you want to run all images, only here to save time and not rerun data
                    # command line to run the image through the grype version
                    cmd = [grype_version_filepath, image, "-o json>", output_path]
                    sp.run(" ".join(cmd), shell=True, check=True)


def main():
    GI = GrypeImageProcessing()
    GI.processing()

    # link this output to the input of next step iff not already done, which we check by seeming if shadow folder exists because it's created when linked
    path = str(Path(sys.path[0]).absolute().parent) + "/04_product/Grype"
    shadow_path = str(Path(sys.path[0]).absolute().parent.parent) + "/03_Processing/01_input/Grype"
    if not os.path.exists(shadow_path):
        link(path, shadow_path)


main()

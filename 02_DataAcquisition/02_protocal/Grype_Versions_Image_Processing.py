import os
import subprocess as sp
import sys
from pathlib import Path

from GlobalFunctions.Symbolic_Link import link


class GrypeImageProcessing:
    def __init__(self):
        # list of the different Grype versions
        self.GVs = os.listdir(
            str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/")

        # list of the different D
        # ages (note this comes out as a list of bytes
        self.images = sp.check_output("docker images --format '{{.Repository}}:{{.Tag}}'", shell=True).splitlines()

    # goes through each version of Grype and runs every docker image through it. Saves output as json
    def processing(self):
        # for each grype version
        for g in self.GVs:
            if g.__contains__('24'):
                grype_version_filepath = str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/" + g
                # for each docker image
                for i in self.images:
                    # image comes out as a byte and we need string form
                    image = i.decode('utf-8')

                    # so images don't have a latest version/ any version so skip those
                    # Later: why does this happen
                    if not(image.__contains__('none')):
                        # if the directory doesn't exist yet create it
                        if not os.path.exists(str(Path(sys.path[0]).absolute().parent)+'/04_product/Grype/' + g):
                            os.makedirs(str(Path(sys.path[0]).absolute().parent) + '/04_product/Grype/' + g)

                        # where we want to save the json that contains vulnerability info from the image run through the grype version
                        output_path = str(Path(sys.path[0]).absolute().parent) + "/04_product/Grype/" + g + "/" + image + ".json"

                        # command line to run the image through the grype version
                        cmd = [grype_version_filepath, image, "-o json>", output_path]
                        sp.run(" ".join(cmd), shell=True, check=True)
                    else:
                        print(image)


def main():
    GI = GrypeImageProcessing()
    GI.processing()

    # link this output to the iput of next step iff not already done, which we check by seeming if shadow folder exists because it's created when linked
    path = str(Path(sys.path[0]).absolute().parent) + "/04_product/Grype"
    shadow_path = str(Path(sys.path[0]).absolute().parent.parent) + "/03_Processing/01_input/Grype"
    if not os.path.exists(shadow_path):
        link(path, shadow_path)
main()
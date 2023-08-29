import os
import subprocess as sp
import sys
from pathlib import Path

from GlobalFunctions.Symbolic_Link import link


class TrivyImageProcessing:
    def __init__(self):
        # list of the different Trivy versions
        self.TVs = os.listdir(
            str(Path(sys.path[0]).absolute().parent) + "/01_input/Trivy/")

        # list of the different Docker Images (note this comes out as a list of bytes
        self.images = sp.check_output("docker images --format '{{.Repository}}:{{.Tag}}'", shell=True).splitlines()

    # goes through each version of trivy and runs every docker image through it. Saves output as json
    def processing(self):
        # for each trivy version
        for t in self.TVs:
            trivy_version_filepath = str(Path(sys.path[0]).absolute().parent) + "/01_input/Trivy/" + t

            # for each docker image
            for i in self.images:

                print(i)
                # image comes out as a byte and we need string form
                image = i.decode('utf-8')

                # some images don't have the latest version/ any version so skip those
                # Later: why does this happen
                if not (image.__contains__('none')):

                    # if the directory doesn't exist yet create it
                    if not os.path.exists(str(Path(
                            sys.path[0]).absolute().parent.parent) + '/02_DataAcquisition/04_product/Trivy/' + t):
                        os.makedirs(str(Path(
                            sys.path[0]).absolute().parent.parent) + '/02_DataAcquisition/04_product/Trivy/' + t)

                    # where we want to save the json that contains vulnerability info from the image run through the trivy version
                    output_path = (str(Path(
                        sys.path[0]).absolute().parent) + "/04_product/Trivy/" + t + "/" + image + ".json")

                    # command line to run the image through the trivy version
                    cmd = [trivy_version_filepath, "image -f json -o", output_path, image]
                    sp.run(" ".join(cmd), shell=True, check=True)
                else:
                    print(image)


def main():
    TI = TrivyImageProcessing()
    TI.processing()

    # link this output to the input of next step iff not already done, which we check by seeming if shadow folder exists because it's created when linked
    path = str(Path(sys.path[0]).absolute().parent) + "/04_product/Trivy"
    shadow_path = str(Path(sys.path[0]).absolute().parent.parent) + "/03_Processing/01_input/Trivy"
    if not os.path.exists(shadow_path):
        link(path, shadow_path)


main()

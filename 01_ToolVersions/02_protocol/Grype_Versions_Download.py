#!/usr/bin/env python3

"""
Here we are given a .txt file with a list of Grype versions from 01_input,
 we download versions of Grype and save to 04_product
"""

import os
import subprocess as sp
import sys
from pathlib import Path
from GlobalFunctions.Symbolic_Link import link


# Tips:
# -some versions of Grype and Trivy aren't available for download if you have a version not present it will throw an error
#

def main():
    """We read in the input txt file with desired Grype versions and run through our install grype version function"""
    with open(
            str(Path(sys.path[0]).absolute().parent) + "/01_input/GrypeVersions.txt",
            "r") as f:
        versions = f.read().splitlines()

    for version in versions:
        install_grype(version)

    # builds a link to the next part of the processes input. Just done once if link doesn't exist yet
    path = str(Path(sys.path[0]).absolute().parent) + "/04_product/Grype"
    shadow_path = str(Path(sys.path[0]).absolute().parent.parent) + "/02_DataAcquisition/01_input/Grype"
    if not os.path.exists(shadow_path):  # shadow_path only exists if we already linked
        link(path, shadow_path)



def install_grype(version):
    """This function is for downloading versions of grype  """
    """Given a version in string form (vX.XX.X or vX.X.X) downloads the associated Grype version and save it."""

    # make file path to save out to
    path = str(Path(sys.path[0]).absolute().parent) + "/04_product/Grype/"

    # command to install grype version of interest
    cmd = ["curl", "-sSfL", "https://raw.githubusercontent.com/anchore/grype/main/install.sh",
           "|", "sh", "-s", "--", "-b", path, version]
    sp.run(" ".join(cmd), shell=True, check=True)


    # command to change the name, so we have the version numbers as the tool title
    cmd = ["mv", path + "grype", path + "O" + version.replace("v", "G").replace(".", "_")]
    sp.run(" ".join(cmd), shell=True, check=True)


main()

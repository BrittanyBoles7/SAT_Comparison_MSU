import os
import requests
import subprocess as sp
import sys
from pathlib import Path
from GlobalFunctions.Symbolic_Link import link

# Tips:
# -some versions of Grype and Trivy aren't available for download if you have a version not present it will throw an error
#

# Given a version (vX.XX.X or vX.X.X) downloads the associated Grype version and save it .
def install_grype(version):
    # make file path to save out to
    path = str(Path(sys.path[0]).absolute().parent) + "/04_product/Grype/"

    # command to install grype version of intrest
    cmd = ["curl", "-sSfL", "https://raw.githubusercontent.com/anchore/grype/main/install.sh",
           "|", "sh", "-s", "--", "-b", path, version]
    sp.run(" ".join(cmd), shell=True, check=True)

    # command to change the name, so we have the version numbers as the tool title
    cmd = ["mv", path + "grype", path + version.replace("v", "G").replace(".", "_")]
    sp.run(" ".join(cmd), shell=True, check=True)


def main():
    with open(
            str(Path(sys.path[0]).absolute().parent) + "/01_input/GrypeVersions.txt",
            "r") as f:
        versions = f.read().splitlines()

    for version in versions:
        install_grype(version)

    # builds a link to the next part of the processes input. Just done once
    path = str(Path(sys.path[0]).absolute().parent) + "/04_product/Grype"
    shadow_path = str(Path(sys.path[0]).absolute().parent.parent) + "/02_DataAcquisition/01_input/Grype"
    if not os.path.exists(shadow_path):
        link(path, shadow_path)


main()

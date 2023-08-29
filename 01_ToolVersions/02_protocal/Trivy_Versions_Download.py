import os
import requests
import sys
import subprocess as sp
from pathlib import Path
from GlobalFunctions.Symbolic_Link import link


# Tips:
# -some versions of Grype and Trivy aren't available for download if you have a version not present it will throw an error
#

# Given a version (vX.XX.X or vX.X.X) downloads the associated Trivy version and save it .
def install_trivy(version):
    # make file path to save out to
    path = str(Path(sys.path[0]).absolute().parent.parent) + "/01_ToolVersions/04_product/Trivy/"

    # command to install grype version of intrest
    cmd = ["curl", "-sSfL", "https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh",
           "|", "sh", "-s", "--", "-b", path, version]
    sp.run(" ".join(cmd), shell=True, check=True)

    # command to change the name, so we have the version numbers as the tool title
    cmd = ["mv", path + "trivy", path + version.replace("v", "T").replace(".", "_")]
    sp.run(" ".join(cmd), shell=True, check=True)


def main():
    # versionNames should look like a list = ['vx.x.x','vx.xx.x']
    with open(
            str(Path(sys.path[0]).absolute().parent.parent) + "/01_ToolVersions/01_input/TrivyVersions.txt",
            "r") as f:
        versions = f.read().splitlines()

    for version in versions:
        install_trivy(version)

    # builds a link to the next part of the processes input. Just done once
    path = str(Path(sys.path[0]).absolute().parent.parent) + "/01_ToolVersions/04_product/Trivy"
    shadow_path = str(Path(sys.path[0]).absolute().parent.parent) + "/02_DataAcquisition/01_input/Trivy"
    if not os.path.exists(shadow_path):
        link(path, shadow_path)


main()

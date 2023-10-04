import subprocess as sp
import sys
from pathlib import Path


def install_Grype_control_database():
    # make file path to save out to
    path = str(Path(sys.path[0]).absolute().parent.parent) + "/01_ToolVersions/01_input"
    path_og = str(Path(sys.path[0]).absolute().parent.parent.parent)

    # command to install grype version of interest
    cmd = ["curl", "-sSfL", "https://raw.githubusercontent.com/anchore/grype-db/main/install.sh",
           "|", "sh", "-s", "--", "-b", path, "/v0.19.1"]
    sp.run(" ".join(cmd), shell=True, check=True)

    # a tool that grype-db uses to build databases/download them
    cmd = ["pip install vunnel"]
    sp.run(" ".join(cmd), shell=True, check=True)

    a = 0
    cmd = ["mv", path_og + "/.local/bin/vunnel", path + "/"]
    sp.run(" ".join(cmd), shell=True, check=True)

    # ask vunnel to get "x" database
    cmd = [path + "/vunnel", "-v", "run", "nvd"]
    sp.run(" ".join(cmd), shell=True, check=True)

    # pull the database into grype-db
    cmd = [path + "/grype-db", "pull", "-g -p nvd"]  # ??
    sp.run(" ".join(cmd), shell=True, check=True)

    # build and format that database?
    cmd = [path + "/grype-db", "build", "-g", "--dir=" + path + "/build", "-p nvd"]
    sp.run(" ".join(cmd), shell=True, check=True)

    cmd = [path + "/grype-db", "package", "--dir=" + path + "/build"]
    sp.run(" ".join(cmd), shell=True, check=True)


# install_Grype_control_database()


def install_trivy_control_database():
    # make file path to save out to
    path = str(Path(sys.path[0]).absolute().parent.parent) + "/01_ToolVersions/01_input"
    path_og = str(Path(sys.path[0]).absolute().parent.parent.parent)

    # command to trivy-db tool
    cmd = ["docker pull aquasec/trivy-db:v1-2023021412"]
    sp.run(" ".join(cmd), shell=True, check=True)

    # command to trivy-db tool
    cmd = [""]
    sp.run(" ".join(cmd), shell=True, check=True)


install_trivy_control_database()
import subprocess as sp
import sys
from pathlib import Path


# old code to try to download Grype and Trivy's databases vendor by vendor


def install_Grype_control_database():
    # make file path to save out to
    path = str(Path(sys.path[0]).absolute().parent.parent) + "/01_ToolVersions/01_input"

    # command to install grype version of interest
    cmd = ["curl", "-sSfL", "https://raw.githubusercontent.com/anchore/grype-db/main/install.sh",
           "|", "sh", "-s", "--", "-b", path, "/v0.19.1"]
    sp.run(" ".join(cmd), shell=True, check=True)

    vendors = ['alpine', 'amazon', 'chainguard', 'debian', 'github', 'mariner', 'nvd', 'oracle', 'rhel', 'sles',
               'ubuntu', 'wolfi']

    for v in vendors:
        # # a tool that grype-db uses to build databases/download them
        # cmd = ["pip install vunnel"]
        # sp.run(" ".join(cmd), shell=True, check=True)
        #
        # # cmd = ["mv", path_og + "/.local/bin/vunnel", path + "/"]
        # # sp.run(" ".join(cmd), shell=True, check=True)
        #
        # # ask vunnel to get "x" database
        # cmd = [path + "/vunnel", "-v", "run", "nvd"]
        # sp.run(" ".join(cmd), shell=True, check=True)

        # pull the database into grype-db
        cmd = [path + "/grype-db", "pull", "-g -p", v]  # ??
        sp.run(" ".join(cmd), shell=True, check=True)

        # build and format that database?
        cmd = [path + "/grype-db", "build", "-g", "--dir=" + path + "/build", "-p", v]
        sp.run(" ".join(cmd), shell=True, check=True)

        cmd = [path + "/grype-db", "package", "--dir=" + path + "/build"]
        sp.run(" ".join(cmd), shell=True, check=True)


# install_Grype_control_database()


def install_trivy_control_database():
    # make file path to save out to
    path_here = str(Path(sys.path[0]).absolute())

    cmd = ["oras pull ghcr.io/aquasecurity/trivy-db:2"]
    sp.run(" ".join(cmd), shell=True, check=True)

    cmd = ["rsync -av -e ssh", path_here + "/db.tar.gz"]
    sp.run(" ".join(cmd), shell=True, check=True)


install_trivy_control_database()

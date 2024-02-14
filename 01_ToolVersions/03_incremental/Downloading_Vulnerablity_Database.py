import subprocess as sp
import sys
from pathlib import Path


# Downloading vulnerability databases for static use. "offline environment" So we can always recreate results. Both for grype and Trivy

# We don't use this way for Grype currently, we just save the vulnerability database grype has on saved on our local machine the same
# day we download Trivy's vulnerability database. This makes them as close as possible and is easy.
def install_Grype_control_database():
    """
    here we download all databases possible for grype to use and then could later point to it.
    instead currently we just saved the database from a certain date and use that to compare vulnerabilities.
    We pull Trivy's database from the same date.
    """
    # make file path to save out to
    path = str(Path(sys.path[0]).absolute().parent.parent) + "/01_ToolVersions/01_input"

    # command to install grype version of interest
    cmd = ["curl", "-sSfL", "https://raw.githubusercontent.com/anchore/grype-db/main/install.sh",
           "|", "sh", "-s", "--", "-b", path, "/v0.19.1"]
    sp.run(" ".join(cmd), shell=True, check=True)

    vendors = ['alpine', 'amazon', 'chainguard', 'debian', 'github', 'mariner', 'nvd', 'oracle', 'rhel', 'sles',
               'ubuntu', 'wolfi']

    # # a tool that grype-db uses to build databases/download them you might need to install?
    # cmd = ["pip install vunnel"]
    # sp.run(" ".join(cmd), shell=True, check=True)
    #
    # # cmd = ["mv", path_og + "/.local/bin/vunnel", path + "/"]
    # # sp.run(" ".join(cmd), shell=True, check=True)
    #
    # # ask vunnel to get "x" database
    # cmd = [path + "/vunnel", "-v", "run", "nvd"]
    # sp.run(" ".join(cmd), shell=True, check=True)

    for v in vendors:

        # pull all the upsteam vulnerability data sources to local cache
        cmd = [path + "/grype-db", "pull", "-g -p", v]  # ??
        sp.run(" ".join(cmd), shell=True, check=True)

        # build a SQLite DB from the vulnerability data for a particular schema version
        cmd = [path + "/grype-db", "build", "-g", "--dir=" + path + "/build", "-p", v]
        sp.run(" ".join(cmd), shell=True, check=True)

        # Package the already built DB file into an archive ready for upload and serving.
        cmd = [path + "/grype-db", "package", "--dir=" + path + "/build"]
        sp.run(" ".join(cmd), shell=True, check=True)


# install_Grype_control_database()

'''
Updated way to download the trivy vulnerability database. 
They collect and store all databases, and can be easily pulled and then pointed to
'''
def install_trivy_control_database():
    # make file path to save out to
    path_here = str(Path(sys.path[0]).absolute())

    cmd = ["oras pull ghcr.io/aquasecurity/trivy-db:2"]
    sp.run(" ".join(cmd), shell=True, check=True)

    cmd = ["rsync -av -e ssh", path_here + "/db.tar.gz"]
    sp.run(" ".join(cmd), shell=True, check=True)


install_trivy_control_database()

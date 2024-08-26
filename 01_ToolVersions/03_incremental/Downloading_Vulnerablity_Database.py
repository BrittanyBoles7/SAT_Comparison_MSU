import subprocess as sp
import sys
from pathlib import Path


# Downloading vulnerability databases for static use. "offline environment" So we can always recreate results. Both for grype and Trivy



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


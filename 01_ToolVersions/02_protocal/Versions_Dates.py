# later we want to automatically download dates of when the versions come out

import subprocess as sp
import sys
from pathlib import Path

def main():
    # list of the different images (note this comes out as a list of bytes)
    images = sp.check_output("docker images --format '{{.Repository}}:{{.Tag}}'", shell=True).splitlines()
    a = []
    for image in images:
        i = image.decode('utf-8')
        if i.__contains__('none'):
            # command to install grype version of interest
            cmd = ['docker rmi', i]
            sp.run(" ".join(cmd), shell=True, check=True)

    print(a)







main()

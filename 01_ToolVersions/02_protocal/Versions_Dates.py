# later we want to automatically download dates of when the versions come out

import subprocess as sp
import sys
from pathlib import Path


# creates a list of the different images we use, for storage later/ records
# def main():
#     # list of the different images (note this comes out as a list of bytes)
#     images = sp.check_output("docker images --format '{{.Repository}}:{{.Tag}}'", shell=True).splitlines()
#     a = []
#     for image in images:
#         i = image.decode('utf-8')
#         if i.__contains__('none'):
#             # command to install grype version of interest
#             cmd = ['docker rmi', i]
#             sp.run(" ".join(cmd), shell=True, check=True)
#
#     print(a)

# creates .txt file of versions
def main():
    with open(str(Path(sys.path[0]).absolute().parent) + '/01_input/GrypeVersions.txt', 'w') as f:
        f.write('v0.63.0')

        with open(str(Path(sys.path[0]).absolute().parent) + '/01_input/TrivyVersions.txt', 'w') as f:
            f.write('v0.63.0')


main()

import sys
from pathlib import Path
import os
import subprocess as sp
import sys
from pathlib import Path

'''
This is a function to download docker images. I have a text file of 
all the docker images I want to download and the versions
'''
def main():
    with open(
            str(Path(sys.path[0]).absolute()) + "/research_images.txt",
            "r") as f:
        versions = f.read().splitlines()

    for i in versions:
        try:
            cmd = ['docker image inspect', i]
            check = sp.check_output(" ".join(cmd), shell=True).splitlines()
        except:
            check = None

        if check is None and i.__contains__('none') != True:
            cmd = ['docker', 'pull', i]
            sp.run(" ".join(cmd), shell=True, check=True)

        else:
            print(i)



main()

import sys
from pathlib import Path
import os
import subprocess as sp
import sys
from pathlib import Path


def main():
    with open(
            str(Path(sys.path[0]).absolute()) + "/research_images.txt",
            "r") as f:
        versions = f.read().splitlines()
    for i in versions:
        cmd = ['docker', 'pull', i]
        sp.run(" ".join(cmd), shell=True, check=True)
        print(i)
        # elasticsearch:8.9.1 couldn't be pulled rate limit



main()

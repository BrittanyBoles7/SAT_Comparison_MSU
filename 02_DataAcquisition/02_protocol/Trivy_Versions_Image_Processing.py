#!/usr/bin/env python3

"""
Here we run every docker image,
through every version of Trivy and save the json files,
which contain info, specifically a list of vulnerabilities.
"""
import json

from GlobalFunctions.Symbolic_Link import link
import os
import subprocess as sp
import sys
from pathlib import Path


class TrivyImageProcessing:
    def __init__(self):
        # list of the different Trivy versions
        self.TVs = os.listdir(
            str(Path(sys.path[0]).absolute().parent) + "/01_input/Trivy/")

        # list of the different Docker Images (note this comes out as a list of bytes)
        #self.images = sp.check_output("docker images --format '{{.Repository}}:{{.Tag}}'", shell=True).splitlines()
        self.images = self.open_file_docker_images_to_download()

    def processing(self):
        """goes through each version of trivy and runs every docker image through it. Saves output as json"""

        for t in self.TVs:  # foreach versions of trivy
            trivy_version_filepath = str(Path(sys.path[0]).absolute().parent) + "/01_input/Trivy/" + t
            # self.images = [x for x in self.images if not x.decode('utf-8').__contains__("latest")]  # "don't care"(these aren't images were using for the research)
            print(t)
            for image in self.images:  # for each docker image

                # image comes out as a byte and we need string form
                #image = i.decode('utf-8')

                # if the directory doesn't exist yet create it
                if not os.path.exists(str(Path(sys.path[0]).absolute().parent) + '/04_product/Trivy/' + t ):
                    os.makedirs(str(Path(sys.path[0]).absolute().parent) + '/04_product/Trivy/' + t  )

                # where we want to save the json that contains vulnerability info from the image run through the trivy version
                output_path = (
                        str(Path(sys.path[0]).absolute().parent) + "/04_product/Trivy/" + t + "/" + image + ".json")

                if not os.path.exists(
                        output_path):  # remove if you want to run all images, only here to save time and not rerun data
                    self.download_dockerImage(image)
                    # command line to run the image through the trivy version
                    cmd = [trivy_version_filepath,
                           "image --timeout 30m --skip-db-update --offline-scan --format json --output", output_path, image]
                    sp.run(" ".join(cmd), shell=True, check=True)
                    self.delete_dockerImage(image)

    def open_file_docker_images_to_download(self):
        path = str(Path(sys.path[0]).absolute().parent.parent) + "/00_DockerImages/04_product/docker-images.json"
        # Read the JSON file
        with open(path, 'r') as file:
            data = json.load(file)

        # Create a list of images and versions
        image_versions = []


        # Iterate through each image in the JSON data
        for image in data['images']:
            image_name = image['name']
            image['versions'] = [version for version in image['versions'] if 'windows' not in version and 'nanoserver' not in version] # I am not a running on windows
            c = len(image['versions'])

            if c >= 10:
                step = (c - 1) / 9
                indices = [int(i * step) for i in range(10)]
            else:
                indices = [i for i in range(0, c)]

            # Iterate through each version in the image
            for i in indices:
                version = image['versions'][i]
                # Combine image name and version and append to the list
                image_versions.append(f"{image_name}:{version}")

        return image_versions

    def download_dockerImage(self, image_version):

        try:
            cmd = ['docker image inspect', image_version]
            check = sp.check_output(" ".join(cmd), shell=True).splitlines()
        except:
            check = None

        if check is None and image_version.__contains__('none') != True:
            cmd = ['docker', 'pull', image_version]
            sp.run(" ".join(cmd), shell=True, check=True)
            print(image_version)

    @staticmethod
    def delete_dockerImage(image_version):

        cmd = ['docker', 'image rm', image_version]
        sp.run(" ".join(cmd), shell=True, check=True)
        print("rm " + image_version)


def main():
    ti = TrivyImageProcessing()
    ti.processing()

    # link this output to the input of next step iff not already done, which we check by seeming if shadow folder exists because it's created when linked
    path = str(Path(sys.path[0]).absolute().parent) + "/04_product/Trivy"
    shadow_path = str(Path(sys.path[0]).absolute().parent.parent) + "/03_Processing/01_input/Trivy"
    if not os.path.exists(shadow_path):
        link(path, shadow_path)


main()

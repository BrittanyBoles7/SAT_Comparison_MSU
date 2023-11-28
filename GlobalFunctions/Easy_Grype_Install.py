
import subprocess as sp


def Running_Grype():
    """Grype runs every docker image through it. Saves output as json"""
    grype_version_filepath = "PATH TO YOUR GRYPE TOOL"

    # here you have to already have docker installed and have pulled the images you want to study.
    # list of the different images (note this comes out as a list of bytes)
    images = sp.check_output("docker images --format '{{.Repository}}:{{.Tag}}'", shell=True).splitlines()
    # for each docker image
    for i in images:

        # image comes out as a byte, and we need string form
        image = i.decode('utf-8')

        # where we want to save the json that contains vulnerability info from the image run through the grype version
        output_path ="OUTPUT PATH YOU WANT RESULTS TO GO TO" + image + ".json"

        # OTHER CONFIGS YOU COULD ADD: --scope all-layers  --by-cve
        cmd = [grype_version_filepath, image, " -o json>", output_path]  # by cve
        sp.run(" ".join(cmd), shell=True, check=True)

def main():

    version = "v0.71.0"

    # make file path to save out to
    path = "PUT YOUR PATH HERE"

    # command to install grype version of interest
    cmd = ["curl", "-sSfL", "https://raw.githubusercontent.com/anchore/grype/main/install.sh",
           "|", "sh", "-s", "--", "-b", path, version]
    sp.run(" ".join(cmd), shell=True, check=True)

    Running_Grype()

    return

main()



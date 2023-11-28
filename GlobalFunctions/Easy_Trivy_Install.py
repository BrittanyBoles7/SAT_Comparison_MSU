

import subprocess as sp



def Running_Trivy():
    """Trivy runs every docker image through it. Saves output as json"""
    trivy_version_filepath = "YOUR PATH YOU SAVED TRIVY TOO"
    images = sp.check_output("docker images --format '{{.Repository}}:{{.Tag}}'", shell=True).splitlines()
    for i in images:  # for each docker image
        # image comes out as a byte and we need string form
        image = i.decode('utf-8')

        # where we want to save the json that contains vulnerability info from the image run through the trivy version
        output_path = "PATH YOU WANT RESULTS TO PRINT TO" + image + ".json"

        cmd = [trivy_version_filepath, "image --timeout 30m --format json --output", output_path, image]
        sp.run(" ".join(cmd), shell=True, check=True)
    return

def main():

    version = ('v0.47.0'
               '')
    # make file path to save out to
    path = "YOUR PATH YOU WANT TO SAVE AT"

    # command to install grype version of intrest
    cmd = ["curl", "-sSfL", "https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh",
           "|", "sh", "-s", "--", "-b", path, version]
    sp.run(" ".join(cmd), shell=True, check=True)

    Running_Trivy()
    return


main()
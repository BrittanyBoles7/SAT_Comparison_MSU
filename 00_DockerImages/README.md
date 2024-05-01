## Introduction
In 00_DockerImages the goal is to collect the docker images
we want to run our program on. 

## 01_input
The input folder is an outdated method with a list of docker 
images to install. You could download all the images and then run 
tools over them. Instead, we opt to collect a list of docker images
then download, run and then delete them to save space on our local 
computers. You can ignore this folder unless you want the previous
method. 

## 02_protocol
Here we have python script that goes through docker collecting a 
list of all versions of the top 100 images. It outputs this list
in 04_product. Later we can sort through and choose which versions 
to use. 

## 04_product
JSON file with the top 100 docker images and all their versions. 
We use this again in 02_DataAcquisition, pulling some subset of the 
images and then running them through Grype and Trivy, finally deleting them 
off our machines. 

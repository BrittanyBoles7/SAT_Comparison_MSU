## Introduction
The goal of this section is to get the results of running docker images
through the tools/versions that we download previously. 

___
## 01_input
Grype folder with versions of Grype to get results from and Trivy folder
with versions of Trivy to get results from.
---
## 02_protocol
Grype_Versions_Image_Processing:  
Here we run the docker images on our local machine through each of the versions of Grype
and save the results in a json file for each image.  
  
Trivy_Versions_Image_Processing:  
Here we run the docker images on our local machine through each of the versions of Trivy
and save the results in a json file for each image.   
Note: we are using Trivy in an offline environment at the moment when scanning we use the configurations
"--skip-db-update", "--offline-scan" and due to timeout errors we also use the configuration
 "--timeout 30m" for Trivy. 
---
## 04_product
Here we have folders for both Grype and Trivy. For each tool we have a folder for each version
and with in each versions folder we have the resulting json files for each image analyzed. 


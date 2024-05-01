## Introduction
The goal of this section is to get the results of running docker images
through the tools/versions that we download previously. 

___
## 01_input
Grype folder with versions of Grype to get results from and Trivy folder
with versions of Trivy to get results from.
---
## 02_protocol
both methods are currently set up to not rerun images we already have saved. So
you need to delete the old run throws if you want new results, or change the 
saving process.
Grype_Versions_Image_Processing:  
Here we run the docker images on our local machine through each of the versions of Grype
and save the results in a json file for each image. We reset the config file, pointing it
to the saved files in 02_ToolVersions/03_incremental. There is two config files, one is to use
CPE matching and one is to not, so we can test the differences. 
  
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


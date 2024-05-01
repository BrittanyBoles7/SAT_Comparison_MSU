## Introduction
01_ToolVersions: In this section we given a .txt file with the different versions of the Static Analysis Tools you want, we download them.
Specifically this pipeline is designed for Grype and Trivy but can easily
be adjusted to add other static analysis tools that analyze Docker Images.
___
## Tools
Grype and Trivy
___
## 01_input
Here we have GrypeVersions.txt and Trivy.txt with the input formatted   
vx.xx.x    
vx.xx.x
---
## 02_protocol

Set Up:
Before running these, download the static databases from our git. We collected them
on Nov 7th. We set the tools to use static databases to have consistent and 
reproducible results. Put Trivy's database in 03_incremental of this section
and change the path of the db in Grype's config file, for where 
ever store its database. Slight adjustments can also be made to use the tools 
normally as well. In Global functions we have functions that download both tools
with the general configurations. 

Grype_Version_Download:  
Here given the list from 01_input, we download all the versions of Grype.
A commented out function allows to download the tool normally, however for 
Grype we change the database to static later with the config file 
while running an analysis on images. To get Grype's database we just copied 
and saved Grypes database the same day we download Trivy's, so both tools 
databases were from the same day. 

Trivy_Versions_Download:  
Here we download all the versions of Trivy from the input lists. We also have 
to set Trivy's database to be static in this section. We also set Trivys database
here.03_incremental have the function used to pull the Trivy database. 
  
## 03_incremental
 
Downloading_vulnerability_Database:
here we have two functions that download the grype and trivy databases at current time
and stores them on our local machine for use later. We use this before the protocol if we are 
running Grype and Trivy in an offline environment for reproducibility.

## 04_product
two folders: one for Grype and one for Trivy, with the versions of each tool downloaded.
The folders are automatically linked with the 01_input folder in 02_DataAcquisition.


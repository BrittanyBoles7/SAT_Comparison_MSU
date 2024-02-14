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
Grype_Version_Download:  
Here we have three method options. One is to simply download the Grype versions 
given to us from 01_input. The Second is to download Grype, but set the vulnerability database
to a saved one on our local machine. This is following their "offline" instructions, making the database static and not updated
every 24 hours. This is to help with reproducibility of results
if needed. The third is to download grype with the static database as before,
and to also turn on CPE matching if version is after v0.69.0. This is because the configuration has a
large impact on the results.  
  
Trivy_Versions_Download:  
Here we have two method options. One is to simply download the Trivy versions
given to us in 01_input. The second is to download Trivy and set its vulnerability database
to be one saved on our local machine. This makes the database static, not updated every 12 hours like
it would be otherwise.  
  
## 03_incremental
 
Downloading_vulnerability_Database:
here we have two functions that download the grype and trivy databases at current time
and stores them on our local machine for use later. We use this before the protocol if we are 
running Grype and Trivy in an offline environment for reproducibility.

## 04_product
two folders: one for Grype and one for Trivy, with the versions of each tool downloaded.

## Build Environment


## Notes
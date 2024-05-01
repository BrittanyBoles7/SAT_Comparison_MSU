## Introduction
The goal of this section is sorting through both Grype and Trivys results
turning them into common dataframes. We collect information on the image, vulnerabilities
counts, severity and for grype related vulnerabilities. 

___
## 01_input
Grype and Trivy folders. Each folder contains a json for each images that's the results
from both tools. 
---
## 02_protocol
Converting_json_CVS:
This class helps load up and sort through all the json files from either tool and also 
hold the function that saves each tools output.

Json_To_CVS_Grype:
Sorts through Grype's output, saving a dataframe with the image source, vulnerabilities, counts severities 
and if there exists a related vulnerabilities. 

Json_To_CVS_Trivy:
sorts through Trivy's output, saving a dataframe with the image source, vulnerabilities,
severity and counts. 
---
## 04_product
Each tool version has a cvs that is a collection of all the vulnerabilities found 
in the corpus of docker images. 

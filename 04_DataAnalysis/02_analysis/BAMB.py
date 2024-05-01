import sys
from pathlib import Path
import pandas as pd


def severity_difference():
    G_CPE = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/CPE_G0_73_0.csv", na_filter=False)
    G_73 = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/G0_73_0.csv", na_filter=False)
    T_49 = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Trivy/T0_49_0.csv", na_filter=False)

    G_73 = G_73[G_73['image_name'] != "golang:1.4rc1"]
    G_CPE = G_CPE[G_CPE['image_name'] != "golang:1.4rc1"]
    T_49 = T_49[T_49['image_name'] != "alpine:3.17.1"]
    T_49 = T_49[T_49['image_name'] != "alpine:3.18.5"]
    T_49 = T_49[T_49['image_name'] != "alpine:3.18.2"]


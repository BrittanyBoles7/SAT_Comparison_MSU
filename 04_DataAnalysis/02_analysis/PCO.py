import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from skbio.stats.ordination import pcoa
from skbio import DistanceMatrix
import sys
from pathlib import Path


df_trivy = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Trivy/T0_47_0.csv", na_filter=False)
df_grype = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/G0_73_0.csv", na_filter=False)

# Map severities to numerical values
severity_map = {
    'negligible': 0,
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4,
    'unknown': -1
}

## Drop the severity column from both DataFrames
df_grype = df_grype.drop(columns='severity')
df_grype = df_grype.drop(columns='related_vuln')
df_trivy = df_trivy.drop(columns='severity')

# Combine the data from both DataFrames
df_combined = pd.concat([df_grype, df_trivy])

# Create a distance matrix with zeros along the diagonal
#n = len(df_combined)dm_data = np.zeros((n, n))

# Perform PCO
dm = DistanceMatrix(np.ones((len(df_combined), len(df_combined))))
pcoa_results = pcoa(dm)

# Plot the results
plt.figure(figsize=(8, 6))

# Plot data from df_grype
plt.scatter(pcoa_results.samples.loc[df_grype.index, 'PC1'],
            pcoa_results.samples.loc[df_grype.index, 'PC2'],
            c='blue', label='Grype')

# Plot data from df_trivy
plt.scatter(pcoa_results.samples.loc[df_trivy.index, 'PC1'],
            pcoa_results.samples.loc[df_trivy.index, 'PC2'],
            c='green', label='Trivy')

plt.title('Principal Coordinate Analysis (Excluding Severity)')
plt.xlabel('PC1')
plt.ylabel('PC2')
plt.legend()
plt.grid(True)
plt.show()

print("hi")
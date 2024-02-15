import sys
from pathlib import Path
import seaborn as sns
import pandas as pd

import matplotlib.pyplot as plt



def get_data():
    G_CPE = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/CPEG0_73_0.csv", na_filter = False)
    G_73 = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/G0_73_0.csv")

    image_vuln_count_CPE = get_count(G_CPE)
    image_vuln_count = get_count(G_73)

    # Sample DataFrame (replace this with your actual DataFrame)
    data = {
        'Image_Name': "Grype",
        'Grype_with_CPE': image_vuln_count['count'],
    }

    df = pd.DataFrame(data)

    # Melt the DataFrame to create a long-form DataFrame
    df_melted = pd.melt(df, id_vars=['Image_Name'], var_name='Tool', value_name='Vulnerabilities')

    # Create violin plots
    plt.figure(figsize=(10, 6))
    sns.violinplot(x='Tool', y='Vulnerabilities', data= df_melted)
    plt.title('Distribution of Vulnerabilities by Tool')
    plt.xlabel('Tool')
    plt.ylabel('Number of Vulnerabilities')
    plt.show()


    print("nothing")


def get_count(df_input):
    df_g = pd.DataFrame(columns=['image_name', 'count'])
    current_image = df_input.values[0][1]
    count = 0
    for i, g in df_input.iterrows():
        if current_image in g['image_name']:
            count = count + int(g['count'])
        elif  df_g['image_name'].__contains__(current_image):
            print("huh " + current_image)
        else:
            new_row = [current_image, count]
            df_g.loc[len(df_g.index)] = new_row
            current_image = g['image_name']
            count = 0
    return df_g

get_data()
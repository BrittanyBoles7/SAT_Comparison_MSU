import sys
from pathlib import Path
import seaborn as sns
import pandas as pd
import matplotlib.pyplot as plt



def get_data():
    G_CPE = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/G0_69_0.csv", na_filter = False)
    G_73 = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/G0_73_0.csv", na_filter = False)
    T_47 = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Trivy/T0_47_0.csv", na_filter = False)
    image_vuln_count_CPE = get_count(G_CPE)
    image_vuln_count = get_count(G_73)

    # Sample DataFrame (replace this with your actual DataFrame)
    data = {
        'Image_Name': get_count(G_CPE)['image_name'],
        'Trivy v0.47.0': get_count(G_CPE)['count'],
        'Grype v0.73.0': get_count(G_73)['count']
    }
    # Define custom color palette
    custom_palette = {'Trivy v0.47.0': (0.8, 0.95, 0.7), 'Grype v0.73.0': (0.5,0.7, 0.95)}
    df = pd.DataFrame(data)

    # Melt the DataFrame to create a long-form DataFrame
    df_melted = pd.melt(df, id_vars=['Image_Name'], var_name='Tool', value_name='Vulnerabilities')

    # Create violin plots for each tool
    plt.figure(figsize=(12, 6))
    sns.violinplot(x='Tool', y='Vulnerabilities', data=df_melted, inner='quartile', palette= custom_palette, cut = 0)

    plt.xlabel('Static Analysis Tool', fontsize='22')
    plt.ylabel('Number of Vulnerabilities Per Image', fontsize='22')
    plt.xticks(fontsize=20)
    plt.yticks(fontsize=20)

    plt.show()
    print("nothing")


def get_count(df_input):
    df_g = pd.DataFrame(columns=['image_name', 'count'])
    current_image = df_input.values[0][1]
    count = 0
    for i, g in df_input.iterrows():
        if current_image in g['image_name']:
            count = count + int(g['count'])
        elif df_g['image_name'].__contains__(current_image):
            print("huh " + current_image)
        else:
            new_row = [current_image, count]
            df_g.loc[len(df_g.index)] = new_row
            current_image = g['image_name']
            count = 0
    return df_g

get_data()
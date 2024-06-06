import math
import sys
from pathlib import Path

import numpy as np
import seaborn as sns
import pandas as pd
import matplotlib.pyplot as plt


def distribution(df):
    """
    :param df dataframe from reports from Grype and Trivy :
    :return number of vulnerabilities in each image:
    """
    # Replace 'NA' strings with actual NaN values
    df.replace('NA', pd.NA, inplace=True)

    # Convert 'count' column to numeric
    df['count'] = pd.to_numeric(df['count'], errors='coerce')

    # Group by 'image_name' and sum the 'count' for each image
    image_counts = df.groupby('image_name')['count'].sum()

    # Reset index to convert the result into a DataFrame
    image_counts_df = image_counts.reset_index()

    # If there are NaN values in the 'count' column, replace them with 0
    image_counts_df['count'] = image_counts_df['count'].fillna(0)

    return image_counts_df


class Measuring_Differences:
    def __init__(self):
        G_CPE = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/CPE_G0_73_0.csv",
                            na_filter=False)
        G_73 = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/G0_73_0.csv", na_filter=False)
        T_49 = pd.read_csv(str(Path(sys.path[0]).absolute().parent) + "/01_input/Trivy/T0_49_0.csv", na_filter=False)

        self.G_73 = G_73[G_73['image_name'] != "golang:1.4rc1"]
        self.G_CPE = G_CPE[G_CPE['image_name'] != "golang:1.4rc1"]
        T_49 = T_49[T_49['image_name'] != "alpine:3.17.1"]
        T_49 = T_49[T_49['image_name'] != "alpine:3.18.5"]
        self.T_49 = T_49[T_49['image_name'] != "alpine:3.18.2"]

    def label_counts(self):
        """This function calculates the percent of each ID label type, all the tools reports have"""
        GHSA = []
        CVE = []
        ALAS = []
        DLA = []
        DSA = []
        NSWG = []
        count = 0
        # the types image_name,vuln_id,severity,count,related_vuln
        for indx, j, i, v, s, c in self.T_49.itertuples():
            if 'GHSA' in v:
                GHSA.append(c)
                count = count + float(c)
            elif 'CVE' in v:
                CVE.append(c)
                count = count + float(c)
            elif 'ALAS' in v:
                ALAS.append(c)
                count = count + float(c)
            elif 'DLA' in v:
                DLA.append(c)
                count = count + float(c)
            elif 'DSA' in v:
                DSA.append(c)
                count = count + float(c)
            elif 'NSWG' in v:
                NSWG.append(c)
                count = count + float(c)
            elif 'NA' in v:
                pass
            else:
                print(v)
        print(" Trivy GHSA count", np.array(GHSA).astype(float).sum() )
        print(" Trivy CVE count", np.array(CVE).astype(float).sum() )
        print(" Trivy ALAS count", np.array(ALAS).astype(float).sum() )
        print(" Trivy DLA count", np.array(DLA).astype(float).sum() )
        print(" Trivy DSA count", np.array(DSA).astype(float).sum())
        print(" Trivy NSWG count", np.array(NSWG).astype(float).sum() )
        print(" Trivy total count = ", count)

        GHSA = []
        CVE = []
        ALAS = []
        DLA = []
        DSA = []
        NSWG = []
        ELSA = []
        count = 0
        # image_name,vuln_id,severity,count,related_vuln
        for indx, j, i, v, s, c, r in self.G_73.itertuples():
            if 'GHSA' in v:
                GHSA.append(c)
                count = count + float(c)
            elif 'CVE' in v:
                CVE.append(c)
                count = count + float(c)
            elif 'ALAS' in v:
                ALAS.append(c)
                count = count + float(c)
            elif 'DLA' in v:
                DLA.append(c)
                count = count + float(c)
            elif 'DSA' in v:
                DSA.append(c)
                count = count + float(c)
            elif 'NSWG' in v:
                NSWG.append(c)
                count = count + float(c)
            elif 'ELSA' in v:
                ELSA.append(c)
                count = count + float(c)
            elif 'NA' in v:
                pass
            else:
                print(v)
        print(" Grype GHSA count", np.array(GHSA).astype(float).sum()  )
        print(" Grype CVE count", np.array(CVE).astype(float).sum() )
        print(" Grype ALAS count", np.array(ALAS).astype(float).sum() )
        print(" Grype DLA count", np.array(DLA).astype(float).sum() )
        print(" Grype DSA count", np.array(DSA).astype(float).sum() )
        print(" Grype NSWG count", np.array(NSWG).astype(float).sum() )
        print(" Grype ELSA count", np.array(ELSA).astype(float).sum())
        print(" Grype total count = ", count)

        GHSA = []
        CVE = []
        ALAS = []
        DLA = []
        DSA = []
        NSWG = []
        ELSA = []
        count = 0
        # image_name,vuln_id,severity,count,related_vuln
        for indx, j, i, v, s, c, r in self.G_CPE.itertuples():
            if 'GHSA' in v:
                GHSA.append(c)
                count = count + float(c)
            elif 'CVE' in v:
                CVE.append(c)
                count = count + float(c)
            elif 'ALAS' in v:
                ALAS.append(c)
                count = count + float(c)
            elif 'DLA' in v:
                DLA.append(c)
                count = count + float(c)
            elif 'DSA' in v:
                DSA.append(c)
                count = count + float(c)
            elif 'NSWG' in v:
                NSWG.append(c)
                count = count + float(c)
            elif 'ELSA' in v:
                ELSA.append(c)
                count = count + float(c)
            elif 'NA' in v:
                pass
            else:
                print(v)
        print(" Grype CPE GHSA count", np.array(GHSA).astype(float).sum())
        print(" Grype CPE CVE count", np.array(CVE).astype(float).sum() )
        print(" Grype CPE ALAS count", np.array(ALAS).astype(float).sum() )
        print(" Grype CPE DLA count", np.array(DLA).astype(float).sum() )
        print(" Grype CPE DSA count", np.array(DSA).astype(float).sum() )
        print(" Grype CPE NSWG count", np.array(NSWG).astype(float).sum())
        print(" Grype CPE ELSA count", np.array(ELSA).astype(float).sum() )
        print(" Grype CPE total count = ", count)

    def severity_difference(self):
        """Prints the number of times Grype and Trivy disagreed on the severity of the same vulnerability found in the same image"""

        t_49 = distribution(self.T_49)  # getting a list of images

        sum = 0
        for i in t_49['image_name']:
            # get results for just one image at a time
            filtered_G_73 = self.G_73[self.G_73['image_name'] == i]
            filtered_T_49 = self.T_49[self.T_49['image_name'] == i]

            # Get the set of unique vuln_id values in each filtered dataframe
            vuln_ids_G_73 = set(filtered_G_73['vuln_id'])
            vuln_ids_T_49 = set(filtered_T_49['vuln_id'])

            # gets list of common vulnerabilities reported by each tool
            common_vuln_ids = vuln_ids_G_73.intersection(vuln_ids_T_49)

            for vuln_id in common_vuln_ids:
                # Filtered rows for the current vulnerability in G_73 and T_49
                row_G_73 = filtered_G_73[filtered_G_73['vuln_id'] == vuln_id]
                row_T_49 = filtered_T_49[filtered_T_49['vuln_id'] == vuln_id]

                # Get severity values
                severity_G_73 = row_G_73['severity'].iloc[0].lower()
                severity_T_49 = row_T_49['severity'].iloc[0].lower()

                # Check if severities agree
                if severity_G_73 == severity_T_49:
                    pass
                elif severity_G_73 == 'negligible':
                    sum = sum + 1
                    # print(
                    #   f"G vs T severity for vulnerability {vuln_id}: G_73 - {severity_G_73}, T_49 - {severity_T_49}")
                else:
                    sum = sum + 1
                    # print(f"Disagreed severity for vulnerability {vuln_id}: G_73 - {severity_G_73}, T_49 - {severity_T_49}")

        print("Grype and Trivy disagreed on severity: ", sum, " number of times")

    def Average_Agreeance(self):

        t_49 = distribution(self.T_49)

        average_num_agreed = []
        average_num_trivy = []
        average_num_grype = []
        count_oh_shit = 0
        for i in t_49['image_name']:

            filtered_G_73 = self.G_73[self.G_73['image_name'] == i]
            filtered_T_49 = self.T_49[self.T_49['image_name'] == i]

            # Get the set of unique vuln_id values in each filtered dataframe
            vuln_ids_G_73 = set(filtered_G_73['vuln_id'])
            vuln_ids_T_49 = set(filtered_T_49['vuln_id'])

            if len(vuln_ids_T_49) == len(vuln_ids_G_73):
                pass
                # print(i, vuln_ids_T_49, vuln_ids_G_73)

            common_vuln_ids = vuln_ids_G_73.intersection(vuln_ids_T_49)
            if len(common_vuln_ids) == len(vuln_ids_T_49) and len(common_vuln_ids) == len(vuln_ids_G_73):
                count_oh_shit = count_oh_shit + 1
            count_common_vuln_ids = len(common_vuln_ids)
            average_num_agreed.append(count_common_vuln_ids)
            average_num_grype.append((len(vuln_ids_G_73)))
            average_num_trivy.append((len(vuln_ids_T_49)))
        agreed = np.array(average_num_agreed)
        gr = np.array(average_num_grype)
        tr = np.array(average_num_trivy)
        print("average agreed: ", np.average(agreed), "std: ", agreed.std())
        print("average grype: ", np.average(gr), "std: ", gr.std())
        print("average trivy: ", np.average(tr), "std: ", tr.std())
        print(count_oh_shit)

    def get_data_difference(self):
        # gets the total vulnerabilities in each image.
        g_73 = distribution(self.G_73)
        t_49 = distribution(self.T_49)

        # Create easy to use dataframe for differences
        data = {
            'Image_Name': g_73['image_name'],
            'Diff': g_73['count'].subtract(t_49['count'])
        }
        df_difference = pd.DataFrame(data)

        # --------------------------------------------------------------------------------------------------------------
        # apache-strut vuln
        a = self.T_49[self.T_49['vuln_id'] == 'CVE-2017-9805']
        b = self.G_73[self.G_73['vuln_id'] == "CVE-2017-9805"]
        print("apache-strut vulnerability count in our corpus of Docker image found by Trivy: ", a)
        print("apache-strut vulnerability count in our corpus of Docker image found by Grype: ", b, "\n")

        # --------------------------------------------------------------------------------------------------------------
        # log4j
        c = self.T_49[self.T_49['vuln_id'] == 'CVE-2021-44228']
        d = self.G_73[self.G_73['vuln_id'] == "CVE-2021-44228"]
        d_g = self.G_73[self.G_73['vuln_id'] == "GHSA-jfh8-c2jp-5v3q"]
        c_t = self.T_49[self.T_49['vuln_id'] == "GHSA-jfh8-c2jp-5v3q"]
        print("Log4j CVE vulnerability count in our corpus of Docker image found by Trivy: ", c)
        print("Log4j CVE vulnerability count in our corpus of Docker image found by Grype: ", d)
        print("Log4j GHSA vulnerability count in our corpus of Docker image found by Trivy: ", d_g)
        print("Log4j GHSA vulnerability count in our corpus of Docker image found by Grype: ", c_t, "\n")

        # --------------------------------------------------------------------------------------------------------------
        # shell shock
        e = self.T_49[self.T_49['vuln_id'] == 'CVE-2014-6271']
        f = self.G_73[self.G_73['vuln_id'] == "CVE-2014-6271"]
        print("shell shock vulnerability count in our corpus of Docker image found by Trivy: ", e)
        print("shell shock vulnerability count in our corpus of Docker image found by Grype: ", f, "\n")

        # --------------------------------------------------------------------------------------------------------------
        # Calculate average count for Grype
        avg_difference = np.mean(g_73['count'])
        std_dev_difference = np.std(g_73['count'])
        total_vuln_g = np.sum(g_73['count'])

        print("On average, the count of vulnerabilities reported by G_73 was {:.2f} ".format(avg_difference))
        print("Standard deviation :", std_dev_difference, "\n")

        # --------------------------------------------------------------------------------------------------------------
        # Calculate average count for Trivy
        avg_difference = np.mean(t_49['count'])
        std_dev_difference = np.std(t_49['count'])
        total_vuln_t = np.sum(t_49['count'])

        print("On average, the count of vulnerabilities reported by t_49 was {:.2f} ".format(avg_difference))
        print("Standard deviation of ", std_dev_difference, "\n")

        # --------------------------------------------------------------------------------------------------------------
        # Calculate average difference
        avg_difference = np.mean(df_difference['Diff'])
        std_dev_difference = np.std(df_difference['Diff'])

        print("On average, the count of vulnerabilities reported by G_73 was {:.2f} higher than T_49.".format(avg_difference))
        print("Standard deviation of the difference:", std_dev_difference, "\n")

        # --------------------------------------------------------------------------------------------------------------
        # Count the number of images where both t_49 and g_73 found counts of 0
        num_images_both_tools_count_zero = (df_difference[(t_49['count'] == 0) & (g_73['count'] == 0)])
        print("Number of images where both tools found zero vulnerabilities:", num_images_both_tools_count_zero, "\n")

        # --------------------------------------------------------------------------------------------------------------
        # Count the number of images where t_49 found counts of 0
        num_images_t_49_count_zero = len(t_49[t_49['count'] == 0])
        # Count the number of images where g_73 found counts of 0
        num_images_b_73_count_zero = len(g_73[g_73['count'] == 0])

        print("Number of images with count 0 in t_49:", num_images_t_49_count_zero)
        print("Number of images with count 0 in g_73:", num_images_b_73_count_zero, "\n")

        ahh = t_49[t_49['count'] == 0]
        bahh = g_73[g_73['count'] == 0]
        common_image_names = pd.merge(ahh, bahh, on='image_name')

        print("overlapping zeros: ", len(common_image_names))
        # --------------------------------------------------------------------------------------------------------------
        # Filter rows where the absolute difference in counts is greater than 500
        diff_greater_than_2000 = df_difference[abs(df_difference['Diff']) > 500]
        num_images_diff_greater_than_2000 = len(diff_greater_than_2000)
        print("Number of images with a difference count greater than 500:", num_images_diff_greater_than_2000 / 927, "\n")

        # --------------------------------------------------------------------------------------------------------------
        # Filter rows where the absolute difference in counts is greater than 100
        diff_greater_than_100 = df_difference[abs(df_difference['Diff']) > 100]
        num_images_diff_greater_than_100 = len(diff_greater_than_100)
        print("Number of images with a difference count greater than 100:", num_images_diff_greater_than_100 / 927, "\n")

        # --------------------------------------------------------------------------------------------------------------
        # Filter rows where the absolute difference in counts is 0
        diff_greater_than_0 = df_difference[abs(df_difference['Diff']) == 0]
        num_images_diff_greater_than_0 = len(diff_greater_than_0)
        print("Number of images with a difference count at 0:", num_images_diff_greater_than_0, "\n")

        # --------------------------------------------------------------------------------------------------------------
        # Find the row with the maximum difference in counts
        trivy = g_73.loc[df_difference['Diff'].idxmax(), 'count']
        grype = t_49.loc[df_difference['Diff'].idxmax(), 'count']
        max_diff_row = df_difference.loc[df_difference['Diff'].idxmax()]

        print("Image Name with Max difference in counts:", max_diff_row['Image_Name'])
        print("Difference in Counts:", max_diff_row['Diff'], " Grype: ", grype, " Trivy: ", trivy,"\n" )
        # --------------------------------------------------------------------------------------------------------------

        # Filter rows where both Grype and Trivy have counts not equal to 0
        filtered_df = df_difference[(g_73['count'] != 0) & (t_49['count'] != 0)]
        num_agreed = len(filtered_df[g_73['count'] == t_49['count']])

        f_t = t_49[(t_49['count'] != 0)]
        f_g = g_73[(g_73['count'] != 0)]
        # Find the row with the maximum difference in counts
        max_diff_row = filtered_df.loc[filtered_df['Diff'].idxmax()]

        print("Image with the maximum difference where counts are not 0:")
        trivy = f_t.loc[filtered_df['Diff'].idxmax(), 'count']
        grype = f_g.loc[filtered_df['Diff'].idxmax(), 'count']
        print("Image Name:", max_diff_row['Image_Name'])
        print("Difference in Counts:", max_diff_row['Diff'], " Grype: ", grype, " Trivy: ", trivy, '\n')

        # max counts of Grype and Trivy difference
        min_diff = min(g_73['count'].subtract(t_49['count']))
        max_diff = max(g_73['count'].subtract(t_49['count']))

        # largest difference in counts
        max_diff_index = df_difference['Diff'].idxmax()
        image_name_largest_diff = df_difference.loc[max_diff_index, 'Image_Name']
        trivy = t_49.loc[max_diff_index, 'count']
        grype = g_73.loc[max_diff_index, 'count']
        print("Image name with the largest difference in counts:", image_name_largest_diff, " Grype: ", grype,
              " Trivy: ",
              trivy, " diff: ", max_diff, '\n')

        # Define custom color palette
        custom_palette = {'Diff': (0.6, 0.8, 0.8)}
        df = pd.DataFrame(data)

        # Melt the DataFrame to create a long-form DataFrame
        df_melted = pd.melt(df, id_vars=['Image_Name'], var_name='Tool', value_name='Vulnerabilities')

        # Create violin plots for each tool
        plt.figure(figsize=(12, 14))
        ax = sns.violinplot(x='Tool', y='Vulnerabilities', data=df_melted, inner='quartile', palette=custom_palette,
                            cut=0)

        plt.xlabel('', fontsize='32')
        plt.ylabel('Grype - Trivy', fontsize='30')
        plt.xticks(fontsize=20)
        plt.yticks(fontsize=20)
        plt.xticks([])
        plt.ylim(min_diff - min_diff % 1000, max_diff + 1000 - (max_diff % 1000))
        # Set light gray background
        ax.set_facecolor('#E0E0E0')

        # Add horizontal lines for y ticks
        plt.gca().yaxis.grid(True)
        plt.gca().xaxis.grid(False)
        plt.gca().set_axisbelow(True)

        plt.show()

    def side_by_side_violin_plots(self):
        """ Side by Side violin plots for Grype and Trivy """
        b_73 = distribution(self.G_73).reset_index()
        t_49 = distribution(self.T_49).reset_index()
        t_max = max(t_49['count'])
        g_max = max(b_73['count'])

        # sanity check, we should have the same number of images for both tools.
        for i in range(0, len(b_73['image_name'])):
            if b_73.loc[i]['image_name'] != t_49.loc[i]['image_name']:
                print(b_73.loc[i]['image_name'], t_49.loc[i]['image_name'])

        data = {
            'Image_Name': b_73['image_name'],
            'Trivy v0.49.0': t_49['count'],
            'Grype v0.73.0': b_73['count'],
        }

        custom_palette = {'Trivy v0.49.0': (0.8, 0.95, 0.7), 'Grype v0.73.0': (0.5, 0.7, 0.95)}
        df = pd.DataFrame(data)

        df_melted = pd.melt(df, id_vars=['Image_Name'], var_name='Tool', value_name='Vulnerabilities')

        plt.figure(figsize=(12, 14))
        ax = sns.violinplot(x='Tool', y='Vulnerabilities', data=df_melted, inner='quartile', palette=custom_palette,
                            cut=0)

        plt.xlabel('Static Analysis Tool', fontsize='22')
        plt.ylabel('Vulnerabilities Per Image', fontsize='22')
        plt.xticks(fontsize=20)
        plt.yticks(fontsize=20)

        # Set light gray background
        ax.set_facecolor('#E0E0E0')

        # Add horizontal lines for y ticks
        plt.gca().yaxis.grid(True)
        plt.gca().xaxis.grid(False)
        plt.gca().set_axisbelow(True)

        plt.show()


def main():
    # a bunch of functions showing differences between tools.
    dd = Measuring_Differences()

    dd.label_counts()

    #dd.severity_difference()
    dd.Average_Agreeance()
    #dd.get_data_difference()
    #dd.side_by_side_violin_plots()


main()

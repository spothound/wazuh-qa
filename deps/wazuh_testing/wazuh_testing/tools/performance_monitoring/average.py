import argparse
import pandas as pd

"""
Script to display the average of all variables (columns) stored in a CSV file.
"""

if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-f', metavar=('<file_path>'), type=str, required=True, help='File path to read')

    script_parameters = arg_parser.parse_args()

    file = script_parameters.f

    df = pd.read_csv(file, sep=",")

    print(df.mean().astype(int))

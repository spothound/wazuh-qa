import argparse
import pandas as pd
import os

"""
Script to display the average of all variables (columns) stored in a CSV file.
"""

if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-f', metavar=('<file_path>'), type=str, required=True, help='File path to read')
    arg_parser.add_argument('-w', action='store_true', required=False, help='Write data to file')
    arg_parser.add_argument('-o', metavar=('<output_file_data_name>'),type=str, required=False,
                            help='Output file data name')

    script_parameters = arg_parser.parse_args()

    file = script_parameters.f
    output_file_name = script_parameters.o

    df = pd.read_csv(file, sep=",")

    mean = df.mean().astype(int)

    base_path = os.path.join(os.path.dirname(os.path.abspath(file)))

    if script_parameters.w:
        with open(f"{base_path}/{output_file_name}", 'w') as f:
            f.write(mean.to_string())
    else:
        print(mean)

import argparse
import pandas as pd
import os

"""
Script to display the average of all variables (columns) stored in a CSV file.
"""

if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-f', metavar=('<file_path>'), type=str, required=True, help='File path to read')
    arg_parser.add_argument('-t', metavar=('<threshold>'), required=False, type=int,
                            help='Lower limit from the data to be averaged', default=1000)
    arg_parser.add_argument('-w', action='store_true', required=False, help='Write data to file')
    arg_parser.add_argument('-o', metavar=('<output_file_data_name>'),type=str, required=False,
                            help='Output file data name')

    script_parameters = arg_parser.parse_args()

    cwd = os.getcwd()

    file = os.path.join(cwd, script_parameters.f)
    lower_limit = script_parameters.t

    output_file_name = script_parameters.o

    df = pd.read_csv(file, sep=",")
    df.columns = df.columns.str.strip()

    # Eliminates rows that do not exceed the established limit.
    if 'events_edps' in df.columns:
        df = df[df.events_edps > lower_limit]

    mean = df.mean().astype(int)

    base_path = os.path.join(os.path.dirname(os.path.abspath(file)))

    if script_parameters.w:
        with open(f"{base_path}/{output_file_name}", 'w') as f:
            f.write(mean.to_string())
    else:
        print(mean)

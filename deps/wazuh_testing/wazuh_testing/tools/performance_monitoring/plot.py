
import argparse
import matplotlib.pyplot as plt
import pandas as pd

from datetime import datetime


DEFAULT_FILE_NAME = 'manager_eps_history.png'

def plot(data, output_file):

    df = pd.read_csv(data, sep=",")
    df.columns = df.columns.str.strip()

    timestamp_format = '%Y-%m-%d %H:%M:%S.%f'
    tstamp1 = datetime.strptime(df['timestamp'][0], timestamp_format)
    tstamp2 = datetime.strptime(df['timestamp'][1], timestamp_format)

    time_difference = tstamp2 - tstamp1
    seconds_interval = int(round(time_difference.total_seconds()))

    df2 = pd.DataFrame({'timestamp': list(range(0, len(df['timestamp'])*seconds_interval, seconds_interval))})

    new_df = pd.concat([df2, df[['events_edps']]], axis=1)

    new_df.plot('timestamp', linewidth = 1, color = 'blue', title='Events per second processed by the manager')

    plt.ylabel('EPS')
    plt.xlabel('Time(s)')
    plt.legend()
    plt.grid()
    plt.savefig(output_file)


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-f', metavar=('<file_path>'), type=str, required=True, help='File path to read')
    arg_parser.add_argument('-o', metavar=('<output_file_data_name>'),type=str, required=False,
                            default=DEFAULT_FILE_NAME, help='Output file name')

    script_parameters = arg_parser.parse_args()

    data_file = script_parameters.f
    output_file = script_parameters.o

    plot(data_file, output_file)

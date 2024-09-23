import json
import pandas as pd
import argparse
from tqdm import tqdm

def getTrunatedDF(df, truncate_size = 500):
    if "Unnamed: 0" in df:
        df.drop(columns= ["Unnamed: 0"], inplace= True) 
    mini_dfs = []

    for flow_id, mini_df in df.groupby(by= "FlowId"):
        mini_df.Timestamp = pd.to_datetime(mini_df.Timestamp, format = "mixed")
        mini_df = mini_df.sort_values(by= "Timestamp")
        if len(mini_df) > truncate_size:
            mini_df = mini_df.iloc[:truncate_size]
        mini_dfs.append(mini_df)

    return pd.concat(mini_dfs,axis= 0).reindex()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('input_json_path', type= str)
    parser.add_argument('output_csv_path', type= str)
    parser.add_argument('truncate_length', type= int)

    args = parser.parse_args()
    input_json_path, output_csv_path = args.input_json_path, args.output_csv_path

    data = []
    with open(input_json_path, "r") as f:
        for line in tqdm(f):
            data.append(json.loads(line))


    df = pd.DataFrame(data= data)
    df = getTrunatedDF(df= df, truncate_size= args.truncate_length)
    df.to_csv(output_csv_path, index= False)
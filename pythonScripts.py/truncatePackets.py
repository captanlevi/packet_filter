import json
import pandas as pd
import numpy as np
from tqdm import tqdm
import matplotlib.pyplot as plt


def getConcatDF(csv_path, truncate_size = 500):
    df = pd.read_csv(csv_path)
    df.drop(columns= ["Unnamed: 0"], inplace= True) 
    mini_dfs = []

    for flow_id, mini_df in df.groupby(by= "FlowId"):
        mini_df.Timestamp = pd.to_datetime(mini_df.Timestamp, format = "mixed")
        mini_df = mini_df.sort_values(by= "Timestamp")
        if len(mini_df) > truncate_size:
            mini_df = mini_df.iloc[:truncate_size]
        mini_dfs.append(mini_df)
    
    pd.concat(mini_dfs,axis= 0).to_csv("truncated_final.csv", index= False)












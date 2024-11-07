import os
import pandas as pd
import json

types = ["Video", "Social Media", "Software Update", "Download", "File Storage", "Conferencing", "Mail"]
types = list(map(lambda x : x.strip().lower(), types))


def getFilteredDf(csv_path):
    df = pd.read_csv(csv_path)
    df = df[df['type'].notna()]
    df = df[df['provider'].notna()]
    df.provider = df.provider.apply(lambda x : x.strip().lower())
    df.type = df.type.apply(lambda x : x.strip().lower())
    return df


def getCounts(df,application_type, K = 20):
    dct =  df[df.type == application_type].provider.value_counts().to_dict()
    top_k =  sorted(dct, key= lambda x : dct[x], reverse= True)[:K]
    return {provider : dct[provider] for provider in top_k}

def mergeValueCountDicts(dct1 : dict,dct2 : dict):
    keys = list(set(list(dct1.keys()) + list(dct2.keys())))
    merged_dict = dict()
    for key in keys:
        merged_dict[key] = dct1.get(key,0) + dct2.get(key, 0)
    return merged_dict


def mergeDfDicts(dct1, dct2):
    keys = set(list(dct1.keys()) + list(dct2.keys()))
    merged_dict = dict()

    for key in keys:
        print(key)
        merged_dict[key] = mergeValueCountDicts(dct1.get(key,dict()), dct2.get(key, dict()))
    return merged_dict


def getDictForCSV(csv_path):
    df = getFilteredDf(csv_path= csv_path)
    df_dct = dict()
    for tp in types:
        df_dct[tp] = getCounts(df,tp)
    return df_dct




if __name__ == "__main__":


    csv_dir_path = "../../data/ground_truth_labels"
    csv_paths = []
    for csv in os.listdir(csv_dir_path):
        if csv.endswith(".csv"):
            csv_paths.append(os.path.join(csv_dir_path, csv))

    master_dct = dict()

    for csv_path in csv_paths:
        master_dct = mergeDfDicts(getDictForCSV(csv_path= csv_path), master_dct)


    write_path = os.path.join(csv_dir_path, "counts.json")

    with open(write_path, "w") as f:
        json.dump(master_dct,f,indent=4)



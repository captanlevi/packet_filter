import os
import pandas as pd
import ipaddress

import os
import pandas as pd
import ipaddress
import json

def check_ip_type(ip):
    try:
        # Create an IP address object
        ip_obj = ipaddress.ip_address(ip)
        
        # Check if it's a private IP
        if ip_obj.is_private:
            return "Private"
        else:
            return "Public"
    except ValueError:
        return "Invalid IP address"

def getIpsForType(csv_path,types = ["Conferencing"], top_N = 10):
    ground_df = pd.read_csv(csv_path)
    classifiers = []

    with open("../GroundTruthFilters/trustedClassifiers.txt", "r") as f:
        for line in f:
            classifiers.append(line.strip().replace("\n", ""))

    ground_df  = ground_df[ground_df.classifier.isin(classifiers)]
    ground_df = ground_df[ground_df.type.isin(types)]


    provider_ip_counts  = ground_df.groupby(["provider", "server_ip"]).size().reset_index(name= "count")

    ips = set()
    provider_to_ips = dict()
    for provider, mini_df in provider_ip_counts.groupby("provider"):
        mini_df.sort_values(by= "count", ascending= False, inplace= True)
        top_ips = mini_df.iloc[:top_N]["server_ip"].values.tolist()
        provider_to_ips[provider] = top_ips
        ips.update(top_ips)
    
    return list(ips),provider_to_ips


def mergeDict(dct,master):
    for key,values in dct.items():
        if key in master:
            master[key].extend(values)
        else:
            master[key] = values
        master[key] = list(set(master[key]))
    return master


def saveDct(dct,file_path):
    with open(file_path, 'w') as f:
        f.write(json.dumps(dct))


if __name__ == "__main__":

    ips = []
    provider_to_ips = dict()
    ground_truth_dir = "../../data/ground_truth_labels"
    out_path = "../../data/conf_ips.txt"
    out_provider_to_ips = "../../data/conf_prov_to_ips.json"

    for csv in os.listdir(path= ground_truth_dir):
        if csv.endswith(".csv") == False:
            continue
        csv_path = os.path.join(ground_truth_dir,csv)
        
        _ips,_provider_to_ips = getIpsForType(csv_path= csv_path)
        provider_to_ips = mergeDict(dct= _provider_to_ips,master= provider_to_ips)
        ips.extend(_ips)
        

    ips = list(set(ips))
    with open(out_path, "w") as f:
        f.write(",".join(ips))
    
    saveDct(dct=provider_to_ips,file_path= out_provider_to_ips)
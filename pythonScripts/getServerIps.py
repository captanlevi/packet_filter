import os
import pandas as pd
import ipaddress

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

def getIpsForType(csv_path,types = ["Conferencing"]):
    ground_df = pd.read_csv(csv_path)
    classifiers = []
    with open("GroundTruthFilters/trustedClassifiers.txt", "r") as f:
        for line in f:
            classifiers.append(line.strip().replace("\n", ""))

    ground_df  = ground_df[ground_df.classifier.isin(classifiers)]
    ground_df = ground_df[ground_df.type.isin(types)]
    ips = ground_df.server_ip.unique().tolist() + ground_df.client_ip.unique().tolist()
    ips = set((filter(lambda x : check_ip_type(x) == "Public", ips)))
    ips = list(ips)
    return ips




if __name__ == "__main__":

    ips = []
    ground_truth_dir = "data/ground_truth_labels"
    out_path = "conf_ips.txt"

    for csv in os.listdir(path= ground_truth_dir):
        if csv.endswith(".csv") == False:
            continue
        csv_path = os.path.join(ground_truth_dir,csv)
        ips.extend(getIpsForType(csv_path= csv_path))


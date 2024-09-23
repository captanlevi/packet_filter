import json
import pandas as pd

data = []
with open("../output_json", "r") as f:
    for line in f:
        data.append(json.loads(line))


df = pd.DataFrame(data= data)


df.to_csv("../final_flows.csv")
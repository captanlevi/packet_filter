import json
import pandas as pd
import argparse
from tqdm import tqdm
import dask.dataframe as dd

def getTrunatedDF(input_csv_path,output_csv_path,truncate_size = 500):

    ddf = dd.read_csv(input_csv_path)

    print(ddf.head())
    ddf['Timestamp'] = dd.to_datetime(ddf['Timestamp'], format="mixed")

    truncated_ddf = ddf.groupby('FlowId').apply(
        lambda df: df.nsmallest(truncate_size, 'Timestamp'), meta=ddf
    )
    truncated_ddf.compute().to_csv(output_csv_path, index=False)



def json_to_csv(input_json_path, output_csv_path, chunk_size=100000):

    def processDfTypes(df : pd.DataFrame):
        df.loc[:,"Timestamp"] = pd.to_datetime(df.Timestamp)
        df = df.astype({"FlowId" : "int32", "Length" : "int64"})
        df["Direction"] = df['Direction'].astype(bool)
        df["Type"] = df['Type'].astype(str)


        return df


    with open(input_json_path, "r") as f:
        # Create a CSV file and write headers on the first iteration
        first_chunk = True
        chunk_data = []

        for line in tqdm(f):
            # Load the JSON line into a dictionary
            chunk_data.append(json.loads(line))
            
            # When the chunk reaches the defined chunk_size, write it to CSV
            if len(chunk_data) >= chunk_size:
                df = pd.DataFrame(chunk_data)
                
                # Write the DataFrame to CSV, append after the first chunk
                df.to_csv(output_csv_path, mode='a', index=False, header=first_chunk)

                # After the first write, avoid writing the header again
                first_chunk = False
                
                # Clear the chunk data
                chunk_data = []

        # Write any remaining data after the loop ends
        if chunk_data:
            df = pd.DataFrame(chunk_data)
            df = processDfTypes(df)           
            df.to_csv(output_csv_path, mode='a', index=False, header=first_chunk)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('input_json_path', type= str)
    parser.add_argument('temp_csv_path', type= str)
    parser.add_argument('output_csv_path', type= str)
    parser.add_argument('truncate_length', type= int)

    args = parser.parse_args()
    input_json_path, temp_csv_path ,output_csv_path = args.input_json_path, args.temp_csv_path ,args.output_csv_path

    json_to_csv(input_json_path= input_json_path, output_csv_path= temp_csv_path)
    getTrunatedDF(input_csv_path= temp_csv_path,output_csv_path= output_csv_path ,truncate_size= args.truncate_length)
source_pcap_file_path = "data/small_pcap_file.pcap"
source_ground_truth_csv_path = "data/ground_truth1.csv"
matching_output_path = "data/output_json"
intermidiate_csv_output_path = "data/temp.csv"
csv_output_path = "data/final_flows.csv"
truncate_length = 500


build:
	go build -o bin/main main.go

run:
	go run main.go $(source_ground_truth_csv_path) $(source_pcap_file_path) $(matching_output_path)
	

convertJSONToCSV:
	python3 pythonScripts/json_to_csv.py $(matching_output_path) $(intermidiate_csv_output_path) $(csv_output_path)  $(truncate_length)
	rm $(matching_output_path)
	rm $(intermidiate_csv_output_path)

all: build run convertJSONToCSV
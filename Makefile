source_pcap_file_path = "data/small_pcap_file.pcap"
source_ground_truth_csv_path = "data/ground_truth.csv"
matching_output_path = "data/output_json"
csv_output_path = "data/final_flows.csv"
truncate_length = 500


build:
	go build -o bin/main main.go

run:
	go run main.go $(source_ground_truth_csv_path) $(source_pcap_file_path) $(matching_output_path)
	

convertJSONToCSV:
	python3 pythonScripts.py/json_to_csv.py $(matching_output_path) $(csv_output_path) $(truncate_length)
	rm $(matching_output_path)

all: build run convertJSONToCSV
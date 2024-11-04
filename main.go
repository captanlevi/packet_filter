package main

import (
	"fmt"
	"os"
	"packet_matching/core"
	"time"
)

func main() {

	num_args, args := len(os.Args), os.Args
	if num_args < 4 {
		panic("Please use code with the input ground_truth.csv, source.pcap and output paths")
	}

	ground_truth_path, pacp_file_path, output_path := args[1], args[2], args[3]
	ground_truth_csvs, err := core.GetCSVFilesFromDirectory(ground_truth_path)
	if err != nil {
		panic("error reading csv files")
	}
	fmt.Println(ground_truth_csvs)
	var mn_timestamp, mx_timestamp time.Time
	mn_timestamp = time.Date(2023, time.January, 1, 0, 0, 0, 0, time.UTC)
	mx_timestamp = time.Now().UTC()
	if len(ground_truth_csvs) > 1 {
		// In case we have more than one csv, we need to filter the recodrs according to time
		mn_timestamp, mx_timestamp = core.GetStartAndEndTimestampsFromPcap(pacp_file_path)
	}

	fmt.Println("min max timestamps = ", mn_timestamp, mx_timestamp)
	flow_map := core.GetFlowTupleToFlowInfo(ground_truth_csvs, mn_timestamp, mx_timestamp)
	fmt.Println(len(flow_map))
	core.MatchPcaps(pacp_file_path, output_path, flow_map)
}

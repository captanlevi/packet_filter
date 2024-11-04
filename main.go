package main

import (
	"fmt"
	"os"
	"packet_matching/core"
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
	mn_timestamp, mx_timestamp := core.GetStartAndEndTimestampsFromPcap(pacp_file_path)

	//mn_timestamp, _ := time.Parse("2006-01-02 15:04:05.000000 -0700 MST", "2024-09-18 08:02:52.138703 +0000 UTC")
	//mx_timestamp, _ := time.Parse("2006-01-02 15:04:05.000000 -0700 MST", "2024-09-20 06:52:26.436679 +0000 UTC")
	fmt.Println("min max timestamps = ", mn_timestamp, mx_timestamp)
	flow_map := core.GetFlowTupleToFlowInfo(ground_truth_csvs, mn_timestamp, mx_timestamp)
	fmt.Println(len(flow_map))
	core.MatchPcaps(pacp_file_path, output_path, flow_map)
}

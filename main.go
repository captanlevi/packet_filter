package main

import (
	"os"
	"packet_matching/core"
)

func main() {
	/*
		csvPath := "ground_truth.csv"
		inputPcapFile := "small_pcap_file.pcap"
		outputPcapFile := "filtered_packets.pcap"
		core.FilterPcaps(csvPath, inputPcapFile, outputPcapFile)
	*/

	num_args, args := len(os.Args), os.Args
	if num_args < 4 {
		panic("Please use code with the input ground_truth.csv, source.pcap and output paths")
	}

	ground_truth_path, pacp_file_path, output_path := args[1], args[2], args[3]
	flow_map := core.GetFlowTupleToFlowInfo(ground_truth_path)
	core.MatchPcaps(pacp_file_path, output_path, flow_map)

}

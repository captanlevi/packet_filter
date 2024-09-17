package main

import (
	"packet_matching/core"
)

func main() {
	/*
		csvPath := "ground_truth.csv"
		inputPcapFile := "small_pcap_file.pcap"
		outputPcapFile := "filtered_packets.pcap"
		core.FilterPcaps(csvPath, inputPcapFile, outputPcapFile)
	*/
	flow_map := core.GetFlowTupleToFlowInfo("ground_truth.csv")
	core.MatchPcaps("small_pcap_file.pcap", "output_json.json", flow_map)

}

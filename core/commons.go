package core

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Tuple struct {
	ClientIP   string
	ServerIP   string
	ClientPort uint16
	ServerPort uint16
	Protocol   uint8
}

type FlowInfo struct {
	Type      string
	StartTime time.Time
	EndTime   time.Time
	Duration  float64
	FlowId    int
	Provider  string
}

type PacketInfo struct {
	FlowId    int
	Timestamp string
	Length    int
	Type      string
	Provider  string
	Direction bool
	ServerIP  string
}

func GetStartAndEndTimestampsFromPcap(pcap_file string) (time.Time, time.Time) {
	fmt.Println("starting timestamp iteration")
	handle, err := pcap.OpenOffline(pcap_file)
	if err != nil {
		log.Fatal("Failed to open PCAP file:", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	var mn_timestamp, mx_timestamp time.Time

	first := true
	count := 0
	for packet := range packetSource.Packets() {
		timestamp := packet.Metadata().Timestamp.UTC()
		count++
		if first {
			mn_timestamp = timestamp
			mx_timestamp = timestamp
			first = false
		}

		if timestamp.Before(mn_timestamp) {
			mn_timestamp = timestamp
		}
		if timestamp.After(mx_timestamp) {
			mx_timestamp = timestamp
		}

		if count%1000000 == 0 {
			count = 0
			fmt.Println("Processed 1000000 packets")
		}

	}
	fmt.Println("Ending timestamp iteration")
	return mn_timestamp, mx_timestamp

}

func ReadMapFromFile(file_path string) map[string]struct{} {
	file, err := os.Open(file_path)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return nil
	}
	defer file.Close() // Ensure the file is closed after reading

	scanner := bufio.NewScanner(file)
	mp := make(map[string]struct{})

	// Iterate over each line
	for scanner.Scan() {
		line := scanner.Text() // Get the current line as a string
		mp[line] = struct{}{}
	}
	return mp
}

func GetFilteredCSVRecordsWithinTime(csv_path string, mn_timestamp time.Time, mx_timestamp time.Time) [][]string {
	/*
		All times are in UTC.Please remember
	*/
	file, err := os.Open(csv_path)
	if err != nil {
		log.Fatal("Failed to open CSV file:", err)
	}
	defer file.Close()

	discarded_records := 0

	reliableClassifiers := ReadMapFromFile("GroundTruthFilters/trustedClassifiers.txt")
	requiredTypes := ReadMapFromFile("GroundTruthFilters/typesToMine.txt")

	// Create a set of tuples
	filtered_records := make([][]string, 0)
	reader := csv.NewReader(file)

	// Skip the header line
	if _, err := reader.Read(); err != nil {
		log.Fatal("Failed to read CSV first line:", err)
	}
	for {
		row, err := reader.Read()
		if err != nil {
			// Check for the end of file
			if err.Error() == "EOF" {
				break
			}
			log.Fatal("Failed to read CSV line:", err)
		}

		// now filtering
		if _, ok := requiredTypes[row[9]]; !ok {
			continue
		}
		if _, ok := reliableClassifiers[row[10]]; !ok {
			continue
		}

		// filtering on time
		start_time, err_s := time.Parse(TimeLayout, row[0])

		if err_s != nil {
			panic("time conversion error")
		}

		if start_time.Before(mn_timestamp) || start_time.After(mx_timestamp) {
			discarded_records++
			continue
		}

		filtered_records = append(filtered_records, row)

	}

	fmt.Println(csv_path, "discarded records (time wise) = ", discarded_records)
	return filtered_records
}

func GetFilteredCSVRecords(csvPath string) [][]string {
	file, err := os.Open(csvPath)
	if err != nil {
		log.Fatal("Failed to open CSV file:", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		log.Fatal("Failed to read CSV file:", err)
	}

	// Define required types and classifiers

	/*
		requiredTypes := map[string]struct{}{
			"Video": {}, "Social Media": {}, "Software Update": {},
			"Download": {}, "File Storage": {}, "Conferencing": {},
			"Music": {}, "Live Video": {}, "Mail": {},
		}

		reliableClassifiers := map[string]struct{}{
			"TPED.SNI.TLD": {}, "TPED.SNI.TLDR": {}, "TPE.N.A2P": {},
			"TPED.SNI.TLD.P.S2T": {}, "TPED.SNI.PGTLD.P": {},
			"TPED.SNI.EM": {}, "TPED.SNI.TLD.P": {}, "TPED.SNI.TLD.PT": {},
			"TPED.SNI.PGTLD.P.S2T": {}, "TPED.PT": {}, "TPED.SNI.TLDR.PT": {},
			"TPED.SNI.TLD.HURL": {},
		}
	*/

	reliableClassifiers := ReadMapFromFile("GroundTruthFilters/trustedClassifiers.txt")
	requiredTypes := ReadMapFromFile("GroundTruthFilters/typesToMine.txt")

	// Create a set of tuples
	filtered_records := make([][]string, 0)

	for _, row := range records[1:] {

		if _, ok := requiredTypes[row[9]]; !ok {
			continue
		}
		if _, ok := reliableClassifiers[row[10]]; !ok {
			continue
		}

		filtered_records = append(filtered_records, row)
	}

	return filtered_records
}

func GetTupleFromPacket(packet gopacket.Packet) (Tuple, bool) {
	var clientIP, serverIP string

	// Check for IPv4 layer
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer != nil {
		ipv4, _ := ipv4Layer.(*layers.IPv4)
		clientIP = ipv4.SrcIP.String()
		serverIP = ipv4.DstIP.String()
	} else {
		// Check for IPv6 layer
		ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
		if ipv6Layer != nil {
			ipv6, _ := ipv6Layer.(*layers.IPv6)
			clientIP = ipv6.SrcIP.String()
			serverIP = ipv6.DstIP.String()
		} else {
			// Neither IPv4 nor IPv6 present, return false
			return Tuple{}, false
		}
	}

	// Extract TCP/UDP information
	var srcPort, dstPort uint16
	var protocol uint8
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		protocol = 6 // TCP
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
		protocol = 17 // UDP
	} else {
		return Tuple{}, false
	}

	// Construct tuple
	tp := Tuple{
		ClientIP:   clientIP,
		ServerIP:   serverIP,
		ClientPort: srcPort,
		ServerPort: dstPort,
		Protocol:   protocol,
	}
	return tp, true
}

func WritePacketInfoBufferToDisk(filepath string, buffer []PacketInfo) error {
	// Open the file in append mode, create it if it doesn't exist
	file, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// Encode the buffer as JSON and append to the file
	encoder := json.NewEncoder(file)
	for _, pkt := range buffer {
		err = encoder.Encode(pkt)
		if err != nil {
			return err
		}
	}

	fmt.Printf("Appended %d packets to %s\n", len(buffer), filepath)
	return nil
}

func GetCSVFilesFromDirectory(dir string) ([]string, error) {
	var csvFiles []string

	// Walk through the directory and find CSV files
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Check if the file has a .csv extension
		if !info.IsDir() && filepath.Ext(path) == ".csv" {
			csvFiles = append(csvFiles, path)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return csvFiles, nil
}

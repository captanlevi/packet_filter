package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type Tuple struct {
	ClientIP   string
	ServerIP   string
	ClientPort uint16
	ServerPort uint16
	Protocol   uint8
}

func get5TuplesFromCSV(csvPath string) map[Tuple]struct{} {
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

	// Create a set of tuples
	tuples := make(map[Tuple]struct{})
	for _, row := range records[1:] {

		if _, ok := requiredTypes[row[9]]; !ok {
			continue
		}
		if _, ok := reliableClassifiers[row[10]]; !ok {
			continue
		}

		clientPort, _ := strconv.ParseUint(row[5], 10, 16)
		serverPort, _ := strconv.ParseUint(row[6], 10, 16)
		protocol, _ := strconv.ParseUint(row[7], 10, 8)

		tuple := Tuple{
			ClientIP:   row[3],
			ServerIP:   row[4],
			ClientPort: uint16(clientPort),
			ServerPort: uint16(serverPort),
			Protocol:   uint8(protocol),
		}
		tuples[tuple] = struct{}{}
	}

	return tuples
}

func main() {
	csvPath := "ground_truth.csv"
	inputPcapFile := "small_pcap_file.pcap"
	outputPcapFile := "filtered_packets.pcap"
	bufferSize := 50000

	// Get tuples from CSV
	tuples := get5TuplesFromCSV(csvPath)

	fmt.Println(len(tuples))

	// Open the PCAP file for reading
	handle, err := pcap.OpenOffline(inputPcapFile)
	if err != nil {
		log.Fatal("Failed to open PCAP file:", err)
	}
	defer handle.Close()

	// Open the output PCAP file for writing
	outputFile, err := os.Create(outputPcapFile)
	if err != nil {
		log.Fatal("Failed to create output PCAP file:", err)
	}
	defer outputFile.Close()

	// Write the global header for the PCAP file
	w := pcapgo.NewWriter(outputFile)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet) // snapshot length and link type
	defer outputFile.Close()

	// Packet buffer
	buffer := make([]gopacket.Packet, 0, bufferSize)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)

		// Extract TCP/UDP information
		var srcPort, dstPort uint16
		var protocol uint8
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			srcPort = uint16(tcp.SrcPort)
			dstPort = uint16(tcp.DstPort)
			protocol = 6
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			srcPort = uint16(udp.SrcPort)
			dstPort = uint16(udp.DstPort)
			protocol = 11
		} else {
			continue
		}

		// Construct tuple
		tp := Tuple{
			ClientIP:   ip.SrcIP.String(),
			ServerIP:   ip.DstIP.String(),
			ClientPort: srcPort,
			ServerPort: dstPort,
			Protocol:   protocol,
		}
		revTp := Tuple{
			ClientIP:   ip.DstIP.String(),
			ServerIP:   ip.SrcIP.String(),
			ClientPort: dstPort,
			ServerPort: srcPort,
			Protocol:   protocol,
		}

		// Check if tuple or reverse tuple is in the set
		if _, exists := tuples[tp]; !exists {
			if _, revExists := tuples[revTp]; !revExists {
				continue
			}
		}

		// Add packet to the buffer
		buffer = append(buffer, packet)
		if len(buffer) >= bufferSize {
			for _, pkt := range buffer {
				w.WritePacket(pkt.Metadata().CaptureInfo, pkt.Data())
			}
			buffer = buffer[:0] // Clear the buffer
		}
	}

	// Write any remaining packets in the buffer
	for _, pkt := range buffer {
		w.WritePacket(pkt.Metadata().CaptureInfo, pkt.Data())
	}
}

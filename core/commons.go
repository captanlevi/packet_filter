package core

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
}

type PacketInfo struct {
	FlowId    int
	Timestamp time.Time
	Length    int
	Type      string
	Direction bool
}

var TimeLayout string = "2006-01-02 15:04:05.000000"

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
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return Tuple{}, false
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
		return Tuple{}, false
	}

	// Construct tuple
	tp := Tuple{
		ClientIP:   ip.SrcIP.String(),
		ServerIP:   ip.DstIP.String(),
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

package core

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func Get5TuplesFromCSV(csvPath string) map[Tuple]struct{} {
	records := GetFilteredCSVRecords(csvPath)
	tuples := make(map[Tuple]struct{})
	for _, row := range records {
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

func FilterPcaps(csvPath string, inputPcapFile string, outputPcapFile string) {
	//csvPath = "ground_truth.csv"
	//inputPcapFile = "small_pcap_file.pcap"
	//outputPcapFile = "filtered_packets.pcap"
	bufferSize := 50000

	// Get tuples from CSV
	tuples := Get5TuplesFromCSV(csvPath)

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

		// Construct tuple
		tp, validity := GetTupleFromPacket(packet)
		if !validity {
			continue
		}
		rev_tp := Tuple{ClientIP: tp.ServerIP, ServerIP: tp.ClientIP, ClientPort: tp.ServerPort, ServerPort: tp.ClientPort, Protocol: tp.Protocol}
		// Check if tuple or reverse tuple is in the set
		if _, exists := tuples[tp]; !exists {
			if _, revExists := tuples[rev_tp]; !revExists {
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

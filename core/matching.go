package core

import (
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func GetFlowTupleToFlowInfo(csv_path string) map[Tuple][]FlowInfo {
	records := GetFilteredCSVRecords(csv_path)
	tuple_map := make(map[Tuple][]FlowInfo)
	flow_id := 0
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

		start_time, err_s := time.Parse(TimeLayout, row[0])
		end_time, err_e := time.Parse(TimeLayout, row[1])
		flow_type := row[9]
		flow_duration, _ := strconv.ParseFloat(row[2], 64)

		flow_info := FlowInfo{StartTime: start_time, EndTime: end_time, Type: flow_type, Duration: flow_duration, FlowId: flow_id}
		if err_s != nil || err_e != nil {
			panic("time conversion error")
		}

		_, exists := tuple_map[tuple]
		if !exists {
			tuple_map[tuple] = make([]FlowInfo, 0)
		}
		tuple_map[tuple] = append(tuple_map[tuple], flow_info)
		flow_id += 1

	}
	return tuple_map
}

func MatchPcaps(input_pcap_file string, output_json_file string, flow_info_map map[Tuple][]FlowInfo) {
	count := 0
	buffer_size := 500
	fmt.Println(len(flow_info_map))
	handle, err := pcap.OpenOffline(input_pcap_file)
	if err != nil {
		log.Fatal("Failed to open PCAP file:", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	buffer := make([]PacketInfo, 0)
	for packet := range packetSource.Packets() {

		// converting time to UTC as the ground truth has UTC format
		timestamp := packet.Metadata().Timestamp.UTC()
		packet_length := packet.Metadata().CaptureLength

		tp, validity := GetTupleFromPacket(packet)
		if !validity {
			panic("invalid packet in filtered pcap")
		}
		rev_tp := Tuple{ClientIP: tp.ServerIP, ServerIP: tp.ClientIP, ClientPort: tp.ServerPort, ServerPort: tp.ClientPort, Protocol: tp.Protocol}
		var packet_info PacketInfo

		if flow_info_slice, exist := flow_info_map[tp]; exist {
			// flow_info_slice found
			timing_matched := false
			for _, flow_info := range flow_info_slice {
				// iterating over the flow infos to check the timestamp information
				if ((flow_info.StartTime == timestamp) || flow_info.StartTime.Before(timestamp)) && flow_info.EndTime.After(timestamp) {
					packet_info = PacketInfo{FlowId: flow_info.FlowId, Direction: true, Timestamp: timestamp, Length: packet_length, Type: flow_info.Type, ServerIP: tp.ServerIP}
					timing_matched = true
					break

				}
			}
			if !timing_matched {
				// if no timings match then skip this packet
				count++
				continue
			}

		} else if flow_info_slice, exist := flow_info_map[rev_tp]; exist {
			// rev tuple matched
			timing_matched := false
			for _, flow_info := range flow_info_slice {
				if ((flow_info.StartTime == timestamp) || flow_info.StartTime.Before(timestamp)) && flow_info.EndTime.After(timestamp) {
					packet_info = PacketInfo{FlowId: flow_info.FlowId, Direction: false, Timestamp: timestamp, Length: packet_length, Type: flow_info.Type, ServerIP: tp.ServerIP}
					timing_matched = true
					break

				}
			}

			if !timing_matched {
				// if no timings match then skip this packet
				count++
				continue
			}

		} else {
			panic("packets with non matching tuple found in filtered pcaps")
		}

		// adding packet to buffer
		buffer = append(buffer, packet_info)

		if len(buffer) >= buffer_size {
			err := WritePacketInfoBufferToDisk(output_json_file, buffer)
			if err != nil {
				panic(err.Error())
			}
			buffer = buffer[:0]
		}
	}

	if len(buffer) > 0 {
		err := WritePacketInfoBufferToDisk(output_json_file, buffer)
		if err != nil {
			panic(err.Error())
		}
	}

	fmt.Println(count)
}

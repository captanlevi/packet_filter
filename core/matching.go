package core

import (
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func GetFlowTupleToFlowInfo(csv_path string) map[Tuple]FlowInfo {
	records := GetFilteredCSVRecords(csv_path)
	tuple_map := make(map[Tuple]FlowInfo)
	for flow_id, row := range records {
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

		tuple_map[tuple] = flow_info

	}
	return tuple_map
}

func MatchPcaps(input_pcap_file string, output_json_file string, flow_info_map map[Tuple]FlowInfo) {
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

		/*
			timestamp, time_err := time.Parse(TimeLayout, packet.Metadata().Timestamp.Format(TimeLayout))
			if time_err != nil {
				panic(time_err.Error())
			}
		*/
		timestamp := packet.Metadata().Timestamp.UTC()
		packet_length := packet.Metadata().CaptureLength

		tp, validity := GetTupleFromPacket(packet)
		if !validity {
			panic("invalid packet in filtered pcap")
		}
		rev_tp := Tuple{ClientIP: tp.ServerIP, ServerIP: tp.ClientIP, ClientPort: tp.ServerPort, ServerPort: tp.ClientPort, Protocol: tp.Protocol}

		var packet_info PacketInfo

		if flow_info, exist := flow_info_map[tp]; exist {
			// flow info found
			if ((flow_info.StartTime == timestamp) || flow_info.StartTime.Before(timestamp)) && flow_info.EndTime.After(timestamp) {
				packet_info = PacketInfo{FlowId: flow_info.FlowId, Direction: true, Timestamp: timestamp, Length: packet_length, Type: flow_info.Type}

			} else {
				//fmt.Println(timestamp.GoString(), flow_info.StartTime.GoString(), flow_info.EndTime.GoString(), flow_info.Duration)
				count++
				continue
			}
		} else if flow_info, exists := flow_info_map[rev_tp]; exists {
			if ((flow_info.StartTime == timestamp) || flow_info.StartTime.Before(timestamp)) && flow_info.EndTime.After(timestamp) {
				packet_info = PacketInfo{FlowId: flow_info.FlowId, Direction: false, Timestamp: timestamp, Length: packet_length, Type: flow_info.Type}
			} else {
				count++
				continue
			}
		} else {
			panic("packets with non matching tuple found in filtered pcaps")
		}

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

package core

import (
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func GetFlowTupleToFlowInfo(csv_paths []string, mn_timestamp time.Time, mx_timestamp time.Time) map[Tuple][]FlowInfo {
	var wg sync.WaitGroup
	record_ch := make(chan [][]string, len(csv_paths))

	for worker_id := 0; worker_id < NUM_WORKERS; worker_id++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for csv_index := worker; csv_index < len(csv_paths); csv_index += NUM_WORKERS {
				fmt.Println("csv_index = ", csv_index, " Worker= ", worker, " csv_name= ", csv_paths[csv_index])
				records := GetFilteredCSVRecordsWithinTime(csv_paths[csv_index], mn_timestamp, mx_timestamp)
				record_ch <- records
			}
		}(worker_id)
	}

	wg.Wait()
	close(record_ch)

	records := make([][]string, 0)

	for channel_records := range record_ch {
		records = append(records, channel_records...)
	}

	//records := GetFilteredCSVRecords(csv_path)
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
		flow_provider := row[8]
		flow_type := row[9]
		flow_duration, _ := strconv.ParseFloat(row[2], 64)

		flow_info := FlowInfo{StartTime: start_time, EndTime: end_time, Type: flow_type, Duration: flow_duration, FlowId: flow_id, Provider: flow_provider}
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
	discarded_count := 0
	no_match_discarded := 0
	found_count := 0
	buffer_size := BUFFER_SIZE
	fmt.Println("Records extracted")
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
			// if packet is invaild just continue
			//discarded_count++
			continue
		}
		rev_tp := Tuple{ClientIP: tp.ServerIP, ServerIP: tp.ClientIP, ClientPort: tp.ServerPort, ServerPort: tp.ClientPort, Protocol: tp.Protocol}
		var packet_info PacketInfo

		if flow_info_slice, exist := flow_info_map[tp]; exist {
			// flow_info_slice found
			found_count++
			timing_matched := false
			for _, flow_info := range flow_info_slice {
				// iterating over the flow infos to check the timestamp information
				if flow_info.StartTime.Add(-TIME_BUFFER).Before(timestamp) && flow_info.EndTime.Add(TIME_BUFFER).After(timestamp) {
					packet_info = PacketInfo{FlowId: flow_info.FlowId, Direction: true, Timestamp: timestamp.Format(TimeLayout),
						Length: packet_length, Type: flow_info.Type, ServerIP: tp.ServerIP, Provider: flow_info.Provider}
					timing_matched = true
					break

				}
			}
			if !timing_matched {
				// if no timings match then skip this packet
				discarded_count++
				continue
			}

		} else if flow_info_slice, exist := flow_info_map[rev_tp]; exist {
			// rev tuple matched
			// The rev tuple server IP is the actual server IP as well, casue that is the one that matched
			found_count++
			timing_matched := false
			for _, flow_info := range flow_info_slice {
				if flow_info.StartTime.Add(-TIME_BUFFER).Before(timestamp) && flow_info.EndTime.Add(TIME_BUFFER).After(timestamp) {
					packet_info = PacketInfo{FlowId: flow_info.FlowId, Direction: false, Timestamp: timestamp.Format(TimeLayout),
						Length: packet_length, Type: flow_info.Type, ServerIP: rev_tp.ServerIP, Provider: flow_info.Provider}
					timing_matched = true
					break

				}
			}

			if !timing_matched {
				// if no timings match then skip this packet
				discarded_count++
				continue
			}

		} else {
			// The tuple and rev-tuple does not match anything from the ground truth file.
			no_match_discarded++
			continue
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
	fmt.Println("Packets found (matched 5 tuple) but discarded from PCAP because of timestamp filtering")
	fmt.Println(found_count, discarded_count, no_match_discarded)
}

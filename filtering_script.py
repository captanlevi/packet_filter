import pandas as pd
from tqdm import tqdm
from scapy.all import PcapReader, rdpcap, PcapWriter

def get5TuplesFromCSV(csv_path):
    def tupleExtract(row):
        return (row.client_ip, row.server_ip, row.client_port, row.server_port, row.protocol)

    df = pd.read_csv(csv_path)
    df = df[df["type"].isna() == False]
    
    required_types = ["Video", "Social Media", "Software Update", "Download", "File Storage", "Conferencing", "Music", "Live Video", "Mail"]
    reliable_classifiers = ["TPED.SNI.TLD",
        "TPED.SNI.TLDR", "TPE.N.A2P", "TPED.SNI.TLD.P.S2T", "TPED.SNI.PGTLD.P", "TPED.SNI.EM","TPED.SNI.TLD.P",                     
        "TPED.SNI.TLD.PT", 
        "TPED.SNI.PGTLD.P.S2T",
        "TPED.PT",             
        "TPED.SNI.TLDR.PT",
        "TPED.SNI.TLD.HURL"]
    
    df = df[df.type.isin(required_types)]
    df = df[df.classifier.isin(reliable_classifiers)]
    tuples = df.apply(tupleExtract, axis = 1)
    return set(tuples.values)




tuples = get5TuplesFromCSV(csv_path= "ground_truth.csv")
input_pcap_file = "small_pcap_file.pcap"
output_pcap_file = 'filtered_packets.pcap'
buffer_size = 50000  # Adjust the buffer size as needed
buffer = []




with PcapReader(input_pcap_file) as pcap_reader,  PcapWriter(output_pcap_file, append=True) as pcap_writer:
    for packet in tqdm(pcap_reader):
        if "IP" in packet:
            packet_ip = packet["IP"]
            src_ip = packet_ip.src
            dst_ip = packet_ip.dst
            proto = None
            if "TCP" in packet:
                src_port = packet["TCP"].sport
                dst_port = packet["TCP"].dport
                proto = 6
            elif "UDP" in packet:
                src_port = packet["UDP"].sport
                dst_port = packet["UDP"].dport
                proto = 11
            else:
                continue

            
            tp = (src_ip,dst_ip,src_port,dst_port,proto)
            rev_tp = (dst_ip,src_ip,dst_port,src_port,proto)

            if (tp not in tuples) and (rev_tp not in tuples):
                continue

            buffer.append(packet)
            if len(buffer) >= buffer_size:
                for pkt in buffer:
                    pcap_writer.write(pkt)
                buffer.clear()
    if buffer:
        for pkt in buffer:
            pcap_writer.write(pkt)
            buffer.clear()

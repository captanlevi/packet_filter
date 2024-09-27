from scapy.all import PcapReader, wrpcap

def extract_pcap_subset(input_pcap_file, output_pcap_file, num_packets):
    """
    Extract a small portion of a large PCAP file and save it as another PCAP file.

    :param input_pcap_file: Path to the input PCAP file.
    :param output_pcap_file: Path to the output PCAP file.
    :param num_packets: Number of packets to extract from the input PCAP file.
    """
    extracted_packets = []
    packet_count = 0

    # Open the input PCAP file using PcapReader for streaming
    with PcapReader(input_pcap_file) as pcap_reader:
        for packet in pcap_reader:
            if packet_count < num_packets:
                extracted_packets.append(packet)
                packet_count += 1
            else:
                break

    # Save the extracted packets to the output PCAP file
    wrpcap(output_pcap_file, extracted_packets)

    print(f"Extracted {packet_count} packets and saved to {output_pcap_file}")

# Example usage
input_pcap_file = 'large_pcap_file.pcap'
output_pcap_file = 'small_pcap_file.pcap'
num_packets = 100  # Adjust this number as needed

extract_pcap_subset(input_pcap_file, output_pcap_file, num_packets)
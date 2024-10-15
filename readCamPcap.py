from fields.Etsi_Its_Msgs import *


def show_cits_cam_messages(pcap_file_path):
    """
    Reads a pcapng file and prints CAMs using Scapy's show() method
    """
    packets = rdpcap(pcap_file_path)

    for packet in packets:
        if ITS_CAM in packet:
            print(packet.show(dump=True))


if __name__ == "__main__":
    pcap_file_path = "CAM_Recording.pcapng"
    show_cits_cam_messages(pcap_file_path)

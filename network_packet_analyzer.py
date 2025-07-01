

from scapy.all import sniff

def packet_callback(packet):
    print(f"[*] Packet Captured:")
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        proto = packet['IP'].proto
        print(f"    Source IP: {src_ip}")
        print(f"    Destination IP: {dst_ip}")
        print(f"    Protocol: {proto}")
        print(f"    Payload: {bytes(packet.payload)}")
    else:
        print(f"    Non-IP Packet: {packet.summary()}")
print("[*] Starting packet sniffer... Press Ctrl+C to stop.")
sniff(count=10, prn=packet_callback, store=False)


from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        proto = "OTHER"
        if packet.haslayer(TCP):
            proto = "TCP"
        elif packet.haslayer(UDP):
            proto = "UDP"

        print(f"[+] {src} -> {dst} | {proto}")

        # Detect suspicious behavior
        if packet.haslayer(TCP):
            dport = packet[TCP].dport
            if dport in [22, 23, 3389]:
                print(f"[!] Possible sensitive port access: {dport}")

print("[*] Starting packet capture...")

sniff(iface="eth0", prn=packet_callback, store=False)
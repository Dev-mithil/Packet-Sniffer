# Import libraries
from scapy.all import sniff, IP, TCP, UDP, conf        

# Forces to Sniff Layer-3
conf.L3socket

# Defined a function
def callback_the_packet(packet):             

    if IP in packet:                                      # if IP address consists of packet in it 
        ip_layer=packet[IP]
    print(f"[!] New Packet: {ip_layer.src} --> {ip_layer.dst}")

    if TCP in packet:                                     # if the protocol is TCP then prints the below message
        print("Protocol: TCP")
        print(f"Source port: {packet[TCP].sport}")
        print(f"Destination port: {packet[TCP].dport}")

    elif UDP in packet:                                   # if the protocol is UDP then prints the below message
        print("Protocol: UDP")
        print(f"Source port: {packet[UDP].sport}")
        print(f"Destination port: {packet[UDP].dport}")

    else:
        print("Protocol: Other")


# Main Program
print("Starting packet sniffing...")
sniff(prn=callback_the_packet, store=False, iface=conf.iface, filter="ip", lfilter=lambda p: IP in p) # calling the function back

#End

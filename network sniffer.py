from scapy.all import sniff

#Default Settings when no filter is applied

def default_settings():
    def process_packet(packet):
        print(packet.summary())
    sniff(prn=process_packet, count=100)

def detailed_settings():
    def process_packet(packet):
        print(packet.show())
    sniff(prn=process_packet, count=100)

#Functions for ip filter

def ip_filter(ip):
    def process_packet(packet):
        print(packet.summary())
    try:
        sniff(prn=process_packet, count=10, filter=f"host {ip}")
    except Exception as e:
        print(f"Error: {e}")

def det_ip_filter(ip):
    def process_packet(packet):
        print(packet.show())
    try:
        sniff(prn=process_packet, count=100, filter=f"host {ip}")
    except Exception as e:
        print(f"Error: {e}")

#Functions for protocol filter

def proto_filter(proto):
    def process_packet(packet):
        print(packet.summary())
    try:
        sniff(prn=process_packet, count=100, filter=f"proto {proto}")
    except Exception as e:
        print(f"Error: {e}")

def det_proto_filter(proto):
    def process_packet(packet):
        print(packet.show())
    try:
        sniff(prn=process_packet, count=100, filter=f"proto {proto}")
    except Exception as e:
        print(f"Error: {e}")

#Functions for port filter

def port_filter(port):
    def process_packet(packet):
        print(packet.summary())
    try:
        sniff(prn=process_packet, count=100, filter=f"port {port}")
    except Exception as e:
        print(f"Error: {e}")

def det_port_filter(port):
    def process_packet(packet):
        print(packet.show())
    try:
        sniff(prn=process_packet, count=100, filter=f"port {port}")
    except Exception as e:
        print(f"Error: {e}")

#Fucntion for packet count filter

def count_filter(count_):
    def process_packet(packet):
        print(packet.summary())
    try:
        sniff(prn=process_packet, count=int(count_))
    except Exception as e:
        print(f"Error: {e}")

def det_count_filter(count_):
    def process_packet(packet):
        print(packet.show())
    try:
        sniff(prn=process_packet, count=int(count_))
    except Exception as e:
        print(f"Error: {e}")

#User Inputs

ip = input("Enter IP address filter (or press enter to skip) : ").strip()
proto = input("Enter protocol filter (or press enter to skip) : ").strip()
port = input("Enter port filter (or press enter to skip) : ").strip()
count = input("Enter the number of packets you want to capture (or press enter to skip) : ").strip()
typ = input("Do you want detailed analysis of the packets or not (Y/N) : ").strip().upper()

#Conditions for the application of the filters

if not ip and not proto and not port and not count:
    if typ == "N":
        default_settings()
    elif typ == "Y":
        detailed_settings()
elif ip and not proto and not port and not count:
    if typ == "N":
        ip_filter(ip)
    elif typ == "Y":
        det_ip_filter(ip)
elif not ip and proto and not port and not count:
    if typ == "N":
        proto_filter(proto)
    elif typ == "Y":
        det_proto_filter(proto)
elif not ip and not proto and port and not count:
    if typ == "N":
        port_filter(port)
    elif typ == "Y":
        det_port_filter(port)
elif not ip and not proto and not port and count:
    if typ == "N":
        count_filter(count)
    elif typ == "Y":
        det_count_filter(count)
else:
    print("One filter at a time:)")
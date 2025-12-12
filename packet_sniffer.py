import scapy.all as scapy
import time

def sniff_packets(interface):
    """Starts the packet sniffer on the specified network interface."""
    # Sniff for 10 packets. Do not store them in memory (store=0).
    # prn calls process_sniffed_packet on each packet.
    scapy.sniff(iface=interface, store=0, prn=process_sniffed_packet, count=10)

def process_sniffed_packet(packet):
    """Processes a single captured packet to extract key information."""
    
    # Filter for IP packets. Most relevant traffic uses the IP layer.
    if packet.haslayer(scapy.IP):
        ip_layer = packet[scapy.IP]
        
        source_ip = ip_layer.src
        destination_ip = ip_layer.dst
        protocol = ip_layer.proto
        
        # Protocol mapping for clear output
        protocol_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        protocol_name = protocol_map.get(protocol, str(protocol))
        
        print("\n--- PACKET DETECTED ---")
        print(f"Source IP: {source_ip}")
        print(f"Destination IP: {destination_ip}")
        print(f"Protocol: {protocol_name}")
        
        # Check for raw payload data
        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load
            # Display a short part of the payload.
            print(f"Payload Data (Snippet): {repr(payload)[:50]}...")
        elif protocol_name == "TCP" and packet.haslayer(scapy.TCP):
            print(f"Source Port: {packet[scapy.TCP].sport}")
            print(f"Destination Port: {packet[scapy.TCP].dport}")
        
        print("-----------------------")

def get_interface():
    """Asks the user to select the active network interface."""
    print("Available interfaces:")
    
    # List all interfaces found by scapy
    interfaces = scapy.get_if_list()
    for i, iface in enumerate(interfaces):
        print(f"[{i}] {iface}")

    # Get user selection
    while True:
        try:
            choice = input("Enter the number of the interface to sniff (e.g., 0): ")
            index = int(choice)
            if 0 <= index < len(interfaces):
                return interfaces[index]
            else:
                print("Invalid choice. Try again.")
        except ValueError:
            print("Invalid input. Enter a number.")
            
def main():
    print("\n--- Prodigy InfoTech Task 05: Network Packet Analyzer ---")
    
    # 1. Select the interface
    chosen_interface = get_interface()
    
    # 2. Start sniffing
    print(f"\nSTARTING SNIFFER on interface: {chosen_interface}. Capturing 10 packets.")
    print("!!! ACTION REQUIRED: You must run this script with administrator/root privileges.")
    print("!!! Open a web page or perform a network action NOW to capture traffic...")
    
    # Give a short pause for the user to switch applications
    time.sleep(2)
    
    try:
        sniff_packets(chosen_interface)
    except Exception as e:
        print(f"\nERROR: Packet sniffing failed. This usually means you lack the necessary permissions. Run as Administrator/root.")
        print(f"Details: {e}")

# Run the main function
if __name__ == "__main__":
    try:
        main()
    except ImportError:
        print("ERROR: The 'scapy' library is not installed. Please install it.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
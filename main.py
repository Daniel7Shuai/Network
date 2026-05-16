from scapy.all import ARP, Ether, srp
import requests
import time

def get_network(ip_range):
    # Create an ARP request packet
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast/arp_request

    # Send the packet and receive responses
    result = srp(packet, timeout=3, verbose=0)[0]

    # Parse the responses
    devices = []
    for sent, received in result:

        # 1. Extract the IP and MAC address from the response
        ip = received.psrc
        mac = received.hwsrc

        # 2. Call your vendor function to resolve the hardware manufacturer
        print(f"[*] Resolving manufacturer for MAC: {mac}...")
        vendor = get_mac_vendor(mac)

        devices.append({"ip": ip, "mac": mac, "vendor": vendor})

        time.sleep(1.2)
    
    return devices

def get_mac_vendor(mac_address):
    # Use an API to get the vendor information based on the MAC address
    url = f"https://api.macvendors.com/{mac_address}"
    try:
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            return response.text
        else:
            return "Unknown Vendor"
    except Exception as e:
        return "Error fetching vendor information"

if __name__ == "__main__":
    target_subnet = input("Enter the IP range (e.g., 192.168.1.0/24): ") 
    results = get_network(target_subnet)

    print("\n[+] Scan Complete! Discovered Targets:")
    print("-" * 60)
    for device in results:
        print(f"IP: {device['ip']:15} | MAC: {device['mac']:17} | Vendor: {device['vendor']}")
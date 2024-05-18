import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff.ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    result  = []

    for element in answered_list:
        result = {"ip": element[1].psrc,"mac": element[1].hwsrc}
        result.append(result)

    return result

def display_results(results):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    print("********************************************")
    for result in result:
        print(result["ip"] + "\t\t" + result["mac"])

    target_ip = "192.168.1.1/24"
    scan_result = scan(target_ip)
    display_results(scan_result)
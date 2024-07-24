from scapy.all import ARP, Ether, srp
from netaddr import IPAddress
import netifaces as ni
from libs.phone import *

def getIfIPs():
    print("Getting interface IPs.")
    interfaces = ni.interfaces()
    gateways = ni.gateways()[2]
    arr = []
    for interface in interfaces:
        ip = ni.ifaddresses(interface)
        gatewayIp = ''
        if [ni.AF_INET][0] in ip:
            ip = ip[ni.AF_INET][0]
        if 'addr' in ip:
            #don't scan the local loopback interface, it's slow.
            if ip['addr'] != '127.0.0.1':
                for gateway in gateways:
                    #grab the gateway by matching the interface
                    if gateway[1] == interface:
                        gatewayIp = gateway[0]
                        arr.append(f'{gatewayIp}/{IPAddress(ip["netmask"]).netmask_bits()}')
    #dedupe arr
    arr = list(dict.fromkeys(arr))
    return arr

def scanNetwork(ips):
    print("Scanning the network.")
    phoneIPs = []
    for ip in ips:
        arp = ARP(pdst=ip)
        ether = Ether(dst='ff:ff:ff:ff:ff:ff')
        packet = ether/arp

        result = srp(packet, timeout=5, verbose=0)[0]
        for sent, received in result:
            # normalize the MAC
            mac = received.hwsrc.replace(":", "")
            mac = mac.lower()
            phoneIPs.append({'ip': received.psrc, 'mac': mac})
    return phoneIPs        

def parseCsv(filename):
    print("Reading CSV.")
    phones = []
    with open(filename, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            # normalize the MAC
            row['mac'] = row['mac'].replace(":", "")
            row['mac'] = row['mac'].lower()
            for value in row:
                value = value.strip()
            phones.append(row)
    return phones

def parseResults(scanIPs, phones):
    print("Parsing results.")
    phoneArr = []
    failures = []
    for scanIP in scanIPs:
        for index in range(len(phones)):
            if scanIP['mac'] == phones[index]['mac']:
                phones[index]['ip'] = scanIP['ip']
                phone = Phone(phones[index])
                phoneArr.append(phone)
                #remove the index as we don't want it to be an option anymore.
                phones.pop(index)
                break
    for phone in phones:
        failures.append(f'{phone["mac"]}: Phone could not be found.')
    return (phoneArr, failures)
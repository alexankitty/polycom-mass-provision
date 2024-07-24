from scapy.all import ARP, Ether, srp
from netaddr import IPAddress
import netifaces as ni
import argparse
import csv
import requests
import base64

### CSV Headers
### mac,pw,servertype,serverurl,serveruser,serverpass,tries,retrywait,tagsnua

parser = argparse.ArgumentParser(
                    prog='polycom-mass-provision',
                    description='Provisions many polycom phones on a network',
                    epilog='Alexankitty 2024')
parser.add_argument('csvfile', help="CSV File of all MACs and Passwords for the phones to provision")
parser.add_argument('provserver', help="The Provisioning server for the phones")
parser.add_argument('-ip', '--ip-address', help="IP Address in CIDR notation to scan for phones")

args = parser.parse_args()
iparr = []

if not args.ipaddress:
    #Grab all interface IPs if the IP CIDR is not supplied
    interfaces = ni.interfaces()
    for interface in interfaces:
        ip = ni.ifaddresses(interface)[ni.AF_INET][0]
        if ip.addr:
            iparr.append(f'{ip.addr}/{IPAddress(ip.netmask).netmask_bits()}')
else:
    iparr.append(args.ipaddress)

def scanNetwork(ips):
    phoneIPs = []
    for ip in ips:
        arp = ARP(pdst=ip)
        ether = Ether(dst='ff:ff:ff:ff:ff:ff')
        packet = ether/arp

        result = srp(packet, timeout=3, verbose=0)[0]
        for sent, received in result:
            phoneIPs.append({'ip': received.psrc, 'mac': received.hwsrc})
    return phoneIPs        

def parseCsv(filename):
    phones = []
    with open(filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            data = {}
            for key, value in row:
                data[key] = value
            phones.append(data)
    return phones

def parseResults(scanIPs, phones):
    phoneArr = []
    for scanIP in scanIPs:
        for index in range(len(phones)):
            if scanIP.mac == phones[index].mac:
                phoneArr.append({'ip': scanIP.ip, 'pw': phones[index].pw})
                #remove the index and decrement as we don't want it to be an option anymore.
                phones.pop(index)
                index-=1

def auth(ip, pw):
    endpoint = f'https://{ip}/form-submit/auth.htm'
    session = requests.Session()
    # Check if password works
    authstring = bytes(f"Polycom:{pw}", encoding="utf-8")
    session.cookies.set("Authorization", f"Basic {base64.b64encode(authstring).decode('ascii')}", domain='192.168.1.183')
    resp = session.post(endpoint, auth=('Polycom', pw), verify=False)
    if "SUCCESS" in resp.text:
        # return the session to simplify usage later.
        return session
    return False

def setProvisioning(session, phone):
    #423: Server Type | 0: FTP 1:TFTP 2:HTTP 3:HTTPS 4:FTPS
    #421: Provisioning Server URL
    #429: Provisioning Server User
    #415: Provisioning Server Password
    #417: File Transmit tries Default: 3
    #419: Retry Wait(s) Default: 1
    #425: Tag SN to UA Default: 0
    keys = {
        423: 'servertype',
        421: 'serverurl',
        429: 'serveruser',
        415: 'serverpass',
        417: 'tries',
        419: 'retrywait',
        425: 'tagsnua'
    }
    data = {}
    for index, key in keys:
        if phone[key]:
            #Only pull values we do have
            data[index] = phone[key]
    resp = session.post('https://192.168.1.183/form-submit',cookies=session.cookies, verify=False, data=data)
    if "CONF_CHANGE" in resp.text:
        print(f'{phone['ip']} succeeded!')
    else:
        print(f'{phone['ip']} failed!')
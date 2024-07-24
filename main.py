from scapy.all import ARP, Ether, srp
from netaddr import IPAddress
from bs4 import BeautifulSoup  
import netifaces as ni
import argparse
import csv
import requests
import urllib3
import base64
import json
import os

urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)

### CSV Headers
### mac,pw,servertype,serverurl,serveruser,serverpass,tries,retrywait,tagsnua

def main(): 
    ## Allow for easy importing for people who wish to use it in their projects by not having main run
    parser = argparse.ArgumentParser(
                        prog='polycom-mass-provision',
                        description='Provisions many polycom phones on a network',
                        epilog='Alexankitty 2024')
    parser.add_argument('csvfile', help="CSV File of all MACs and Passwords for the phones to provision")
    parser.add_argument('-ip', '--ip-address', dest='ipaddress', help="IP Address in CIDR notation to scan for phones")

    args = parser.parse_args()
    iparr = []

    if not args.ipaddress:
        #Grab all interface IPs if the IP CIDR is not supplied
        iparr = getIfIPs()
    else:
        iparr.append(args.ipaddress)

    phoneIPs = scanNetwork(iparr)
    phones = parseCsv(args.csvfile)
    phonetuple = parseResults(phoneIPs, phones)
    phoneArr = phonetuple[0]
    failures = phonetuple[1]
    for phone in phoneArr:
        try:
            session = auth(phone['ip'], phone['pw'])
        except requests.exceptions.ConnectionError as e:
            failures.append(f'{phone["ip"]} {phone["mac"]}: {e.args[0].reason}')
            continue
        if not session:
            failures.append(f'{phone["ip"]} {phone["mac"]}: Authentication failed')
            continue
        if not setProvisioning(session, phone):
            failures.append(f'{phone["ip"]} {phone["mac"]}: Configuration failed')
    for failure in failures:
        print(failure)
    if not failures:
        print("All phones configured successfully. :)")

def getIfIPs():
    print("Getting interface IPs.")
    interfaces = ni.interfaces()
    arr = []
    for interface in interfaces:
        ip = ni.ifaddresses(interface)
        if [ni.AF_INET][0] in ip:
            ip = ip[ni.AF_INET][0]
        if 'addr' in ip:
            #don't scan the local loopback interface, it's slow.
            if ip['addr'] != '127.0.0.1':
                arr.append(f'{ip["addr"]}/{IPAddress(ip["netmask"]).netmask_bits()}')
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
                phoneArr.append(phones[index])
                #remove the index as we don't want it to be an option anymore.
                phones.pop(index)
                break
    for phone in phones:
        failures.append(f'{phone["mac"]}: Phone could not be found.')
    return (phoneArr, failures)

def auth(ip, pw):
    endpoint = f'https://{ip}/form-submit/auth.htm'
    endpointalt = f'https://{ip}/auth.htm'
    session = requests.Session()
    # Older devices require cookie forging
    authstring = bytes(f"Polycom:{pw}", encoding="utf-8")
    # Check if password works
    #session.auth = ('Polycom', pw)
    resp = session.post(endpoint, auth=('Polycom', pw), verify=False)
    if not "SUCCESS" in resp.text:
        #some firmwares require get for god knows why
        resp = session.get(endpointalt, auth=('Polycom', pw), verify=False)
        if resp.status_code == 200:
            session.cookies = resp.cookies
            session.cookies.set("Authorization", f"Basic {base64.b64encode(authstring).decode('ascii')}", domain=ip)
            return session
    if "SUCCESS" in resp.text:
        # return the session to simplify usage later.
        session.cookies = resp.cookies
        session.cookies.set("Authorization", f"Basic {base64.b64encode(authstring).decode('ascii')}", domain=ip)
        return session
    return False

def parseNames(session, ip):
    #gotta scrape the web to find out the input name of each paramName 
    keys = {
            'servertype': 'device.prov.serverType',
            'serverurl': 'device.prov.serverName',
            'serveruser': 'device.prov.user',
            'serverpass': 'device.prov.password',
            'tries': 'device.prov.redunAttemptLimit',
            'retrywait': 'device.prov.redunInterAttemptDelay',
            'tagsnua':'device.prov.tagSerialNo'
            }
    configKeys = {}
    endpoint = f'https://{ip}/provConf.htm'
    resp = session.get(endpoint, cookies=session.cookies, verify=False)
    soup = BeautifulSoup(resp.text, 'xml')
    for index, key in keys.items():
        tag = soup.find('input', {"paramName": key})
        if not tag:
            tag = soup.find('select', {"paramName": key})
        configKeys[tag.attrs['name']] = index
    return configKeys

def setProvisioning(session, phone):
    keys = parseNames(session, phone['ip'])
    print(keys)
    if not keys:
        return False
    data = {}
    for index, key in keys.items():
        if phone[key]:
            #Only pull values we do have
            data[index] = phone[key]
    resp = session.post(f'https://{phone["ip"]}/form-submit', cookies=session.cookies, verify=False, data=data)
    if "CONF_CHANGE" in resp.text:
        return True
    else:
        return False

if __name__=="__main__": 
    main() 
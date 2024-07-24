from scapy.all import ARP, Ether, srp
from netaddr import IPAddress
from bs4 import BeautifulSoup  
import netifaces as ni
import argparse
import csv
import requests
import urllib3
import base64
import re
import ssl

urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)

ctx = urllib3.util.create_urllib3_context()
ctx.set_ciphers("DEFAULT@SECLEVEL=0")
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

### CSV Headers
### mac,pw,servertype,serverurl,serveruser,serverpass,tries,retrywait,tagsnua

class CustomSSLContextHTTPAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, ssl_context=None, **kwargs):
        self.ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = urllib3.poolmanager.PoolManager(
            num_pools=connections, maxsize=maxsize,
            block=block, ssl_context=self.ssl_context)

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
    # consider returning a phone object instead of a dict
    phonetuple = parseResults(phoneIPs, phones)
    phoneArr = phonetuple[0]
    failures = phonetuple[1]
    if phoneArr:
        for phone in phoneArr:
            try:
                #todo: make parallel
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
                phoneArr.append(phones[index])
                #remove the index as we don't want it to be an option anymore.
                phones.pop(index)
                break
    for phone in phones:
        failures.append(f'{phone["mac"]}: Phone could not be found.')
    return (phoneArr, failures)

def auth(ip, pw):
    endpointBase = f'https://{ip}/'
    endpointJs = f'https://{ip}/js/login.js'
    session = requests.session()
    session.adapters.pop("https://", None)
    session.mount("https://", CustomSSLContextHTTPAdapter(ctx))
    authstring = bytes(f"Polycom:{pw}", encoding="utf-8")
    # Check if password works
    resp = session.get(endpointJs, verify=False)
    js = resp.text
    authType = re.search(r'type: .*', js, re.MULTILINE).group(0)
    authType = charReplace(["'", '"', ","], authType)
    authType = authType.strip().lower()
    authEndpoint = re.search(r'url: .*.htm', js, re.MULTILINE).group(0)
    authEndpoint = charReplace(["'", '"', ","], authEndpoint)
    authEndpoint = endpointBase + authEndpoint.strip()
    if authType == 'get':
        resp = session.post(authEndpoint, auth=('Polycom', pw), verify=False)
    if authType == 'post':
        resp = session.post(authEndpoint, auth=('Polycom', pw), verify=False)
    if "INVALID" in resp.text:
        return False
    if resp.status_code == 200:
        # return the session to simplify usage later.
        session.cookies = resp.cookies
        if not session.cookies:
            # commit cookie forgery
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

def charReplace(charArray, target):
    for char in charArray:
         if char in target:
             target = target.replace(char, '')
    return target

def setProvisioning(session, phone):
    keys = parseNames(session, phone['ip'])
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
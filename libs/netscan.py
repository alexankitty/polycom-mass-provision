from scapy.all import srp, ARP, Ether
import netifaces as ni
from netaddr import IPAddress

class NetworkScanner():
    def __init__(self, ips: list = None) -> None:
        self['ips'] = [] if not ips else [ips]
        if not self['ips']:
            self.get_networks()
        self['networks'] = []
        self['resolved_hosts'] = []

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __getitem__(self, key):
        return getattr(self, key)

    def get_networks(self):
        print("Getting interface IPs.")
        interfaces = ni.interfaces()
        gateways = ni.gateways()[2]
        self['ips'] = []
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
                            self['ips'].append(f'{gatewayIp}/{IPAddress(ip["netmask"]).netmask_bits()}')
        #dedupe arr
        self['ips'] = list(dict.fromkeys(self['ips']))
    
    def get_hosts(self):
        print("Scanning for hosts")
        for ip in self['ips']:
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=5, verbose=False)
            for orig, host in ans:
                mac = host.src.replace(":", "")
                mac = mac.lower()
                self['resolved_hosts'].append({'ip': host.psrc, 'mac': mac})
        print(f"Found {len(self['resolved_hosts'])} hosts.")
        return self['resolved_hosts']
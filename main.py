import argparse
from libs.net import *
from libs.phone import *

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
    # consider returning a phone object instead of a dict
    phonetuple = parseResults(phoneIPs, phones)
    phoneArr = phonetuple[0]
    failures = phonetuple[1]
    if phoneArr:
        for phone in phoneArr:
            try:
                #todo: make parallel
                session = phone.auth()
            except requests.exceptions.ConnectionError as e:
                failures.append(f'{phone["ip"]} {phone["mac"]}: {e.args[0].reason}')
                continue
            if not session:
                failures.append(f'{phone["ip"]} {phone["mac"]}: Authentication failed')
                continue
            if not phone.setProvisioning():
                failures.append(f'{phone["ip"]} {phone["mac"]}: Configuration failed')
    for failure in failures:
        print(failure)
    if not failures:
        print("All phones configured successfully. :)")

if __name__=="__main__": 
    main() 
import argparse
from libs.net import *
from libs.phone import *
from joblib import Parallel, delayed

### CSV Headers
### mac,pw,servertype,serverurl,serveruser,serverpass,tries,retrywait,tagsnua

def main() -> None: 
    ## Allow for easy importing for people who wish to use it in their projects by not having main run
    parser = argparse.ArgumentParser(
                        prog='polycom-mass-provision',
                        description='Provisions many polycom phones on a network',
                        epilog='Alexankitty 2024')
    parser.add_argument('csvfile', help="CSV File of all MACs and Passwords for the phones to provision")
    parser.add_argument('-ip', '--ip-address', dest='ipaddress', help="IP Address in CIDR notation to scan for phones")
    parser.add_argument('-p', '--parallel-jobs', dest='jobs', help='Sets the limit on the number of phones that can be done simultaneously')
    parser.add_argument('-f', '--force', action='store_true', dest='forceUpdate', help='Forces empty fields to be entered. Useful for when the provisioning server does not require a username or password.')

    args = parser.parse_args()
    iparr = []
    jobs = 5

    if not args.ipaddress:
        #Grab all interface IPs if the IP CIDR is not supplied
        iparr = getIfIPs()
    else:
        iparr.append(args.ipaddress)
    if args.jobs:
        jobs = args.jobs

    phoneIPs = scanNetwork(iparr)
    phones = parseCsv(args.csvfile)
    # consider returning a phone object instead of a dict
    phonetuple = parseResults(phoneIPs, phones, args.forceUpdate)
    phoneArr = phonetuple[0]
    failures = phonetuple[1]
    if phoneArr:
        results = Parallel(n_jobs = jobs)(delayed(phoneHandler)(phone) for phone in phoneArr)
         #for phone in phoneArr:
            #phoneHandler(phone)
        for result in results:
            if result == True:
                continue
            failures.append(result)
    for failure in failures:
        print(failure)
    if not failures:
        print("All phones configured successfully. :)")

def phoneHandler(phone: Phone) -> str:
    try:
        session = phone.auth()
    except requests.exceptions.ConnectionError as e:
        return f'{phone["ip"]} {phone["mac"]}: {e.args[0].reason}'
    if not session:
        return f'{phone["ip"]} {phone["mac"]}: Authentication failed'
    if not phone.setProvisioning():
        return f'{phone["ip"]} {phone["mac"]}: Configuration failed'
    return True

if __name__=="__main__": 
    main() 
from libs.phone import *
import csv

def parseCsv(filename: str) -> list[dict]:
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

def parseResults(scanIPs: list[str], phones: list[Phone], force: bool = False) -> tuple[list[Phone], list[str]]:
    print("Parsing results.")
    phoneArr = []
    failures = []
    for scanIP in scanIPs:
        for index in range(len(phones)):
            if scanIP['mac'] == phones[index]['mac']:
                phones[index]['ip'] = scanIP['ip']
                phone = Phone(phones[index], force)
                phoneArr.append(phone)
                #remove the index as we don't want it to be an option anymore.
                phones.pop(index)
                break
    for index in range(len(phones)):
        #allow manually specifying the phone ip
        if 'ip' in phones[index]:
            phone = Phone(phones[index], force)
            phoneArr.append(phone)
    for phone in phones:
        #bypass if the phone got an ip through manual specification
        if 'ip' in phone:
            continue
        failures.append(f'{phone["mac"]}: Phone could not be found.')
    return (phoneArr, failures)
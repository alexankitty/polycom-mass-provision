# polycom-mass-provision
Provisions a network of phone from a CSV faster than a human can.

# Usage
A `./cleararpcache.sh` script is included should there be any issues locating any phones.  
Takes a path to a csv file, and optionally an IP Address in CIDR notation (192.168.1.0/24)  
May require you to run as root/admin.

```
usage: polycom-mass-provision [-h] [-ip IP_ADDRESS] csvfile

Provisions many polycom phones on a network

positional arguments:
  csvfile               CSV File of all MACs and Passwords for the phones to provision

options:
  -h, --help            show this help message and exit
  -ip IP_ADDRESS, --ip-address IP_ADDRESS
                        IP Address in CIDR notation to scan for phones

Alexankitty 2024
```
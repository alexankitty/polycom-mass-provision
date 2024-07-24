# polycom-mass-provision
Provisions a network of phone from a CSV faster than a human can.

# Usage
Takes a path to a csv file, and optionally an IP Address in CIDR notation (192.168.1.0/24)

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
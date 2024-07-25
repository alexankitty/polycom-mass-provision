# polycom-mass-provision
Provisions a network of phone from a CSV faster than a human can.

# Windows
Requires [Python](https://www.python.org/ftp/python/3.12.4/python-3.12.4-amd64.exe) to be able to run the script.
Requires [npcap](https://npcap.com/dist/npcap-1.79.exe) installed for the network scan functionality.  
Requires [Visual Studio Build Tools](https://aka.ms/vs/17/release/RemoteTools.amd64ret.enu.exe) in order to build python wheels.

# Setup
1. Run either `setup.bat` or `setup.sh` from your system's terminal emulator/command prompt.
2. Wait for the venv to setup, along with all python dependencies to build and install.
3. Once this is completed, proceed to usage.

# Usage
1. Put together a csv file with all of the phones you want to provisiong using the `template.csv` file included.
2. Run the script with `run.bat` or `run.sh` from your system's terminal emulator/command prompt. Include your csv file, and any additional arguments (Ex: `run.bat phones.csv -ip 192.168.1.1/24 -p 10`)
3. Wait for the script to finish. The results will be included once the script has ran to show you what phones failed to provision and why.
4. Report any issues you run into with the script to this repo.

Takes a path to a csv file, and optionally the IP Address of your router/gateway in CIDR notation (192.168.1.1/24)  
May require you to run as root/admin depending on your system setup.

```
usage: polycom-mass-provision [-h] [-ip IPADDRESS] [-p JOBS] csvfile

Provisions many polycom phones on a network

positional arguments:
  csvfile               CSV File of all MACs and Passwords for the phones to provision

options:
  -h, --help            show this help message and exit
  -ip IPADDRESS, --ip-address IPADDRESS
                        IP Address in CIDR notation to scan for phones
  -p JOBS, --parallel-jobs JOBS
                        Sets the limit on the number of phones that can be done simultaneously

Alexankitty 2024
```
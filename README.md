## Fail2ban Log Analysis Script
This script automatically parses fail2ban log and generates statistics on detected attacks

![alt tag](resources/img/attacks-by-country.png)

![alt tag](resources/img/attacks-by-time.png)

## Features:
- Uses offline geoip database to lookup country
- Also supports online ip lookup

## Requirements:
- Python 3.x
- python-geoip
- python-geoip-geolite2
- matplotlib

## Installation:
```
pip3 install --user python-geoip python-geoip-geolite2 matplotlib
```

```
Usage: python3 parse-log.py fail2ban.log
```

## TODO:
- Enable commandline options
- Option to run as a service 
- Email weekly / monthly report to user
- Support for analysis of other types of logs, e.g: btmp, etc.


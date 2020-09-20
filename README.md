# fail2ban-log-analysis
Python script to automatically parse fail2ban log and generate statistics on detected attacks

![alt tag](resources/img/attacks-by-country.png)

![alt tag](resources/img/attacks-by-time.png)

## Requirements:
- python-geoip
- python-geoip-geolite2
- matplotlib

## Features:
- Uses offline geoip database to lookup country of ip address
- Also supports online ip lookup

```
Usage: python3 parse-log.py fail2ban.log
```


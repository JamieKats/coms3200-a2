import ipaddress
ips = {ipaddress.IPv4Address("1.2.3.4"): 1234}

for device in ips.keys():
    print(type(device))
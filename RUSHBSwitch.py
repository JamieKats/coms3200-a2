"""
Entry point for the program.

Switch has three forms
    - local
    - global
    - mixed
    
QUESTIONS
    - How do you know what size data in the data pkt you receive? if mulitple 
    msgs in buffer then need to know how big data packet is so you dont read into the next packet in the buffer
"""
import struct
import ipaddress
import socket
import sys

MAX_LAT_LONG = 32767

class RUSHBSwitch:
    
    def __init__(self, type: str, ip_addresses_cidr: str, latitude: int, longitude: int) -> None:
        """_summary_
        """
        if self.check_valid_args(type, ip_addresses_cidr, latitude, longitude) == False:
            exit(1)
        
        self.type: str = type
        self.ip_addresses_cidr: str = ip_addresses_cidr
        self.latitude: int = latitude
        self.longitude: int = longitude
        
    
    def check_valid_args(self, type: str, ip_addresses_cidr: str, latitude: int, longitude: int) -> bool:
        # check type is either "global" or "local"
        if type in ["local", "global"] == False: return False
        
        # check ip address is valid CIDR notation
        # https://stackoverflow.com/questions/45988215/python-how-to-validate-an-ip-address-with-a-cidr-notation-import-socket
        try:
            ipaddress.ip_network(ip_addresses_cidr, strict=False)
        except ValueError:
            return False
        
        # check latitude and longitude in range of 0 -> 32767 inclusive
        if latitude in range(0, MAX_LAT_LONG + 1) == False \
            or longitude in range(0, MAX_LAT_LONG + 1) == False:
            return False
        
        
    def valid_cidr(ip: str) -> bool:
        """
        Checks if the provided ip is a valid cidr notation

        Args:
            ip (str): _description_

        Returns:
            bool: _description_
        """
        
    def run(self):
        print(self.ip_addresses_cidr)
        
        
class RUSHBSwitchLocal(RUSHBSwitch):
    """
    open listening port on UDP
    can connect to global and mixed switches

    Args:
        RUSHBSwitch (_type_): _description_
    """
    def __init__(self, type: str, ip_addresses_cidr: str, latitude: int, longitude: int) -> None:
        super().__init__(type, ip_addresses_cidr, latitude, longitude)


class RUSHBSwitchMixed(RUSHBSwitch):
    """
    open listening sockets on UDP and TCP for incoming connection from adapters and switches respectively
    
    creates outgoing connections to global/mixed switches
    """
    def __init__(self, type: str, local_ip_addresses_cidr: str, global_ip_addresses_cidr: str, latitude: int, longitude: int) -> None:
        super().__init__(type, local_ip_addresses_cidr, latitude, longitude)
        try:
            ipaddress.ip_network(global_ip_addresses_cidr, strict=False)
        except ValueError:
            exit(1)
        
        self.global_ip_addresses_cidr = global_ip_addresses_cidr


class RUSHBSwitchGlobal(RUSHBSwitch):
    """
    open listening port on TCP
    service other switches
    
    can create outgoing connectins to global/mixed

    Args:
        RUSHBSwitch (_type_): _description_
    """
    def __init__(self, type: str, ip_addresses_cidr: str, latitude: int, longitude: int) -> None:
        super().__init__(type, ip_addresses_cidr, latitude, longitude)
        
        
def process_arguments():
    """
    commands provided to this file are different for local mixed and global switched
    
    need to check which switch the arguments are for and initialise the correct type of switch
    """
    if len(sys.argv) != 5 and len(sys.argv) != 6: return
    
    # check if local switch
    switch = check_local_switch()
    if switch is not None:
        return switch
    
    # check if mixed switch
    switch = check_mixed_switch()
    if switch is not None:
        return switch
    
    # check if global switch
    switch = check_global_switch()
    if switch is not None:
        return switch
    
    return exit(1)
    
    
def check_local_switch():
    type = sys.argv[1]
    ip_addresses_cidr = sys.argv[2]
    latitude = sys.argv[3]
    longitude = sys.argv[4]

    if type == "local":
        return RUSHBSwitchLocal(type, ip_addresses_cidr, latitude, longitude)
    return None

def check_mixed_switch():
    if len(sys.argv) != 6: return None
    
    type = sys.argv[1]
    local_ip_addresses_cidr = sys.argv[2]
    global_ip_addresses_cidr = sys.argv[3]
    latitude = sys.argv[4]
    longitude = sys.argv[5]

    if type == "local":
        return RUSHBSwitchMixed(type, local_ip_addresses_cidr, global_ip_addresses_cidr, latitude, longitude)
    return None

def check_global_switch():
    type = sys.argv[1]
    ip_addresses_cidr = sys.argv[2]
    latitude = sys.argv[3]
    longitude = sys.argv[4]

    if type == "global":
        return RUSHBSwitchGlobal(type, ip_addresses_cidr, latitude, longitude)
    return None

def main():
    
    switch = process_arguments()
    
    switch.run()

if __name__ == "__main__":
    main()
import struct
import ipaddress
import socket

# Modes
DISCOVERY_01 = 0x01
OFFER_02 = 0x02
REQUEST_03 = 0x03
ACK_04 = 0x04
ASK_06 = 0x06
DATA_05 = 0x05
READY_07 = 0x07
LOCATION_08 = 0x08
FRAGMENT_0A = 0x0a
FRAGMENT_END_0B = 0x0b

class Packet:
    
    def __init__(self, mode: bytes, offset: int=0, src_ip: str="0.0.0.0", dest_ip: str="0.0.0.0") -> None:
        self.src_ip: ipaddress.IPv4Address = ipaddress.IPv4Address(src_ip) # 4 bytes
        self.dest_ip: ipaddress.IPv4Address = ipaddress.IPv4Address(dest_ip) # 4 bytes
        self.mode: bytes = mode # 1 byte
        self.offset: int = offset # 3 bytes
        self.date = None # any length
        
    def to_bytes(self):
        return struct.pack("!i i i L", int(self.src_ip), int(self.dest_ip), self.offset, self.mode)
    
    @staticmethod
    def fromBytes(data):
        unpacked_data = struct.unpack("!i i i L", data)
        mode = unpacked_data[3]
        offset = unpacked_data[2]
        src_ip = str(ipaddress.IPv4Address(unpacked_data[0]))
        dest_ip = str(ipaddress.IPv4Address(unpacked_data[1]))
        # print(unpacked_data)
        # print(ipaddress.IPv4Address(unpacked_data[0]))
        # print(ipaddress.IPv4Address(unpacked_data[1]))
        return Packet(mode=mode, offset=offset, src_ip=src_ip, dest_ip=dest_ip)
    
# def ip2long(ip):
#     """
#     Convert an IP string to long
#     """
#     packedIP = socket.inet_aton(ip)
#     return socket.inet_aton(ip)
#     # return struct.unpack("!L", packedIP)[0]
# # print(struct.calcsize("4i "))

x = Packet(DISCOVERY_01, 10, "1.2.3.4", "10.12.34.2")
print(x.to_bytes())

received_pkt = Packet.fromBytes(x.to_bytes())

print(received_pkt.dest_ip)
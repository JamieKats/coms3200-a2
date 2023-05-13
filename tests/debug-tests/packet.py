import struct
import ipaddress
import socket

# Modes
DISCOVERY_01 = 0x01
OFFER_02 = 0x02
REQUEST_03 = 0x03
ACK_04 = 0x04
DATA_05 = 0x05
ASK_06 = 0x06
READY_07 = 0x07
LOCATION_08 = 0x08
DISTANCE_09 = 0x09
FRAGMENT_0A = 0x0a
FRAGMENT_END_0B = 0x0b

HEADER_SIZE = 12 # bytes

# def header_from_bytes(data: bytearray):
#     unpacked_data = struct.unpack("!i i i L", data)
#     mode = unpacked_data[3]
#     offset = unpacked_data[2]
#     src_ip = str(ipaddress.IPv4Address(unpacked_data[0]))
#     dest_ip = str(ipaddress.IPv4Address(unpacked_data[1]))
#     # print(unpacked_data)
#     # print(ipaddress.IPv4Address(unpacked_data[0]))
#     # print(ipaddress.IPv4Address(unpacked_data[1]))
#     return Packet(mode=mode, offset=offset, src_ip=src_ip, dest_ip=dest_ip)


class Packet:
    
    def __init__(self, 
                 mode: int, 
                 offset: int=0, 
                 src_ip: ipaddress.IPv4Address=ipaddress.IPv4Address("0.0.0.0"), 
                 dest_ip: ipaddress.IPv4Address=ipaddress.IPv4Address("0.0.0.0"), 
                 data=None
    ) -> None:
        self.src_ip: ipaddress.IPv4Address = src_ip # 4 bytes
        self.dest_ip: ipaddress.IPv4Address = dest_ip # 4 bytes
        
        # self.mode: bytes = bytearray(mode) # 1 byte
        # self.mode: bytes = int.to_bytes(mode, 1, 'big') # 1 byte
        self.mode: int = mode # 1 byte
        # print(type(self.mode))
        # print(f"mode in packet init: {self.mode}")
        # print(f"mode in packet init: {mode}")
        # print(len(self.mode))
        self.offset: int = offset # 3 bytes
        self.data = data # any length
        
    def to_bytes(self):
        """
        Might need to change struct pack to this
        https://stackoverflow.com/questions/41664084/python-pack-ip-string-to-bytes

        Returns:
            _type_: _description_
        """
        # print(f"mode in to bytes: {self.mode}")
        # print(len(self.mode))
        offset_bytes = self.offset.to_bytes(3, 'big')
        mode_bytes = self.mode.to_bytes(1, 'big')
        offset_mode_as_int = int.from_bytes(offset_bytes + mode_bytes, "big")
        # print("IN PACKET TO BYTES")
        # print(f"offset bytes: {offset_bytes}")
        # print(f"mode_bytes: {mode_bytes}")
        # print(f"offset mode as int: {offset_mode_as_int}")
        # print(f"src ip: {self.src_ip} = {int(self.src_ip)}")
        # print(f"dest_ip: {self.dest_ip} = {int(self.dest_ip)}")
        return struct.pack("!I I I", int(self.src_ip), int(self.dest_ip), offset_mode_as_int)
        # return struct.pack("!i i i L", int(self.src_ip), int(self.dest_ip), self.offset, self.mode)
    
    @staticmethod
    def from_bytes(data_bytes):
        unpacked_data = struct.unpack("!I I I", data_bytes[:HEADER_SIZE])
        src_ip = ipaddress.IPv4Address(unpacked_data[0])
        dest_ip = ipaddress.IPv4Address(unpacked_data[1])
        # offset = int.to_bytes(data_bytes[2][8:11], 4)
        offset = int.from_bytes(data_bytes[8:11], 'big')
        # mode = unpacked_data[2][11:]
        mode = int.from_bytes(data_bytes[11:HEADER_SIZE], 'big')
        # print(unpacked_data)
        # print(f"src_ip: {src_ip}")
        # print(f"dest_ip: {dest_ip}")
        # print(f"offset: {offset}")
        # print(f"mode: {mode}")
        return Packet(mode=mode, offset=offset, src_ip=src_ip, dest_ip=dest_ip)
    
    # @staticmethod
    # def discovery_packet():
    #     disc_pkt: Packet = Packet(mode=DISCOVERY_01)
    #     disc_pkt.data = ipaddress.IPv4Address("0.0.0.0")
    #     # header = Packet(mode=DISCOVERY_01).to_bytes()
    #     # data = struct.pack("!i", int(ipaddress.IPv4Address("0.0.0.0")))
    #     return header + data
    
class DiscoveryPacket(Packet):
    def __init__(self) -> None:
        super().__init__(mode=DISCOVERY_01, data=ipaddress.IPv4Address("0.0.0.0"))
        
    def to_bytes(self):
        # self.data = ipaddress.IPv4Address('0.0.0.0')
        return super().to_bytes() + struct.pack("!I", int(self.data))
    
    @staticmethod
    def from_bytes(data_bytes) -> Packet:
        disc_packet: Packet = Packet.from_bytes(data_bytes)
        unpacked_data = struct.unpack("!I", data_bytes[HEADER_SIZE:])
        disc_packet.data = ipaddress.IPv4Address(unpacked_data[0])
        return disc_packet
    
class OfferPacket(Packet):
    def __init__(self, src_ip: ipaddress.IPv4Address, assigned_ip: ipaddress.IPv4Address) -> None:
        super().__init__(mode=OFFER_02, src_ip=src_ip, data=assigned_ip)
        
    def to_bytes(self):
        return super().to_bytes() + struct.pack("!I", int(self.data))
    
    @staticmethod
    def from_bytes(data_bytes) -> Packet:
        base_packet: Packet = Packet.from_bytes(data_bytes)
        unpacked_offer_data = struct.unpack("!I", data_bytes[HEADER_SIZE:])
        base_packet.data = ipaddress.IPv4Address(unpacked_offer_data[0])
        return base_packet
    
class RequestPacket(Packet):
    def __init__(self, dest_ip: ipaddress.IPv4Address, assigned_ip: ipaddress.IPv4Address) -> None:
        super().__init__(mode=REQUEST_03, dest_ip=dest_ip, data=assigned_ip)
        
    def to_bytes(self):
        return super().to_bytes() + struct.pack("!I", int(self.data))
    
    @staticmethod
    def from_bytes(data_bytes) -> Packet:
        base_packet: Packet = Packet.from_bytes(data_bytes)
        unpacked_request_data = struct.unpack("!I", data_bytes[HEADER_SIZE:])
        base_packet.data = ipaddress.IPv4Address(unpacked_request_data[0])
        return base_packet
    
class AcknowledgePacket(Packet):
    def __init__(self, 
                 src_ip: ipaddress.IPv4Address, 
                 dest_ip: ipaddress.IPv4Address, 
                 assigned_ip: ipaddress.IPv4Address
    ) -> None:
        super().__init__(mode=ACK_04, src_ip=src_ip, dest_ip=dest_ip, data=assigned_ip)
        
    def to_bytes(self):
        return super().to_bytes() + struct.pack("!I", int(self.data))
    
    @staticmethod
    def from_bytes(data_bytes):
        base_packet: Packet = Packet.from_bytes(data_bytes)
        unpacked_ack_data = struct.unpack("!I", data_bytes[HEADER_SIZE:])
        base_packet.data = ipaddress.IPv4Address(unpacked_ack_data[0])
        return base_packet
    
    
class DataPacket(Packet):
    def __init__(self, 
                 src_ip: ipaddress.IPv4Address, 
                 dest_ip: ipaddress.IPv4Address, 
                 data
    ) -> None:
        super().__init__(mode=DATA_05, src_ip=src_ip, dest_ip=dest_ip, data=data)
        
    def to_bytes(self):
        return super().to_bytes() + self.data.encode()
    
    @staticmethod
    def from_bytes(data_bytes):
        base_packet: Packet = Packet.from_bytes(data_bytes)
        base_packet.data = data_bytes[HEADER_SIZE:].decode()
        return base_packet
    

class QueryPacket(Packet):
    def __init__(
        self, 
        src_ip: ipaddress.IPv4Address, 
        dest_ip: ipaddress.IPv4Address
    ) -> None:
        super().__init__(mode=ASK_06, src_ip=src_ip, dest_ip=dest_ip)
        
    # def to_bytes(self):
    #     return super().to_bytes()
    
    # @staticmethod
    # def from_bytes(data_bytes):
    #     return super().from_bytes(data_bytes)
    
    
class ReadyPacket(Packet):
    def __init__(self, src_ip: ipaddress.IPv4Address, dest_ip: ipaddress.IPv4Address) -> None:
        super().__init__(mode=READY_07, src_ip=src_ip, dest_ip=dest_ip)
        
    # def to_bytes(self):
    #     return super().to_bytes()
        
class LocationPacket(Packet):
    def __init__(self, 
                 src_ip: ipaddress.IPv4Address, 
                 dest_ip: ipaddress.IPv4Address, 
                 latitude: int, 
                 longitude: int
    ) -> None:
        # print(f"pkt ip in location pkt init: {src_ip}")
        # print(f"pkt ip in location pkt init: {dest_ip}")
        super().__init__(mode=LOCATION_08, src_ip=src_ip, dest_ip=dest_ip, data=(latitude, longitude))
        
    def to_bytes(self):
        # print(self.data[0])
        # print(self.data[1])
        return super().to_bytes() + int(self.data[0]).to_bytes(2, 'big') + int(self.data[1]).to_bytes(2, 'big')
    
    @staticmethod
    def from_bytes(data_bytes):
        base_packet: Packet = Packet.from_bytes(data_bytes)
        latitude = int.from_bytes(data_bytes[HEADER_SIZE:HEADER_SIZE+2], 'big')
        longitude = int.from_bytes(data_bytes[HEADER_SIZE+2:], 'big')
        base_packet.data = (latitude, longitude)
        return base_packet
    
class DistancePacket(Packet):
    def __init__(self, 
                 src_ip: ipaddress.IPv4Address, 
                 dest_ip: ipaddress.IPv4Address, 
                 og_ip: ipaddress.IPv4Address, 
                 dist: int
    ) -> None:
        data = (og_ip, dist)
        super().__init__(mode=DISTANCE_09, src_ip=src_ip, dest_ip=dest_ip, data=data)
        
    def to_bytes(self):
        return super().to_bytes() + int(self.data[0]).to_bytes(4, 'big') + int(self.data[1]).to_bytes(4, 'big')
    
    @staticmethod
    def from_bytes(data_bytes):
        base_packet: Packet = Packet.from_bytes(data_bytes)
        og_ip = ipaddress.IPv4Address(int.from_bytes(data_bytes[HEADER_SIZE:HEADER_SIZE+4], 'big'))
        dist = int.from_bytes(data_bytes[HEADER_SIZE+4:], 'big')
        base_packet.data = (og_ip, dist)
        return base_packet
    
    
        
    
# def ip2long(ip):
#     """
#     Convert an IP string to long
#     """
#     packedIP = socket.inet_aton(ip)
#     return socket.inet_aton(ip)
#     # return struct.unpack("!L", packedIP)[0]
# # print(struct.calcsize("4i "))

# x = Packet(DISCOVERY_01, 10, "1.2.3.4", "10.12.34.2")
# print(x.to_bytes())

# received_pkt = Packet.from_bytes(x.to_bytes())

# print(received_pkt.dest_ip)
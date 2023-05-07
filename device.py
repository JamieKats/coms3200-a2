"""
Represents the class for a successful incoming TCP connection from a switch
to the current switch (host).

this class might be used for UDP connections also later?? just tcp for now
"""
    
import socket
import ipaddress
from sender_receiver import SenderReceiver

class Device:
    def __init__(self, conn_socket) -> None:
        self.conn_socket: socket.socket = conn_socket
        self.ip: ipaddress.IPv4Address = None
        self.latitude: int = None
        self.longitude: int = None
        
    def set_ip(self, ip: ipaddress.IPv4Address):
        self.ip = ip
        
    def set_latitude(self, latitude: int):
        self.latitude = latitude
        
    def set_longitude(self, longitude: int):
        self.longitude = longitude  
        
    def receive_packet(self):
        return SenderReceiver.receive_packet(conn_socket=self.conn_socket)
        
    def send_packet(self, packet: bytes):
        SenderReceiver.send_packet(packet=packet, conn_socket=self.conn_socket)
        
class Switch(Device):
    def __init__(self, conn_socket) -> None:
        super().__init__(conn_socket)
    
class ClientSwitch(Switch):
    def __init__(self, conn_socket) -> None:
        super().__init__(conn_socket)
    
class HostSwitch(Switch):
    def __init__(self, conn_socket) -> None:
        super().__init__(conn_socket)
        self.host_ip = None
        
    def set_host_ip(self, host_ip):
        self.host_ip = host_ip
    
class ClientAdapter(Device):
    def __init__(self, conn_socket) -> None:
        super().__init__(conn_socket)
        
        
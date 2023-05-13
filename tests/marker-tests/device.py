"""
Represents the class for a successful incoming TCP connection from a switch
to the current switch (host).

this class might be used for UDP connections also later?? just tcp for now
"""
    
import socket
import ipaddress
from sender_receiver import SenderReceiver
import packet as pkt
import queue
import time

class Device:
    def __init__(self, conn_socket) -> None:
        self.conn_socket: socket.socket = conn_socket
        self.ip: ipaddress.IPv4Address = None
        self.latitude: int = None
        self.longitude: int = None
        self.euclidian_dist = None
        
    # def set_ip(self, ip: ipaddress.IPv4Address):
    #     self.ip = ip
        
    def set_latitude(self, latitude: int):
        self.latitude = latitude
        
    def set_longitude(self, longitude: int):
        self.longitude = longitude  
        
    def receive_packet(self) -> pkt.Packet:
        return SenderReceiver.receive_packet_tcp(conn_socket=self.conn_socket)
        
    def send_packet(self, packet: pkt.Packet):
        SenderReceiver.send_packet_tcp(packet=packet, conn_socket=self.conn_socket)
        
class ClientDevice(Device):
    def __init__(self, conn_socket) -> None:
        super().__init__(conn_socket)
        # self.client_ip: ipaddress.IPv4Address = None
    
class ClientSwitch(ClientDevice):
    def __init__(self, conn_socket) -> None:
        super().__init__(conn_socket)

class ClientAdapter(ClientDevice):
    def __init__(self, udp_socket, socket_addr) -> None:
        super().__init__(conn_socket=udp_socket)
        self.socket_addr = socket_addr
        self.packet_queue = queue.Queue()
        self.time_last_ready_pkt: time.time = 0
        
    def receive_packet(self) -> pkt.Packet:
        return SenderReceiver.receive_packet_udp(self.packet_queue)
    
    def send_packet(self, packet: pkt.Packet):
        SenderReceiver.send_packet_udp(packet=packet, udp_socket=self.conn_socket, client_addr=self.socket_addr)
        
        
        
class HostSwitch(Device):
    def __init__(self, conn_socket) -> None:
        super().__init__(conn_socket)
        # self.host_ip: ipaddress.IPv4Address = None
        self.my_assigned_ip: ipaddress.IPv4Address = None
        
    # def set_host_ip(self, host_ip):
    #     self.host_ip = host_ip
        
    def set_assigned_ip(self, assigned_ip):
        self.my_assigned_ip = assigned_ip
        
# class Switch(Device):
#     def __init__(self, conn_socket) -> None:
#         super().__init__(conn_socket)
    
    
    
        
        
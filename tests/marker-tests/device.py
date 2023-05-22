"""
The University of Queensland
Semester 1 2023 COMS3200 Assignment 2 Part C

author: Jamie Katsamatsas 
student id: 46747200

This file contains classes used to represent different types of switches.
"""
import socket
import ipaddress
import queue
import time
import packet as pkt
from sender_receiver import SenderReceiver

READY_PACKET_TIMEOUT = 5

class Device:
    def __init__(self, conn_socket) -> None:
        self.conn_socket: socket.socket = conn_socket
        self.ip: ipaddress.IPv4Address = None
        self.latitude: int = None
        self.longitude: int = None
        self.euclidian_dist = None
        self.ready_to_receive = 0 # time the device last responded to a query packet
        self.fragments = []
        
    def set_latitude(self, latitude: int):
        self.latitude = latitude
        
    def set_longitude(self, longitude: int):
        self.longitude = longitude  
        
    def receive_packet(self) -> pkt.Packet:
        return SenderReceiver.receive_packet_tcp(conn_socket=self.conn_socket)
        
    def send_packet(self, packet: pkt.Packet):
        SenderReceiver.send_packet_tcp(packet=packet, conn_socket=self.conn_socket)
        
    def set_ready_to_receive(self) -> None:
        """
        Sets the ready to receive timestamp as now
        """
        self.ready_to_receive = time.time()
        
    def is_ready_to_receive(self) -> bool:
        """
        Checks if the device is ready to receive a data packet.
        The device is ready to receive a data packet if they have responded to 
        a query packet with a ready packet in the last 5 seconds.

        Returns:
            bool: True if the device is ready to receive, False otherwise.
        """
        return time.time() < (self.ready_to_receive + READY_PACKET_TIMEOUT)
        
class ClientDevice(Device):
    def __init__(self, conn_socket) -> None:
        super().__init__(conn_socket)
    
class ClientSwitch(ClientDevice):
    def __init__(self, conn_socket) -> None:
        super().__init__(conn_socket)

class ClientAdapter(ClientDevice):
    def __init__(self, udp_socket, socket_addr) -> None:
        super().__init__(conn_socket=udp_socket)
        self.socket_addr = socket_addr
        self.packet_queue = queue.Queue()
        
    def receive_packet(self) -> pkt.Packet:
        return SenderReceiver.receive_packet_udp(self.packet_queue)
    
    def send_packet(self, packet: pkt.Packet):
        SenderReceiver.send_packet_udp(
            packet=packet, 
            udp_socket=self.conn_socket, 
            client_addr=self.socket_addr
            )
        
        
class HostSwitch(Device):
    def __init__(self, conn_socket) -> None:
        super().__init__(conn_socket)
        self.my_assigned_ip: ipaddress.IPv4Address = None
        
    def set_assigned_ip(self, assigned_ip):
        self.my_assigned_ip = assigned_ip
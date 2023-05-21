"""
The University of Queensland
Semester 1 2023 COMS3200 Assignment 1 Part C

author: Jamie Katsamatsas 
student id: 46747200

This file implements send and receive messages for TCP. This file is used by 
both the server and client to send a receive messages.

TODO remove all instances of todo print statements in all files
"""
import json
import socket
import packet as pkt
import queue

MAX_BUFFER_SIZE = 1500


class SenderReceiver:
    
    @staticmethod
    def send_packet_tcp(packet: pkt.Packet, conn_socket: socket) -> bool:
        """
        Sends the given message to the given TCP socket.
        
        The length of the message is sent first, then the encoded mesage is 
        sent after.

        Args:
            message (dict): message to be sent
            conn_socket (socket): TCP socket the message is sent over

        Returns:
            bool: True if the message was sent successfully, False otherwise.
            Typically False indicates an issue with the socket e.g. a 
            closed socket.
        """
        print(type(packet))
        packet_bytes = packet.to_bytes()
        # send the message length and the message
        # print(f"sending pkt {packet}")
        try:
            conn_socket.sendall(packet_bytes)
        except BrokenPipeError or ConnectionResetError:
            return False
        
        return True
    
    @staticmethod
    def send_packet_udp(packet: pkt.Packet, udp_socket: socket, client_addr) -> bool:
        packet_bytes = packet.to_bytes()
        
        udp_socket.sendto(packet_bytes, client_addr)
        
        return True
        
        
    @staticmethod
    def receive_packet_tcp(conn_socket: socket) -> pkt.Packet:
        """
        Receive message over TCP.
        
        The length of the message is first received then the message is received.
        
        Args:
            conn_socket (socket): TCP socket to read the message off

        Returns:
            dict: the message read from the TCP socket
            
        [4]     J. Xu, "Handling Message Boundary in Socket Programming" 
        enzircle.com. 
        https://enzircle.com/handling-message-boundaries-in-socket-programming 
        (accessed April 10)
        """
        # receive the message length
        try:
            packet_bytes = conn_socket.recv(MAX_BUFFER_SIZE)
        except OSError:
            return None
        
        if packet_bytes == b'': return None
        # print(f"RECEVIED PACKET BYTES: {packet_bytes}")

        return _decode_packet(packet_bytes)
    
    @staticmethod
    def receive_packet_udp(packet_queue: queue.Queue):
        packet_bytes = packet_queue.get()
        print(f"udp packet receved from queue: {packet_bytes}")
        return _decode_packet(packet_bytes)
        
    
def _decode_packet(packet_bytes: bytes):
    packet_header: pkt.Packet = pkt.Packet.from_bytes(packet_bytes)
    
    if packet_header.mode == pkt.DISCOVERY_01:
        packet = pkt.DiscoveryPacket.from_bytes(packet_bytes)
    elif packet_header.mode == pkt.OFFER_02:
        packet = pkt.OfferPacket.from_bytes(packet_bytes)
    elif packet_header.mode == pkt.REQUEST_03:
        packet = pkt.RequestPacket.from_bytes(packet_bytes)
    elif packet_header.mode == pkt.ACK_04:
        packet = pkt.AcknowledgePacket.from_bytes(packet_bytes)
    elif packet_header.mode == pkt.DATA_05:
        packet = pkt.DataPacket.from_bytes(packet_bytes)
    elif packet_header.mode == pkt.ASK_06:
        packet = pkt.QueryPacket.from_bytes(packet_bytes)
    elif packet_header.mode == pkt.READY_07:
        packet = pkt.ReadyPacket.from_bytes(packet_bytes)
    elif packet_header.mode == pkt.LOCATION_08:
        packet = pkt.LocationPacket.from_bytes(packet_bytes)
    elif packet_header.mode == pkt.DISTANCE_09:
        packet = pkt.DistancePacket.from_bytes(packet_bytes)
    elif packet_header.mode == pkt.FRAGMENT_0A:
        packet = pkt.FragmentPacket.from_bytes(packet_bytes)
    elif packet_header.mode == pkt.FRAGMENT_END_0B:
        packet = pkt.FragmentEngPacket.from_bytes(packet_bytes)
        
    return packet
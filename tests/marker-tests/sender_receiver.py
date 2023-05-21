"""
The University of Queensland
Semester 1 2023 COMS3200 Assignment 2 Part C

author: Jamie Katsamatsas 
student id: 46747200

This file implements methods to send and receive packets for TCP and UDP.
"""
import socket
import queue
import packet as pkt

MAX_BUFFER_SIZE = 2000

class SenderReceiver:
    
    @staticmethod
    def send_packet_tcp(packet: pkt.Packet, conn_socket: socket) -> bool:
        """
        Sends the given packet to the given TCP socket.
        
        Args:
            packet (pkt.Packet): packet to be sent
            conn_socket (socket): TCP socket the message is sent over

        Returns:
            bool: True if the message was sent successfully, False otherwise.
            Typically False indicates an issue with the socket e.g. a 
            closed socket.
        """
        packet_bytes = packet.to_bytes()
        try:
            conn_socket.sendall(packet_bytes)
        except BrokenPipeError or ConnectionResetError:
            return False
        return True
    
    
    @staticmethod
    def send_packet_udp(
        packet: pkt.Packet, 
        udp_socket: socket, 
        client_addr: tuple
    ) -> bool:
        """
        Sends the given packet on the given UDP socket.

        Args:
            packet (pkt.Packet): packet to be sent
            udp_socket (socket): udp socket to send packet over
            client_addr (_type_): client ip and port to send UDP packet to

        Returns:
            bool: True on successful packet sending
        """
        packet_bytes = packet.to_bytes()
        
        udp_socket.sendto(packet_bytes, client_addr)
        
        return True
        
        
    @staticmethod
    def receive_packet_tcp(conn_socket: socket) -> pkt.Packet:
        """
        Receive packet bytes over TCP.
        
        Args:
            conn_socket (socket): TCP socket to read the packet off

        Returns:
            pkt.Packet: the packet object read from the TCP socket
        """
        try:
            packet_bytes = conn_socket.recv(MAX_BUFFER_SIZE)
        except OSError:
            return None
        
        if packet_bytes == b'': return None

        return _decode_packet(packet_bytes)
    
    
    @staticmethod
    def receive_packet_udp(packet_queue: queue.Queue) -> pkt.Packet:
        """
        Receive packet bytes from UDP socket

        Args:
            packet_queue (queue.Queue): Queue holding the incoming UDP packets.
            for a client

        Returns:
            pkt.Packet: _description_
        """
        packet_bytes = packet_queue.get()
        return _decode_packet(packet_bytes)
        
    
def _decode_packet(packet_bytes: bytes) -> pkt.Packet:
    """
    Deserialises a stream of bytes into a packet object.

    Args:
        packet_bytes (bytes): bytes representing a packet

    Returns:
        pkt.Packet: packet instance created from the packet_bytes given
    """
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
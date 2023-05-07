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

MAX_BUFFER_SIZE = 1500


class SenderReceiver:
    
    @staticmethod
    def send_packet(packet: bytes, conn_socket: socket) -> bool:
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
        # send the message length and the message
        print(f"sending pkt {packet}")
        try:
            conn_socket.sendall(packet)
        except BrokenPipeError or ConnectionResetError:
            return False
        
        return True
        
        
    @staticmethod
    def receive_packet(conn_socket: socket) -> dict:
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
            packet = conn_socket.recv(MAX_BUFFER_SIZE)
        except OSError:
            return None
        # print(f"received pkt: {packet}")

        return packet
                
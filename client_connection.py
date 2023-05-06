"""
Represents the class for a successful incoming TCP connection from a switch
to the current switch (host).

this class might be used for UDP connections also later?? just tcp for now
"""
    
import socket
from sender_receiver import SenderReceiver

class ClientConnection:
    def __init__(self, conn_socket) -> None:
        self.conn_socket: socket.socket = conn_socket
        self.ip = None
        self.latitude = None
        self.longitude = None
        
    def receive_message(self):
        SenderReceiver.receive_message()
        
    def send_message(self):
        SenderReceiver.send_message()
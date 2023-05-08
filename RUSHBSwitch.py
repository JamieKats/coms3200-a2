"""
Entry point for the program.

Switch has three forms
    - local
    - global
    - mixed
    
switches open their listening ports immediately and print them, mixed show UDP port first

local and global can create outgoping connections to switches and take stdin to connect to other switches.
mixed switches ignore all stdin
    
TEST STRINGS
# local switch
python3 RUSHBSwitch.py local 1.2.3.4/24 10 20

# mixed switch
python3 RUSHBSwitch.py local 2.3.4.5/24 12.12.12.12/24 49 50

QUESTIONS
    - How do you know what size data in the data pkt you receive? if mulitple 
    msgs in buffer then need to know how big data packet is so you dont read into the next packet in the buffer
    NOTE: adding a seperater to p[ackets ownt help since the adapter is not aware. I believe there needs to be some sort of data length field
    - can CIDR ip addresses given to us have the host bits set? e.g. in mixed switch example
    130.102.72.10/24 is given as the global_ip_address which has the host bit set at x.x.x.10
    therefore should that network start at 130.102.72.10 (host) then have 2 ^ (32-24) possible clients?
    The "IP Address Allocation" bit gives examples where the host ip starts at x.x.x.1, can we always 
    expect that or can the host bit start at any number like the mixed global switch example of 
    x.x.x.10
    - linking with qn above, in example where 130.102.72.10/24 is given as the global ip
    what would be the two ips you dont count in the 256 total ips in a /24 network??
"""
import struct
import ipaddress
import socket
import sys
import device
import threading
import queue
import time
import packet as pkt

HOST_IP = "127.0.0.1"

MAX_LAT_LONG = 32767

BUFFER_SIZE = 1500

class RUSHBSwitch:
    
    def __init__(
        self, 
        switch_type: str, 
        latitude: int, 
        longitude: int, 
        local_ip_addresses_cidr: str=None, 
        global_ip_addresses_cidr: str=None
    ) -> None:
        """_summary_
        """
        # check if the arguments provided are valid
        if self.check_valid_args(
            switch_type=switch_type, 
            local_ip_addresses_cidr=local_ip_addresses_cidr, 
            global_ip_addresses_cidr=global_ip_addresses_cidr, 
            latitude=latitude, 
            longitude=longitude) == False:
            exit(1)
            
        # print(ipaddress.ip_network(ip_addresses_cidr, strict=False))
        # print(type(ipaddress.ip_network(ip_addresses_cidr, strict=False)))
        # # print(list(ipaddress.ip_network(ip_addresses_cidr, strict=False)))
        # print(iter(ipaddress.ip_network(ip_addresses_cidr, strict=False)))
        # ip_iter = iter(ipaddress.ip_network(ip_addresses_cidr, strict=False))
        # print(next(ip_iter))
        # for ip in ipaddress.ip_network(ip_addresses_cidr, strict=False):
        #     print(ip)
        
        self.type: str = switch_type
        self.latitude: int = latitude
        self.longitude: int = longitude
        
        # self.local_ip_addresses_cidr: ipaddress.ip_network = ipaddress.ip_network(local_ip_addresses_cidr, strict=False)
        # self.global_ip_addresses_cidr: ipaddress.ip_network = ipaddress.ip_network(global_ip_addresses_cidr, strict=False)
        
        # set up packet queues
        self.incoming_tcp_packet_queue = queue.Queue()
        self.incoming_stdin_queue = queue.Queue()
        
        # initi empty clients and hosts maps
        self.clients = {}
        self.hosts = {}
        
        # set host ip with ipaddress.ip_network iterator
        self.set_global_ip(global_ip_addresses_cidr)
        self.set_local_ip(local_ip_addresses_cidr)
        
        # print(f"client ip: {self.get_local_client_ip()}")
        # print(f"client ip: {self.get_local_client_ip()}")
        # print(f"client ip: {self.get_local_client_ip()}")
    
    def check_valid_args(
        self, 
        switch_type: str, 
        local_ip_addresses_cidr: str, 
        global_ip_addresses_cidr: str, 
        latitude: int, 
        longitude: int
    ) -> bool:
        # check type is either "global" or "local"
        if switch_type in ["local", "global"] == False: return False
        
        # check ip address is valid CIDR notation
        # https://stackoverflow.com/questions/45988215/python-how-to-validate-an-ip-address-with-a-cidr-notation-import-socket
        if local_ip_addresses_cidr != None:
            try:
                ipaddress.ip_network(local_ip_addresses_cidr, strict=False)
            except ValueError:
                return False
            
        if global_ip_addresses_cidr != None:
            try:
                ipaddress.ip_network(global_ip_addresses_cidr, strict=False)
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
        
        
    def set_global_ip(self, global_ip_addresses_cidr):
        if global_ip_addresses_cidr == None: return
        
        self.global_ip_addresses_cidr: ipaddress.ip_network = ipaddress.ip_network(global_ip_addresses_cidr, strict=False)
        self.global_ip_addrs_iter = iter(self.global_ip_addresses_cidr)
        self.global_ip = next(self.global_ip_addrs_iter)

        
    def set_local_ip(self, local_ip_addresses_cidr):
        if local_ip_addresses_cidr == None: return
        
        self.local_ip_addresses_cidr: ipaddress.ip_network = ipaddress.ip_network(local_ip_addresses_cidr, strict=False)
        self.local_ip_addrs_iter = iter(self.local_ip_addresses_cidr)
        self.local_ip = next(self.local_ip_addrs_iter)
        
        
    def get_global_client_ip(self) -> ipaddress.IPv4Address:
        return next(self.global_ip_addrs_iter)
    
    def get_local_client_ip(self) -> ipaddress.IPv4Address:
        return next(self.local_ip_addrs_iter)
        
        
    def start(self):
        self.setup_listening_ports()
        self.setup_command_line()
        
        self.run_switch()
        
        
    def setup_listening_ports(self):
        raise NotImplementedError
    
    
    def init_udp_socket(self) -> socket.socket:
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.bind((HOST_IP, 0))
        
        # print udp port
        print(f"udp port: {udp_socket.getsockname()[1]}")
        
        return udp_socket
        
        
    def init_tcp_socket(self) -> socket.socket:
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_socket.bind((HOST_IP, 0))
        tcp_socket.listen()
        
        # print port bound
        print(f"tcp port: {tcp_socket.getsockname()[1]}")
        
        return tcp_socket
    
    
    def listen_udp_socket_thread(self, udp_socket: socket.socket):
        """
        receives incoming messages on udp and adds them to the incoming 
        message queue
        """
        while True:
            packet_information = udp_socket.recvfrom(BUFFER_SIZE)
            message = packet_information[0]
            addr = packet_information[1]
            
            # process udp packet here, might need to move udp packet processing out
            # via an outgoing udp packet queue

            
        
    def listen_tcp_socket_thread(self, tcp_socket):
        """
        accepts incoming connections and starts connections threads 
        
        All incoming connections from TCP socket are global ip side

        Returns:
            _type_: _description_
        """
        while True:
            try:
                conn_socket, addr = tcp_socket.accept()
            except OSError:
                return
            
            # create client connection instance
            client = device.ClientSwitch(conn_socket)
            
            # create thread to handle client incoming messages
            client_listener_thread = threading.Thread(
                target=self.client_listen_thread,
                args=(client, ),
                daemon=True)
            
            client_listener_thread.start()
            
            
    def client_listen_thread(self, client: device.Device):
        # complete greeting protocol then enter while loop
        discovery_packet: pkt.DiscoveryPacket = client.receive_packet()
        print(f"recevied pkt src_ip: {discovery_packet.src_ip}")
        print(f"recevied pkt dst_ip: {discovery_packet.dest_ip}")
        print(f"recevied pkt offset: {discovery_packet.offset}")
        print(f"recevied pkt mode: {discovery_packet.mode}")
        print(f"recevied pkt data: {discovery_packet.data}")
        
        # assign client ip and send offer packet
        client.ip: ipaddress.IPv4Address = self.get_global_client_ip()
        offer_packet: pkt.Packet = pkt.Packet(mode=pkt.OFFER_02, src_ip=self.global_ip)
        
        
        
        while True:
            try:
                packet = client.receive_packet()
            except ConnectionResetError:
                return
            
            # print(f"received packet = {packet}")
            # add message received to message queue
            self.incoming_tcp_packet_queue.put(packet)
            
    def setup_command_line(self):
        pass
            
    def create_stdin_thread(self):
        """
        Create a thread to handle commands from stdin and put into incoming 
        command queue

        Returns:
            _type_: _description_
        """
        stdin_thread = threading.Thread(
            target=self.stdin_listener_thread,
            args=(self.incoming_stdin_queue, ),
            daemon=True)
        stdin_thread.start()
        
        
    def stdin_listener_thread(self, incoming_stdin_queue: queue.Queue):
         while True:
            try:
                command = input().strip().split(" ")
            except EOFError:
                continue
            
            if len(command) < 2: continue
            
            if command[0] != "connect": continue
            
            try:
                port = int(command[1])
            except ValueError:
                continue
            
            print(f"Connecting to port: {port}")
            
            incoming_stdin_queue.put(port)
            

    def run_switch(self):
        """
        Once the switch is set up will process all incoming packets/commands

        Returns:
            _type_: _description_
        """
        while True:
            self.process_connect_commands()
            
            time.sleep(0.1)
        
    def process_connect_commands(self):
        """
        Creates TCP connections to global/mixed switches

        Returns:
            _type_: _description_
        """
        while True:
            try:
                port = self.incoming_stdin_queue.get(block=False)
            except queue.Empty:
                return
            
            switch_socket = self.connect_to_switch(port)
            
            # create client switch object
            host = device.HostSwitch(conn_socket=switch_socket)
            
            # greeting protocol needs to complete before client (self) can 
            # receive any message from host
            # greeting protocol needs to begin in its own thread, greeting protocol can hang indefinitely
            greeting_thread = threading.Thread(
                target=self.greeting_protocol,
                args=(host, ),
                daemon=True
            )
            greeting_thread.start()
            
            # complete greeting protocol
            
            
            # start thread listening for incoming tcp packets from host
            
            
            
            
            
    def connect_to_switch(self, port: int):
        switch_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            switch_socket.connect((HOST_IP, port))
        except ConnectionRefusedError:
            return None
        return switch_socket
    
    
    def greeting_protocol(self, host: device.HostSwitch):
        # send host dicsovery packet
        # discovery_pkt = pkt.Packet(
        #     mode=pkt.DISCOVERY_01
        #     )
        # discovery_pkt = discovery_pkt.to_bytes()
        discovery_pkt = pkt.DiscoveryPacket()
        # print(f"discovery pkt mode: {discovery_pkt.mode}")
        
        host.send_packet(discovery_pkt)
        
        time.sleep(10)
        
        
        
        
class RUSHBSwitchLocal(RUSHBSwitch):
    """
    open listening port on UDP to serve adapter
    can connect to global and mixed switches by TCP? i think

    Args:
        RUSHBSwitch (_type_): _description_
    """
    def __init__(
        self, 
        switch_type: str, 
        latitude: int, 
        longitude: int, 
        local_ip_addresses_cidr: str = None, 
        global_ip_addresses_cidr: str = None
    ) -> None:
        super().__init__(switch_type, latitude, longitude, local_ip_addresses_cidr, global_ip_addresses_cidr)
        
    def setup_listening_ports(self):
        # create udp socket
        udp_socket = self.init_udp_socket()
        
        # open UDP listen port for incoming adapter messages
        udp_listener_thread = threading.Thread(
            target=self.listen_udp_socket_thread,
            args=(udp_socket, ),
            daemon=True)
        udp_listener_thread.start()
        
        # doesnt open a tcp listening port, only connects outwards to other 
        # TCP ports i think
        
        return
    
    def setup_command_line(self):
        self.create_stdin_thread()


class RUSHBSwitchMixed(RUSHBSwitch):
    """
    open listening sockets on UDP and TCP for incoming connection from adapters and switches respectively
    
    creates outgoing connections to global/mixed switches on TCP
    """
    def __init__(self, switch_type: str, latitude: int, longitude: int, local_ip_addresses_cidr: str = None, global_ip_addresses_cidr: str = None) -> None:
        super().__init__(switch_type, latitude, longitude, local_ip_addresses_cidr, global_ip_addresses_cidr)
        try:
            ipaddress.ip_network(global_ip_addresses_cidr, strict=False)
        except ValueError:
            exit(1)
        
        self.global_ip_addresses_cidr = global_ip_addresses_cidr

    def setup_listening_ports(self):
        #################### SET UP UDP LISTENER FOR ADAPTERS
        # upen udp listen port for incoming adapter packets
        udp_socket = self.init_udp_socket()
        
        # open UDP listen port for incoming adapter messages
        udp_listener_thread = threading.Thread(
            target=self.listen_udp_socket_thread,
            args=(udp_socket, ),
            daemon=True)
        udp_listener_thread.start()
        
        #################### SET UP TCP LISTENER FOR SWITCHES
        tcp_socket = self.init_tcp_socket()
        
        tcp_listener_thread = threading.Thread(
            target=self.listen_tcp_socket_thread,
            args=(tcp_socket, ),
            daemon=True)
        tcp_listener_thread.start()
        

class RUSHBSwitchGlobal(RUSHBSwitch):
    """
    open listening port on TCP for service other switches
    
    can create outgoing connectins to global/mixed

    Args:
        RUSHBSwitch (_type_): _description_
    """
    def __init__(self, switch_type: str, latitude: int, longitude: int, local_ip_addresses_cidr: str = None, global_ip_addresses_cidr: str = None) -> None:
        super().__init__(switch_type, latitude, longitude, local_ip_addresses_cidr, global_ip_addresses_cidr)
        
    def setup_listening_ports(self):
        #################### SET UP TCP LISTENER FOR SWITCHES
        tcp_socket = self.init_tcp_socket()
        
        tcp_listener_thread = threading.Thread(
            target=self.listen_tcp_socket_thread,
            args=(tcp_socket, ),
            daemon=True)
        tcp_listener_thread.start()
        
    def setup_command_line(self):
        self.create_stdin_thread()
        
        
########################## FUNCTIONS WITHOUT CLASSES
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
    if len(sys.argv) != 5: return
    
    switch_type = sys.argv[1]
    local_ip_addresses_cidr = sys.argv[2]
    latitude = sys.argv[3]
    longitude = sys.argv[4]

    if switch_type == "local":
        return RUSHBSwitchLocal(
            switch_type=switch_type,
            latitude=latitude,
            longitude=longitude,
            local_ip_addresses_cidr=local_ip_addresses_cidr
            )
    return None

def check_mixed_switch():
    if len(sys.argv) != 6: return None
    
    switch_type = sys.argv[1]
    local_ip_addresses_cidr = sys.argv[2]
    global_ip_addresses_cidr = sys.argv[3]
    latitude = sys.argv[4]
    longitude = sys.argv[5]

    if switch_type == "local":
        return RUSHBSwitchMixed(
            switch_type=switch_type,
            latitude=latitude,
            longitude=longitude,
            local_ip_addresses_cidr=local_ip_addresses_cidr,
            global_ip_addresses_cidr=global_ip_addresses_cidr
        )
    return None

def check_global_switch():
    switch_type = sys.argv[1]
    global_ip_addresses_cidr = sys.argv[2]
    latitude = sys.argv[3]
    longitude = sys.argv[4]

    if switch_type == "global":
        return RUSHBSwitchGlobal(
            switch_type=switch_type,
            latitude=latitude,
            longitude=longitude,
            global_ip_addresses_cidr=global_ip_addresses_cidr
        )
    return None

def main():
    
    switch = process_arguments()
    
    switch.start()

if __name__ == "__main__":
    main()
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
python3 RUSHBSwitch.py local 192.168.0.1/24 50 20

# mixed switch
python3 RUSHBSwitch.py local 192.168.0.1/24 130.102.72.10/24 20 50
python3 RUSHBSwitch.py local 192.200.0.1/24 140.102.72.10/24 34 98

# global switch
python3 RUSHBSwitch.py global 111.102.72.10/24 70 5
python3 RUSHBSwitch.py global 150.102.72.10/24 32 76

QUESTIONS
    - How do you know what size data in the data pkt you receive? if mulitple 
    msgs in buffer then need to know how big data packet is so you dont read into the next packet in the buffer
    NOTE: adding a seperater to p[ackets ownt help since the adapter is not aware. I believe there needs to be some sort of data length field
    A: can assume for now adapter will send large packets slow enough that the receiver side will block before the adapter sends another
    - can CIDR ip addresses given to us have the host bits set? e.g. in mixed switch example
    130.102.72.10/24 is given as the global_ip_address which has the host bit set at x.x.x.10
    therefore should that network start at 130.102.72.10 (host) then have 2 ^ (32-24) possible clients?
    The "IP Address Allocation" bit gives examples where the host ip starts at x.x.x.1, can we always 
    expect that or can the host bit start at any number like the mixed global switch example of 
    x.x.x.10
    A: host is given ip sttarting at .10 and first client starts at .1
    - linking with qn above, in example where 130.102.72.10/24 is given as the global ip
    what would be the two ips you dont count in the 256 total ips in a /24 network??
    - is there any need for the client to save the IP address
    - is the ip assigned to a client only removed from the list of remaining 
    client ips when the greeting protocol finishes or when the offer packet is sent??
    i.e. if commuinication fails between the offfer pkt and the end of greeting 
    protocol can that ip be used for another client? ASK ON ED ............INCREMENT THE IP ONCE THE OFFER PACKET IS SENT
    - Chris mentioned in an ed post that "In IP allocation your switch will 
    ignore out of order packets" so therfore, out of order packets in IP 
    allocation breaks IP allocation and that connection will hang indefinitely? ASK ON ED. none of the tests check any error cases
    - if a host switch receives a distance packet from a client about an updated distance
    for one of the clients clients (which is already known to the host as a 
    different ip) how can the host switch "update" the distance to the clients client
    since the host only knows this switch by another ip????
    A: ignore case where theres multiple names for the same client
    - "If the distance specified in the packet is greater than or equal to the 
    existing distance record, or if the distance is greater than 1000, the 
    switch will do nothing." therefore if the original distance is 1500 and the 
    new distance is 1200, I do nothing since the new distance > 1000?? A: YES
    - "Whenever a switch receives a Location packet, it will inform all other 
    neighbouring switches of the Euclidean distance (rounded down) from the 
    new switch to the respective neighbour." This so me sounds like you are 
    telling your neighbouring switches the distance to the new switch connected 
    to you to your neighbours is the stright line?? AKA it skips the middle router??
    A: not in straight line, it is dist from client to middle then middle to neighbour
    
    - Since for now we can assume the adapter will send the packets slow enough 
    that the receiving switch will block before a new piece of data is received.
    A similar issue occurs for switch to switch packet sending. Suggestion from chris
    is to pattern match the structure of the header to split up packets. Suggestion
    from arthur is this shouldnt be an issue or you can put sleeps in between 
    sending the packets so you dont get multiple packets in the buffer
"""
import math
import ipaddress
import socket
import sys
import device
import threading
import queue
import time
import packet as pkt
from connected_devices import ConnectedDevices

HOST_IP = "127.0.0.1"

MAX_LAT_LONG = 32767

BUFFER_SIZE = 1500

def euclidean_dist(p1, p2):
    return int(math.sqrt((int(p1.latitude) - int(p2.latitude))**2 + (int(p1.longitude) - int(p2.longitude))**2))

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
        # self.clients = {}
        # self.hosts = {}
        self.connected_devices = ConnectedDevices()
        
        # set host ip with ipaddress.ip_network iterator
        self.set_global_ip(global_ip_addresses_cidr)
        self.set_local_ip(local_ip_addresses_cidr)
        
        # print(f"client ip: {self.get_local_client_ip()}")
        # print(f"client ip: {self.get_local_client_ip()}")
        # print(f"client ip: {self.get_local_client_ip()}")
        self.adapter_message_queues = {}
    
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
        
        
    # def valid_cidr(ip: str) -> bool:
    #     """
    #     Checks if the provided ip is a valid cidr notation

    #     Args:
    #         ip (str): _description_

    #     Returns:
    #         bool: _description_
    #     """
        
        
    def set_global_ip(self, global_ip_addresses_cidr):
        if global_ip_addresses_cidr == None: return
        
        self.global_ip_addresses_cidr: ipaddress.ip_network = ipaddress.ip_network(global_ip_addresses_cidr, strict=False)
        self.global_ip_addrs_iter = iter(self.global_ip_addresses_cidr)
        
        # start client addresses at x.x.x.1 addr
        next(self.global_ip_addrs_iter)
        self.global_ip = ipaddress.IPv4Address(global_ip_addresses_cidr.split("/")[0])
        # print(f"GLOBAL IP: {self.global_ip}")
        # print(f"GLOBAL IP LIST IS: {list(iter(self.global_ip_addresses_cidr))}")

        
    def set_local_ip(self, local_ip_addresses_cidr):
        if local_ip_addresses_cidr == None: return
        
        self.local_ip_addresses_cidr: ipaddress.ip_network = ipaddress.ip_network(local_ip_addresses_cidr, strict=False)
        self.local_ip_addrs_iter = iter(self.local_ip_addresses_cidr)
        
        # start client addresses at x.x.x.1 addr
        next(self.local_ip_addrs_iter)
        self.local_ip = ipaddress.IPv4Address(local_ip_addresses_cidr.split("/")[0])
        # print(f"LOCAL IP: {self.local_ip}")
        # print(f"LOCAL IP LIST IS: {list(iter(self.local_ip_addresses_cidr))}")
        
        
    def get_global_client_ip(self) -> ipaddress.IPv4Address:
        client_addr = next(self.global_ip_addrs_iter)
        return client_addr if client_addr != self.global_ip else next(self.global_ip_addrs_iter)
    
    def get_local_client_ip(self) -> ipaddress.IPv4Address:
        client_addr = next(self.local_ip_addrs_iter)
        return client_addr if client_addr != self.local_ip else next(self.local_ip_addrs_iter)
        
        
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
            packet = packet_information[0]
            addr = packet_information[1]
            
            print(f"UDP message: {packet}")
            print(f"UDP addr: {addr}")
            
            
            # create adapterClient instance only if client doesnt already exist
            existing_adapter = self.connected_devices.get_udp_client_with_addr(addr)
            if existing_adapter is not None: # adapter already exists
                existing_adapter.packet_queue.put(packet)
                continue
            
            # create client and thread if they dont exist
            adapter = device.ClientAdapter(udp_socket=udp_socket, socket_addr=addr)
            # self.connected_devices.add_new_connection(adapter)
            
            adapter.packet_queue.put(packet)
                
            adapter_client_thread = threading.Thread(
                target=self.client_listen_thread,
                args=(adapter,),
                daemon=True
            )
            adapter_client_thread.start()
            print("end of listen udp socket")
            
        
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
        if self.greeting_protocol_with_client(client) == False:
            print("client_listen_thread: Greeting proto with client FAILED")
            return
        print("client_listen_thread: Greeting proto with client PASSED")
        
        # client sends location package
        
        self.process_incoming_packets(client)
        # while True:
        #     try:
        #         packet = client.receive_packet()
        #     except ConnectionResetError:
        #         return
            
        #     # NOTE may need to switch functionality to send packets to an incoming packet queue
        #     # add message received to message queue
        #     # self.incoming_tcp_packet_queue.put(packet)
            
    def greeting_protocol_with_client(self, client: device.ClientDevice):
        # print("in greeting proto")
        # complete greeting protocol then enter while loop
        discovery_packet: pkt.DiscoveryPacket = client.receive_packet()
        # print(f"disc packet {discovery_packet}")
        # print(f"recevied pkt src_ip: {discovery_packet.src_ip}")
        # print(f"recevied pkt dst_ip: {discovery_packet.dest_ip}")
        # print(f"recevied pkt offset: {discovery_packet.offset}")
        # print(f"recevied pkt mode: {discovery_packet.mode}")
        # print(f"recevied pkt data: {discovery_packet.data}")
        if discovery_packet.mode != pkt.DISCOVERY_01: return False
        
        
        # assign client ip and send offer packet
        # if client is adapter give next availble local ip otherwise give global ip
        if isinstance(client, device.ClientAdapter):
            client.ip: ipaddress.IPv4Address = self.get_local_client_ip()
            src_ip = self.local_ip
        else:
            client.ip: ipaddress.IPv4Address = self.get_global_client_ip()
            src_ip = self.global_ip
    
        offer_packet: pkt.OfferPacket = pkt.OfferPacket(src_ip=src_ip, assigned_ip=client.ip)
        client.send_packet(offer_packet)
        # print("in client listen greeting after offer packet")
        
        # receive request packet
        request_pkt: pkt.RequestPacket = client.receive_packet()
        if request_pkt.mode != pkt.REQUEST_03: return False
        
        # create and send acknowledgement packet
        ack_pkt: pkt.AcknowledgePacket = pkt.AcknowledgePacket(src_ip=src_ip, dest_ip=client.ip, assigned_ip=client.ip)
        client.send_packet(ack_pkt)
        
        self.connected_devices.add_new_connection(client)
        return True

    # def location_exchange_with_client(self, client: device.ClientDevice):
    #     """
    #     Server waits for location message from client and responds to client 
    #     with one then relays distance to neighbours
        
    #     NOTE after greeting protocol the host can just listen for normal packets
    #     and respond to the location packet like normal and update people with distance packets
    #     BUT when the client finishes greeting proto it will send the first 
    #     location pkt as part of the start up process and update all its 
    #     neighbours of the servers response without responding again to the servers location packet.
    #     Therefore, responding to location pkts can be apart of processing normal pkts for server
    #     but for the client this process has to be unique and apart of the start up process 

    #     Args:
    #         client (device.ClientDevice): _description_
    #     """
    #     client_location_pkt: pkt.LocationPacket = client.receive_packet()
    #     if client_location_pkt.mode != pkt.LOCATION_08: return False
        
    #     # get host ip relative to if client is local or global        
    #     if isinstance(client, device.ClientAdapter):
    #         src_ip = self.local_ip
    #     else:
    #         src_ip = self.global_ip
        
    #     # create and send responde location pkt
    #     location_pkt: pkt.LocationPacket = pkt.LocationPacket(src_ip=src_ip, dest_ip=client.ip, latitude=self.latitude, longitude=self.longitude)
    #     client.send_packet(location_pkt)
        
    #     # update client information with latitude and longitude
    #     client.latitude = location_pkt.data[0]
    #     client.longitude = location_pkt.data[1]
    #     client_dist = math.sqrt((self.latitude - client.latitude)**2 + (self.longitude - client.longitude)**2)
        
        
        
        
        
        
            
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
            if switch_socket == None:
                print("Connection failed...") # TODO
                continue
            
            # create client switch object
            host = device.HostSwitch(conn_socket=switch_socket)
            
            # greeting protocol needs to complete before client (self) can 
            # receive any message from host
            # greeting protocol needs to begin in its own thread, greeting protocol can hang indefinitely
            host_conn_thread = threading.Thread(
                target=self.host_connection_thread,
                args=(host, ),
                daemon=True
            )
            host_conn_thread.start()
            
            # complete greeting protocol
            
            
            # start thread listening for incoming tcp packets from host
            
            
            
            
            
    def connect_to_switch(self, port: int):
        switch_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            switch_socket.connect((HOST_IP, port))
        except ConnectionRefusedError:
            return None
        return switch_socket
    
    def host_connection_thread(self, host: device.HostSwitch):
        greeting_success = self.greeting_protocol_with_host(host)
        if greeting_success == False: 
            print("host_connection_thread: Greeting proto with host FAILED")
            return
        print("host_connection_thread: Greeting proto with host PASSED")
        
        # client switch sends location pkt to host
        # print("Creating location pkt to send to host")
        # print(f"my ip: {host.my_assigned_ip}")
        # print(f"host ip: {host.ip}")
        # print(f"my lat: {self.latitude}")
        # print(f"my long: {self.longitude}")
        location_pkt: pkt.LOCATION_08 = pkt.LocationPacket(src_ip=host.my_assigned_ip, dest_ip=host.ip, latitude=self.latitude, longitude=self.longitude)
        host.send_packet(location_pkt)
        print("Sent location pkt to host")
        
        
        # # recevie location pkt response from host
        # host_location_pkt: pkt.LocationPacket = host.receive_packet()
        # if host_location_pkt.mode != pkt.LOCATION_08:
        #     print("Host did not send a location pkt back")
        #     return
        
        # host.latitude = host_location_pkt.data[0]
        # host.longitude = host_location_pkt.data[1]
        # host_dist = euclidean_dist(host, self)
        # self.connected_devices.update_distance_to_device(host_dist, host.ip)
        
        # greeting protocol with host was success, therefore can add host to 
        # list of hosts we can communicate with
        # self.connected_devices.add_new_connection(host)
        self.process_incoming_packets(host)
        
                
    def process_incoming_packets(self, device: device.Device):
        while True:
            try:
                packet = device.receive_packet()
            except ConnectionResetError:
                return
            
            if packet.mode == pkt.DATA_05:
                self.handle_data_packet(packet)
            elif packet.mode == pkt.READY_07:
                self.handle_ready_packet(packet)
            elif packet.mode == pkt.LOCATION_08:
                self.handle_location_packet(conn_device=device, packet=packet)
            elif packet.mode == pkt.DISTANCE_09:
                self.handle_distance_packet(packet)
            elif packet.mode == pkt.FRAGMENT_0A or packet.data == pkt.FRAGMENT_END_0B:
                self.handle_fragments(packet)
        
    
    def handle_data_packet(self, packet: pkt.DataPacket):
        # if packet is for someone an immediate neighbour send to them
        neighbour: device.Device = self.connected_devices.get_neighbour_with_ip(packet.src_ip)
        if neighbour != None:
            neighbour.send_packet(packet)
            return
        
        # If switch aware of dest send to switch on shortest path with longest 
        # matching ip prefix
        if packet.dest_ip in self.connected_devices.distance_to_devices.keys():
            paths = self.connected_devices.distance_to_devices[packet.dest_ip]
            if len(paths) == 1:
                neighbour = self.connected_devices.get_neighbour_with_ip(paths[0][0])
                neighbour.send_packet(packet)
                return
            
            # get neighbour on path with greatest matching prefix of dest ip
            ips = [path[0] for path in paths]
            selected_ip = self.connected_devices.get_ip_with_longest_ip_prefix(ips, packet.dest_ip)
            neighbour = self.connected_devices.get_neighbour_with_ip(selected_ip)
            neighbour.send_packet(packet)
            return
            
        # if dest ip is unknown send to neighbour with longest matching ip prefix
        ips = [device.ip for device in self.connected_devices.get_neighbours()]
        selected_ip = self.connected_devices.get_ip_with_longest_ip_prefix(ips, packet.dest_ip)
        neighbour = self.connected_devices.get_neighbour_with_ip(selected_ip)
        neighbour.send_packet(packet)
        return
        
        
        
    def handle_location_packet(self, conn_device: device.Device, packet: pkt.LocationPacket):
        print("in handle_location_packet")
        conn_device.latitude = packet.data[0]
        conn_device.longitude = packet.data[1]
        # print(f"conn device lat: {conn_device.latitude}")
        # print(f"conn device long: {conn_device.longitude}")
        # print(f"out lat: {self.latitude}")
        # print(f"out long: {self.longitude}")
        
        device_dist = euclidean_dist(conn_device, self)
        # print(f"ip in handle {conn_device.ip}")
        self.connected_devices.update_distance_to_device(new_dist=device_dist , device_ip=conn_device.ip)
        # print(f"connected hosts: {self.connected_devices.hosts}")
        # print(f"connected clients: {self.connected_devices.clients}")
        # print(f"connected device dist: {self.connected_devices.distance_to_devices}")
        
        # respond to device if they are a client
        if isinstance(conn_device, device.ClientDevice) == True:
            # print(True)
            location_pkt: pkt.LocationPacket = pkt.LocationPacket(src_ip=self.global_ip, dest_ip=conn_device.ip, latitude=self.latitude, longitude=self.longitude)
            conn_device.send_packet(location_pkt)
    
        # create dist pkt for each neighbour and send
        neighbour: device.Device
        for neighbour in self.connected_devices.get_neighbours():
            if neighbour == conn_device: continue
            
            # distance from location pkt sender to neighbour
            og_to_neighbour: int = int(device_dist) + int(self.connected_devices.distance_to_devices[neighbour.ip][1])
            dist_pkt: pkt.DistancePacket = pkt.DistancePacket(
                src_ip=self.global_ip,
                dest_ip=neighbour.ip, 
                og_ip=conn_device.ip, 
                dist=og_to_neighbour)
            neighbour.send_packet(dist_pkt)
            
            
    def handle_distance_packet(self, packet: pkt.DistancePacket):
        """
        Updates the distance to the client specified in the distance packet

        Args:
            packet (pkt.DistancePacket): _description_
        """
        # print(f"DKJFGBDFKJGBDFGKB {packet.data[0]}")
        self.connected_devices.update_distance_to_device(
            new_dist=packet.data[1], 
            device_ip=packet.data[0], 
            via_device=packet.src_ip)
        
        
    
    
    def greeting_protocol_with_host(self, host: device.HostSwitch) -> bool:
        """
        TODO 
        - may need to cause running thread to hang indefinitely if the 
        greeting process fails
        - will need to implement checks to make sure the received packets have all the correct information

        Args:
            host (device.HostSwitch): _description_
        """
        # send host dicsovery packet
        # discovery_pkt = pkt.Packet(
        #     mode=pkt.DISCOVERY_01
        #     )
        # discovery_pkt = discovery_pkt.to_bytes()
        discovery_pkt = pkt.DiscoveryPacket()
        host.send_packet(discovery_pkt)
        
        # receive offer packet: assign ip to host instance and save ip assigned to you
        offer_pkt = host.receive_packet()
        if offer_pkt.mode != pkt.OFFER_02: return False
        # print(f"offer pkt src ip: {offer_pkt.src_ip}")
        host.ip = offer_pkt.src_ip
        host.my_assigned_ip = offer_pkt.data
        
        # create and send request packet
        request_pkt = pkt.RequestPacket(host.ip, host.my_assigned_ip)
        host.send_packet(request_pkt)
        
        # receive ack packet
        ack_pkt = host.receive_packet()
        if ack_pkt.mode != pkt.ACK_04: return False
        
        self.connected_devices.add_new_connection(host)
        return True
        
        
        
        
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
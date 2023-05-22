"""
The University of Queensland
Semester 1 2023 COMS3200 Assignment 2 Part C

author: Jamie Katsamatsas 
student id: 46747200

This file contains the implementation of the three types of switches outlined
in the specification.
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
from sender_receiver import SenderReceiver

HOST_IP = "127.0.0.1"
MAX_LAT_LONG = 32767
BUFFER_SIZE = 1500
READY_PACKET_TIME_LIMIT = 5

def euclidean_dist(p1: device.Device, p2: device.Device) -> int:
    """
    Returns the euclidean distance between two switches given using their 
    latitude and longitude values.

    Args:
        p1 (device.Device): first device provided
        p2 (device.Device): second device provided

    Returns:
        int: euclidean dist rounded down
    """
    return int(math.sqrt(
        (int(p1.latitude) - int(p2.latitude))**2 
        + (int(p1.longitude) - int(p2.longitude))**2))

class RUSHBSwitch:
    """
    Abstract class for the Switch that contains most of the functionality 
    shared between switch types.
    """
    def __init__(
        self, 
        switch_type: str, 
        latitude: int, 
        longitude: int, 
        local_ip_addresses_cidr: str=None, 
        global_ip_addresses_cidr: str=None
    ) -> None:
        """
        Initialises a switch

        Args:
            switch_type (str): type of switch, either "local" or "global"
            latitude (int): latitude of device
            longitude (int): longitude of device
            local_ip_addresses_cidr (str, optional): IP address range of 
            local addresses used for UDP connections in CIDR notation. 
            Defaults to None.
            global_ip_addresses_cidr (str, optional): IP address range of 
            global addresses used for TCP connection in CIDR notation. 
            Defaults to None.
        """
        # check if the arguments provided are valid
        if self.check_valid_args(
            switch_type=switch_type, 
            local_ip_addresses_cidr=local_ip_addresses_cidr, 
            global_ip_addresses_cidr=global_ip_addresses_cidr, 
            latitude=latitude, 
            longitude=longitude) == False:
            exit(1)
        
        self.type: str = switch_type
        self.latitude: int = latitude
        self.longitude: int = longitude
        
        # set up packet queues
        self.incoming_tcp_packet_queue = queue.Queue()
        self.incoming_stdin_queue = queue.Queue()
        
        self.connected_devices = ConnectedDevices()
        
        # set host ip with ipaddress.ip_network iterator
        self.global_ip = None
        self.local_ip = None
        self.set_global_ip(global_ip_addresses_cidr)
        self.set_local_ip(local_ip_addresses_cidr)
        
        self.adapter_message_queues = {}
    
    
    def check_valid_args(
        self, 
        switch_type: str, 
        local_ip_addresses_cidr: str, 
        global_ip_addresses_cidr: str, 
        latitude: int, 
        longitude: int
    ) -> bool:
        """
        Checks if the arguments given are valid according to the assignment 
        specification.

        Args:
            see RUSHBSwitch __init__ method for argument descriptions

        Returns:
            bool: True if the given arguments are valid, False otherwise
        """
        # check type is either "global" or "local"
        if switch_type in ["local", "global"] == False: return False
        
        # check ip address is valid CIDR notation
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
        
        
    def set_global_ip(self, global_ip_addresses_cidr: ipaddress.IPv4Network) -> None:
        """
        Sets the global ip address for the switch. 

        Args:
            global_ip_addresses_cidr (ipaddress.IPv4Network): CIDR notation of 
            addresses used for TCP connections.
        """
        if global_ip_addresses_cidr == None: return
        
        self.global_ip_addresses_cidr: ipaddress.ip_network = \
            ipaddress.ip_network(global_ip_addresses_cidr, strict=False)
        self.global_ip_addrs_iter = iter(self.global_ip_addresses_cidr)
        
        # start client addresses at x.x.x.1 addr
        next(self.global_ip_addrs_iter)
        self.global_ip = ipaddress.IPv4Address(global_ip_addresses_cidr.split("/")[0])

        
    def set_local_ip(self, local_ip_addresses_cidr: ipaddress.IPv4Network) -> None:
        """
        Sets the local ip address for the switch.

        Args:
            local_ip_addresses_cidr (ipaddress.IPv4Network): CIDR notation of 
            addresses used for UDP connections.
        """
        if local_ip_addresses_cidr == None: return
        
        self.local_ip_addresses_cidr: ipaddress.ip_network \
            = ipaddress.ip_network(local_ip_addresses_cidr, strict=False)
        self.local_ip_addrs_iter = iter(self.local_ip_addresses_cidr)
        
        # start client addresses at x.x.x.1 addr
        next(self.local_ip_addrs_iter)
        self.local_ip = ipaddress.IPv4Address(local_ip_addresses_cidr.split("/")[0])
        
        
    def get_global_client_ip(self) -> ipaddress.IPv4Address:
        """
        Returns the address given to the TCP client.

        Returns:
            ipaddress.IPv4Address
        """
        client_addr = next(self.global_ip_addrs_iter)
        return client_addr if client_addr != self.global_ip else next(self.global_ip_addrs_iter)
    
    
    def get_local_client_ip(self) -> ipaddress.IPv4Address:
        """
        Returns the address given to the UDP client.

        Returns:
            ipaddress.IPv4Address
        """
        client_addr = next(self.local_ip_addrs_iter)
        return client_addr if client_addr != self.local_ip else next(self.local_ip_addrs_iter)
        
        
    def start(self):
        self.setup_listening_ports()
        self.setup_command_line()
        self.run_switch()
        
        
    def setup_listening_ports(self):
        raise NotImplementedError
    
    
    def init_udp_socket(self) -> socket.socket:
        """
        Creates UDP socket used to accept incomming connections on.

        Returns:
            socket.socket: UDP socket
        """
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.bind((HOST_IP, 0))
        print(udp_socket.getsockname()[1], flush=True)
        return udp_socket
        
        
    def init_tcp_socket(self) -> socket.socket:
        """
        Creates TCP socket used to accept incomming connections on.

        Returns:
            socket.socket
        """
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_socket.bind((HOST_IP, 0))
        tcp_socket.listen()
        print(tcp_socket.getsockname()[1], flush=True)
        return tcp_socket
    
    
    def listen_udp_socket_thread(self, udp_socket: socket.socket) -> None:
        """
        Receives incoming UDP messages and adds them to the incoming 
        message queue for the client specified in the packet address.

        Args:
            udp_socket (socket.socket): UDP socket to receive from
        """
        while True:
            packet_information = udp_socket.recvfrom(2000)
            packet = packet_information[0]
            addr = packet_information[1]

            # create adapterClient instance only if client doesnt already exist
            existing_adapter = self.connected_devices.seen_adapters.get(addr)
            if existing_adapter is not None: # adapter already exists
                existing_adapter.packet_queue.put(packet)
                continue
            
            # create client and thread if they dont exist
            adapter = device.ClientAdapter(udp_socket=udp_socket, socket_addr=addr)
            adapter.packet_queue.put(packet)
            self.connected_devices.seen_adapters[addr] = adapter
            
            adapter_client_thread = threading.Thread(
                target=self.client_listen_thread,
                args=(adapter,),
                daemon=True
            )
            adapter_client_thread.start()
            print(f"CREATED UDP CLIENT THREAD: {adapter_client_thread.ident}")
            
        
    def listen_tcp_socket_thread(self, tcp_socket: socket.socket) -> None:
        """
        Accepts incoming connections on TCP and starts threads to handle the 
        connection. 

        Args:
            tcp_socket (socket.socket): TCP socket to listen on
        """
        while True:
            try:
                conn_socket, _ = tcp_socket.accept()
            except OSError:
                print("Error connecting to socket")
                return
            
            # create client connection instance
            client = device.ClientSwitch(conn_socket)
            
            # create thread to handle client incoming messages
            client_listener_thread: threading.Thread = threading.Thread(
                target=self.client_listen_thread,
                args=(client, ),
                daemon=True)
            client_listener_thread.start()
            (f"tcp socket client thread created: {client_listener_thread.ident}")
            
            
    def client_listen_thread(self, client: device.Device) -> None:
        """
        Initiates greeting protocol with clients and starts processing their 
        packets.

        Args:
            client (device.Device): client to greet and start processing 
            packets from.
        """
        if self.greeting_protocol_with_client(client) == False:
            return
        
        self.process_incoming_packets(client)

            
    def greeting_protocol_with_client(self, client: device.ClientDevice) -> bool:
        """
        Completed a greeting protocol with a client according to the assignment
        specification.

        Args:
            client (device.ClientDevice): client we are performing greeting 
            protocol with

        Returns:
            bool: True if greeting protocol succeeded, False otherwise.
        """
        discovery_packet: pkt.DiscoveryPacket = client.receive_packet()
        
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
        
        # receive request packet
        request_pkt: pkt.RequestPacket = client.receive_packet()
        
        # create and send acknowledgement packet
        ack_pkt: pkt.AcknowledgePacket = pkt.AcknowledgePacket(src_ip=src_ip, dest_ip=client.ip, assigned_ip=client.ip)
        client.send_packet(ack_pkt)
        
        self.connected_devices.add_new_connection(client)
        return True
        
            
    def setup_command_line(self):
        pass
        
        
    def create_stdin_thread(self) -> None:
        """
        Create a thread to handle commands from stdin and put into incoming 
        command queue
        """
        stdin_thread = threading.Thread(
            target=self.stdin_listener_thread,
            args=(self.incoming_stdin_queue, ),
            daemon=True)
        stdin_thread.start()
        print(f"stdin listen thread created: {stdin_thread.ident}")
        
        
    def stdin_listener_thread(self, incoming_stdin_queue: queue.Queue) -> None:
        """
        Listens on stdin for connect commands.
        
        Connect command used to connect to other switches.
        
        "connect <port>"

        Args:
            incoming_stdin_queue (queue.Queue): queue to put incoming connect 
            commands onto.
        """
        while True:
            time.sleep(0.01)
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
            
            incoming_stdin_queue.put(port)
            

    def run_switch(self) -> None:
        """
        Once the switch is set up will process all incoming packets/commands
        """
        while True:
            self.process_connect_commands()
            time.sleep(0.01)

        
    def process_connect_commands(self) -> None:
        """
        Creates TCP connections to global/mixed switches
        """
        while True:
            try:
                port = self.incoming_stdin_queue.get(block=False)
            except queue.Empty:
                return
            
            switch_socket: socket.socket = self.connect_to_switch(port)
            if switch_socket == None:
                continue
            
            # create client switch object
            print(f"creating host instance on port: {switch_socket.getsockname()}")
            host = device.HostSwitch(conn_socket=switch_socket)
            
            host_conn_thread: threading.Thread = threading.Thread(
                target=self.host_connection_thread,
                args=(host, ),
                daemon=True
            )
            host_conn_thread.start()
            print(f"created host switch thread: {host_conn_thread.ident}")
            
            
    def connect_to_switch(self, port: int) -> socket.socket:
        """
        Connects to a switch on TCP using the given port.

        Args:
            port (int): port to connect to

        Returns:
            socket.socket: TCP connection
        """
        switch_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            switch_socket.connect((HOST_IP, port))
        except ConnectionRefusedError:
            print(f"Connection refused for host {HOST_IP, port}")
            return None
        print(f"Successfully connected to tcp port: {switch_socket.getsockname()}")
        return switch_socket
    
    
    def host_connection_thread(self, host: device.HostSwitch) -> None:
        """
        Performs connection set up with a host according to the assignment 
        specification.

        Args:
            host (device.HostSwitch): connected host device
        """
        print(f"top of host connection thread socket is: {host.conn_socket.getsockname()}")
        greeting_success = self.greeting_protocol_with_host(host)
        if greeting_success == False: 
            return

        location_pkt: pkt.LOCATION_08 = pkt.LocationPacket(
            src_ip=host.my_assigned_ip, 
            dest_ip=host.ip, 
            latitude=self.latitude, 
            longitude=self.longitude
            )
        host.send_packet(location_pkt)
        self.process_incoming_packets(host)
        
                
    def process_incoming_packets(self, device: device.Device) -> None:
        """
        Processes incoming packets.

        Args:
            device (device.Device): device sending the packets.

        Raises:
            Exception: the packet receved is of an unknown type
        """
        print(f"Listening for packets from socket: {device.conn_socket}")
        while True:
            try:
                print("before getting packet")
                packet = device.receive_packet()
                print(f"got packet on thread {threading.get_ident()} for device {device.ip}")
            except ConnectionResetError:
                return
            
            if packet == None: return
            
            if packet.mode == pkt.DATA_05:
                self.handle_data_packet(sender_device=device, data_packet=packet)
            elif packet.mode == pkt.ASK_06:
                self.handle_query_packet(neighbour=device)
            elif packet.mode == pkt.READY_07:
                self.handle_ready_packet(conn_device=device, ready_packet=packet)
            elif packet.mode == pkt.LOCATION_08:
                self.handle_location_packet(conn_device=device, packet=packet)
            elif packet.mode == pkt.DISTANCE_09:
                self.handle_distance_packet(packet)
            elif packet.mode == pkt.FRAGMENT_0A or packet.data == pkt.FRAGMENT_END_0B:
                self.handle_fragments(neighbour=device, fragment_packet=packet)
            # else:
            #     raise Exception(f"Received unknown packet mode {packet.mode}...")
            print("going back to top of process_incoming_packets")
        
    
    def handle_data_packet(
        self, 
        sender_device: device.Device, 
        data_packet: pkt.DataPacket) -> None:
        """
        Handles a data packet according to the assignment spec.

        Args:
            sender_device (device.Device): device sending the packet
            data_packet (pkt.DataPacket): packet to process
        """
        # display data if intended for self
        if data_packet.dest_ip == self.local_ip or data_packet.dest_ip == self.global_ip:
            print(f"Received from {data_packet.src_ip}: {data_packet.data}")
            return
        
        # IF DATA PACKET > 1500B FRAGMENT
        if data_packet.data_size > pkt.MAX_DATA_IN_PACKET:
            data_packets = self.create_packet_fragments(data_packet)
        else:
            data_packets = [data_packet]
            
        # if packet is for someone an immediate neighbour send to them
        neighbour: device.Device = self.connected_devices.get_neighbour_with_ip(data_packet.dest_ip)
        if neighbour != None:
            self.query_neighbour_and_forward_data(data_packets, neighbour)
            return
        
        # If switch aware of dest send to switch on shortest path with longest 
        # matching ip prefix
        if data_packet.dest_ip in self.connected_devices.distance_to_devices.keys():
            paths = self.connected_devices.distance_to_devices[data_packet.dest_ip]
            if len(paths) == 1:
                neighbour = self.connected_devices.get_neighbour_with_ip(paths[0][0])
                self.query_neighbour_and_forward_data(data_packets, neighbour)
                return
            
            # get neighbour on path with greatest matching prefix of dest ip
            ips = [path[0] for path in paths]
            selected_ip = self.connected_devices.get_ip_with_longest_ip_prefix(ips, data_packet.dest_ip, sender_device.ip)
            neighbour = self.connected_devices.get_neighbour_with_ip(selected_ip)
            self.query_neighbour_and_forward_data(data_packets, neighbour)
            return
            
        # if dest ip is unknown send to neighbour with longest matching ip prefix
        ips = [device.ip for device in self.connected_devices.get_neighbours_ips()]
        print(f"neighbours: {ips}")
        selected_ip = self.connected_devices.get_ip_with_longest_ip_prefix(
            ips, data_packet.dest_ip, sender_device.ip)
        neighbour = self.connected_devices.get_neighbour_with_ip(selected_ip)
        self.query_neighbour_and_forward_data(data_packets, neighbour)
        return
    
    
    def create_packet_fragments(self, data_packet: pkt.DataPacket) -> list:
        """
        Splits up a large data packet into fragment packets.

        Args:
            data_packet (pkt.DataPacket): data packet to split

        Returns:
            list: fragments
        """
        fragments = []

        data_fragmented = 0
        while data_fragmented < data_packet.data_size:
            data_chunk_end = min(len(data_packet.data), data_fragmented + pkt.MAX_DATA_IN_PACKET)
            data_fragment = data_packet.data[data_fragmented:data_chunk_end]
            
            fragment: pkt.FragmentPacket = pkt.FragmentPacket(
                mode=pkt.FRAGMENT_0A if data_chunk_end != len(data_packet.data) else pkt.FRAGMENT_END_0B, 
                offset=data_fragmented,
                src_ip=data_packet.src_ip,
                dest_ip=data_packet.dest_ip,
                data=data_fragment)
            
            data_fragmented += pkt.MAX_DATA_IN_PACKET
            fragments.append(fragment)
            
        return fragments
    
    
    def query_neighbour_and_forward_data(
        self, 
        data_packets: list, 
        neighbour: device.Device
    ) -> None:
        """
        Modifies the src address in the packet to be the ip address the dest 
        knows self as

        Args:
            packet (pkt.DataPacket): _description_
        """
        for data_packet in data_packets:
            # check that query/ready proto has been done within 5 sec otherwise do
            # query/ready proto before actually sending the data
            if neighbour.is_ready_to_receive() == False:
                # send query packet
                query_packet: pkt.QueryPacket = pkt.QueryPacket(src_ip=self.get_my_ip_for_device(neighbour), dest_ip=neighbour.ip)
                neighbour.send_packet(query_packet)
                print(f"SENT QUERY PACKET to {neighbour.ip}:{neighbour.conn_socket}")
                print(f"ON thread: {threading.get_ident()}")
                
                # receive ready packet
                print(False)
                # ready_pkt: pkt.ReadyPacket = neighbour.receive_packet()
                print(True)
                # ready_packet = SenderReceiver.receive_packet_tcp(neighbour.conn_socket)
                while neighbour.is_ready_to_receive() == False:
                    time.sleep(0.01)
                
                # if ready_pkt.mode != pkt.READY_07:
                #     print("kdsfgjdfvghjgfvdkhfgvk")
                #     raise Exception(f"Did not receive a ready packet, got {ready_pkt.mode} instead...")
                # print(f"Got ready pkt from {neighbour.ip}")
                
                # set ready time
                # print("setting neighbour as ready to receive")
                # neighbour.set_ready_to_receive()

            neighbour.send_packet(data_packet)
        
        
    def handle_query_packet(self, neighbour: device.Device):
        ready_pkt: pkt.ReadyPacket = pkt.ReadyPacket(
            src_ip=self.get_my_ip_for_device(neighbour), dest_ip=neighbour.ip)
        neighbour.send_packet(ready_pkt)
        
    
    def handle_ready_packet(
        self, 
        conn_device: device.Device,
        ready_packet: pkt.ReadyPacket
    ) -> None:
        """
        Have received a ready packet from a neighbour. The original query 
        packet was sent to the neighbour on a different thread.

        Args:
            conn_device (device.Device): _description_
            ready_packet (pkt.ReadyPacket): _description_
        """
        conn_device.set_ready_to_receive()
        
        
    def handle_location_packet(
        self, 
        conn_device: device.Device, 
        packet: pkt.LocationPacket) -> None:
        """
        Handles location packets according to the spec.

        Args:
            conn_device (device.Device): device that sent the packet
            packet (pkt.LocationPacket): packet to process
        """
        # update distance
        conn_device.latitude = packet.data[0]
        conn_device.longitude = packet.data[1]
        device_dist = euclidean_dist(conn_device, self)
        self.connected_devices.update_distance_to_device(new_dist=device_dist , device_ip=conn_device.ip)
        
        # respond to device if they are a client
        if isinstance(conn_device, device.ClientDevice) == True:
            location_pkt: pkt.LocationPacket = pkt.LocationPacket(
                src_ip=self.global_ip, 
                dest_ip=conn_device.ip, 
                latitude=self.latitude, 
                longitude=self.longitude)
            conn_device.send_packet(location_pkt)
            
        # mixed switch sends location pkt with its UDP ip and dist to the switch
        # we just connected to in packet
        if isinstance(self, RUSHBSwitchMixed):
            loc_pkt: pkt.DistancePacket = pkt.DistancePacket(
                src_ip=self.get_my_ip_for_device(conn_device),
                dest_ip=conn_device.ip, 
                og_ip=self.local_ip, 
                dist=device_dist)
            conn_device.send_packet(loc_pkt)
    
        # create dist pkt for each neighbour and send
        neighbour: device.Device
        for neighbour in self.connected_devices.get_neighbours_ips():
            if neighbour == conn_device or isinstance(neighbour, device.ClientAdapter):
                continue

            # distance from location pkt sender to neighbour
            og_to_neighbour: int = int(device_dist) \
                + int(self.connected_devices.distance_to_devices[neighbour.ip][0][1])
            
            dist_pkt: pkt.DistancePacket = pkt.DistancePacket(
                src_ip=self.get_my_ip_for_device(neighbour),
                dest_ip=neighbour.ip, 
                og_ip=conn_device.ip, 
                dist=og_to_neighbour)
            neighbour.send_packet(dist_pkt)
            
    
    def get_my_ip_for_device(self, neighbour: device.Device) -> ipaddress.IPv4Address:
        """
        Returns the ip I am known as to the given device

        Args:
            neighbour (device.Device): neighbour we are getting our ip for

        Returns:
            ipaddress.IPv4Address: the ip we are known as to the neighbour
        """
        if isinstance(neighbour, device.ClientSwitch):
            return self.global_ip
        if isinstance(neighbour, device.ClientAdapter):
            return self.local_ip
        if isinstance(neighbour, device.HostSwitch):
            return neighbour.my_assigned_ip
            
            
    def handle_distance_packet(self, packet: pkt.DistancePacket) -> None:
        """
        Updates the distance to the client specified in the distance packet 
        according to the spec.

        Args:
            packet (pkt.DistancePacket): packet to process
        """
        dist_updated = self.connected_devices.update_distance_to_device(
            new_dist=packet.data[1], 
            device_ip=packet.data[0], 
            via_device=packet.src_ip)
        
        if dist_updated == False: return
        
        # if the distance was updated relay distance packets to all neighbours 
        # except the ip in the src field (who sent the ditance packet)
        neighbour: device.Device
        for neighbour in self.connected_devices.get_neighbours_ips():
            if neighbour.ip == packet.src_ip:
                continue
            
            src_ip = self.get_my_ip_for_device(neighbour)
            dest_ip = neighbour.ip
            dist = packet.data[1] + self.connected_devices.distance_to_devices[neighbour.ip][0][1]
            
            new_packet: pkt.DistancePacket = pkt.DistancePacket(
                src_ip=src_ip, 
                dest_ip=dest_ip, 
                og_ip=packet.data[0], 
                dist=dist)
            
            neighbour.send_packet(new_packet)

            
    def handle_fragments(
        self, 
        neighbour: device.Device, 
        fragment_packet: pkt.FragmentPacket
    ) -> None:
        """
        Handles fragment packets according to the spec.

        Args:
            neighbour (device.Device): device that sent the fragment
            fragment_packet (pkt.FragmentPacket): packet to process
        """
        # received fragment not for us, pass on like a data packet
        if fragment_packet.dest_ip != self.global_ip and fragment_packet.dest_ip != self.local_ip:
            self.handle_data_packet(neighbour, fragment_packet)
            return
        
        # fragment is for us add to list of fragments and reconstruct
        if fragment_packet.mode == pkt.FRAGMENT_0A:
            neighbour.fragments.append(fragment_packet)
            return
        elif fragment_packet.mode == pkt.FRAGMENT_END_0B:
            neighbour.fragments.append(fragment_packet)
            
            assembled_data = []
            for fragment in neighbour.fragments:
                assembled_data.append(fragment.data)
            assembled_data = "".join(assembled_data)
            
            print(f"Received from {str(fragment_packet.src_ip)}: {assembled_data}")
                
    
    def greeting_protocol_with_host(self, host: device.HostSwitch) -> bool:
        """
        Perform greeting protocol with a host device.

        Args:
            host (device.HostSwitch): host we are connected to

        Returns:
            bool: True if the greeting protocol was successful, False otherwise.
        """
        discovery_pkt = pkt.DiscoveryPacket()
        print(f"send discovery pkt to : {host.conn_socket.getsockname()}")
        
        host.send_packet(discovery_pkt)
        
        # receive offer packet: assign ip to host instance and save ip assigned to you
        offer_pkt = host.receive_packet()
        if offer_pkt.mode != pkt.OFFER_02: 
            return False
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
    def __init__(
        self, 
        switch_type: str, 
        latitude: int, 
        longitude: int, 
        local_ip_addresses_cidr: str = None, 
        global_ip_addresses_cidr: str = None
    ) -> None:
        super().__init__(
            switch_type=switch_type, 
            latitude=latitude, 
            longitude=longitude, 
            local_ip_addresses_cidr=local_ip_addresses_cidr, 
            global_ip_addresses_cidr=global_ip_addresses_cidr)
        
        
    def setup_listening_ports(self) -> None:
        # create udp socket
        udp_socket = self.init_udp_socket()
        
        # open UDP listen port for incoming adapter messages
        udp_listener_thread = threading.Thread(
            target=self.listen_udp_socket_thread,
            args=(udp_socket, ),
            daemon=True)
        udp_listener_thread.start()
        print(f"SETTING UP LOCAL SWITCH PORTS on thread: {udp_listener_thread.ident}")
        return
    
    
    def setup_command_line(self) -> None:
        self.create_stdin_thread()


class RUSHBSwitchMixed(RUSHBSwitch):
    def __init__(
        self, 
        switch_type: str, 
        latitude: int, 
        longitude: int, 
        local_ip_addresses_cidr: str = None, 
        global_ip_addresses_cidr: str = None
    ) -> None:
        super().__init__(
            switch_type=switch_type, 
            latitude=latitude, 
            longitude=longitude, 
            local_ip_addresses_cidr=local_ip_addresses_cidr, 
            global_ip_addresses_cidr=global_ip_addresses_cidr)
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
        print("SETTING UP MIXED SWITCH PORTS")
        

class RUSHBSwitchGlobal(RUSHBSwitch):
    def __init__(
        self, 
        switch_type: str, 
        latitude: int, 
        longitude: int, 
        local_ip_addresses_cidr: str = None, 
        global_ip_addresses_cidr: str = None
    ) -> None:
        super().__init__(
            switch_type=switch_type, 
            latitude=latitude, 
            longitude=longitude, 
            local_ip_addresses_cidr=local_ip_addresses_cidr,
            global_ip_addresses_cidr=global_ip_addresses_cidr)
        
        
    def setup_listening_ports(self):
        #################### SET UP TCP LISTENER FOR SWITCHES
        tcp_socket = self.init_tcp_socket()
        print(f"global conn on tcp soc:{tcp_socket.getsockname()}:{tcp_socket}")
        tcp_listener_thread = threading.Thread(
            target=self.listen_tcp_socket_thread,
            args=(tcp_socket, ),
            daemon=True)
        tcp_listener_thread.start()
        print(f"main thread: {threading.get_ident()}")
        print(f"SETTING UP GLOBAL SWITCH PORTS on thread: {tcp_listener_thread.ident}")
        
        
    def setup_command_line(self):
        self.create_stdin_thread()
        
        
########################## FUNCTIONS WITHOUT CLASSES
def process_arguments():
    """
    Checks if the provided command line arguments are valid. Exits if not
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
    
    exit(1)
    
    
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
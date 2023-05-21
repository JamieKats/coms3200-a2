"""
The University of Queensland
Semester 1 2023 COMS3200 Assignment 2 Part C

author: Jamie Katsamatsas 
student id: 46747200

This file contains collections used to store hosts and clients connected to the 
switch, and methods that act on these collections.
"""
import device
import ipaddress

class ConnectedDevices:
    def __init__(self) -> None:
        self.hosts = []
        self.clients = []
        self.distance_to_devices = {} # dist to neighbours and known non neighbours
        
        # map of seen addresses to their adapters, used to pass adapter packets
        # to the correct adapter before they have been given their ip
        self.seen_adapters: dict = {}
    
    
    def add_new_connection(self, new_device: device.Device) -> None:
        """
        Adds the given device to the client or host list it belongs in.
        
        Args:
            new_device (device.Device): Device to add to the host or clients 
            lists
        """
        if isinstance(new_device, device.ClientDevice):
            self.clients.append(new_device)
        if isinstance(new_device, device.HostSwitch):
            self.hosts.append(new_device)


    def get_udp_client_with_addr(self, addr: tuple) -> device.ClientAdapter:
        """
        Gets the udp client from the list of clients that has the address given.

        Args:
            addr (tuple): UDP address of the client to return

        Returns:
            device.ClientAdapter: Adapter instance that has the addr given. None
            if it doesn't exist.
        """
        for client in self.clients:
            if isinstance(client, device.ClientAdapter) and client.socket_addr == addr:
                return client
        return None
    
    
    def update_distance_to_device(
        self, 
        new_dist: int,
        device_ip: ipaddress.IPv4Address, 
        via_device:ipaddress.IPv4Address=None
    ) -> bool:
        """
        Updates the collection of shortest known distances to known ips.
        
        If the given distance is shorter than or equal to the currently known 
        distance the new distance is saved. Otherwise ignored. 

        Args:
            new_dist (int): distance to the given device
            device_ip (ipaddress.IPv4Address): device to which we are given a 
            distance to
            via_device (ipaddress.IPv4Address, optional): Device along the 
            shortest distance to the device we are saving. Defaults to None.

        Returns:
            bool: True if the distance given was added to the list of known 
            shortest paths. False otherwise.
        """
        # if device not currently known add to list without any further checks
        if device_ip not in self.distance_to_devices.keys():
            self.distance_to_devices[device_ip] = [(via_device, new_dist)]
            return True
        
        # get list of current paths with same length, can be multiple but will
        # be one most of the time
        known_paths: list = self.distance_to_devices[device_ip]
        
        # if current known path is shorter than the new distance or the new 
        # distance is > 1000 return early
        if new_dist > known_paths[0][1] or new_dist > 1000:
            return False
        
        # if new dist is same as current dist, append to list of paths
        if new_dist == known_paths[0][1]:
            self.distance_to_devices[device_ip].append((via_device, new_dist))
            return True
        
        # if new dist is shorter than current paths update paths
        self.distance_to_devices[device_ip] = [(via_device, new_dist)]
        return True
            
            
    def get_neighbours_ips(self) -> list:
        """
        Return the known host and client neighbours.

        Returns:
            list: host and client neighbours
        """
        return self.hosts + self.clients
    
    
    def get_neighbour_with_ip(self, ip: ipaddress.IPv4Address) -> device.Device:
        """
        Returns the neighbour device instance that has the ip given.

        Args:
            ip (ipaddress.IPv4Address): ip of device to return

        Returns:
            device.Device: device with the matching ip
        """
        host: device.Device
        for host in self.hosts:
            if host.ip == ip:
                return host
        
        client: device.Device
        for client in self.clients:
            if client.ip == ip:
                return client
        
        return None
    
    def get_ip_with_longest_ip_prefix(
        self, 
        ips: list, 
        dest_ip: ipaddress.IPv4Address, 
        src_ip: ipaddress.IPv4Address
    ) -> ipaddress.IPv4Address:
        """
        Returns the ip that has the longest matching prefix of bytes to the 
        given ip from the provided list of ips.
        
        The ip addresses are converted to bit format and the ip that has the 
        longest prefixed bits matching is returned.
        
        Args:
            ips (list): list of ips to do prefix matching on
            dest_ip (ipaddress.IPv4Address): ip to do prefix matching against
            src_ip (ipaddress.IPv4Address): source ip of the packet we are 
            matching against

        Returns:
            ipaddress.IPv4Address: ip address with the longest ip prefix match.
        """
        dest_ip_bin = bin(int(dest_ip))
        
        # initialise longest_matching_path as the first
        longest_matching_path_ip = (ips[0], 0)
        
        for ip in ips:
            # dont count the src ip
            if ip == src_ip: continue
            
            count = 0
            neighbour_ip_bin = bin(int(ip))
            
            for i in range(len(neighbour_ip_bin)):
                if dest_ip_bin[i] != neighbour_ip_bin[i]: break
                
                count += 1
            if count > longest_matching_path_ip[1]:
                longest_matching_path_ip = (ip, count)
            
        return longest_matching_path_ip[0]
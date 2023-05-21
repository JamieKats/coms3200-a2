"""
Stores mappings of all connected clients and hosts to group together all 
functionality involving: 
    - finding hosts/clients
    - storing distances to devices
    - prefix matching ip in a packets with known ips
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
    
    def add_new_connection(self, new_device: device.Device):
        """
        NOTE At time this method is called the new_device may not have had an ip assigned yet

        Args:
            new_device (device.Device): _description_
        """
        print(new_device.__class__)
        if isinstance(new_device, device.ClientDevice):
            self.clients.append(new_device)
        if isinstance(new_device, device.HostSwitch):
            self.hosts.append(new_device)

    def get_udp_client_with_addr(self, addr):
        for client in self.clients:
            # print(isinstance(client, device.ClientAdapter))
            if isinstance(client, device.ClientAdapter) and client.socket_addr == addr:
                return client
        return None
    
    def update_distance_to_device(
        self, 
        new_dist: int,
        device_ip: ipaddress.IPv4Address, 
        via_device:ipaddress.IPv4Address=None
    ) -> bool:
        if device_ip not in self.distance_to_devices.keys():
            self.distance_to_devices[device_ip] = [(via_device, new_dist)]
            # print(f"conn devices: added device info to known distances: {device_ip} -> {self.distance_to_devices[device_ip]}")
            return True
        
        # get list of current paths with same length, can be multiple but will
        # be one most of the time
        current_paths: list = self.distance_to_devices[device_ip]
        
        if new_dist > current_paths[0][1] or new_dist > 1000:
            return False
        
        # if new dist is same as current dist, append to list of paths
        if new_dist == current_paths[0][1]:
            self.distance_to_devices[device_ip].append((via_device, new_dist))
            # print(f"conn devices: updated device info in known distances: {device_ip} -> {self.distance_to_devices[device_ip]}")
            return True
        
        self.distance_to_devices[device_ip] = (via_device, new_dist)
        return True
        # print(f"conn devices: updated device info in known distances: {device_ip} -> {self.distance_to_devices[device_ip]}")
            
            
    def get_neighbours_ips(self):
        print(f"hosts: {[x.ip for x in self.hosts]}")
        print(f"clients: {[x.ip for x in self.clients]}")
        return self.hosts + self.clients
    
    
    def get_neighbour_with_ip(self, ip: ipaddress.IPv4Address):
        host: device.Device
        for host in self.hosts:
            if host.ip == ip:
                return host
        
        client: device.Device
        for client in self.clients:
            if client.ip == ip:
                return client
        
        return None
    
    def get_ip_with_longest_ip_prefix(self, ips: list, dest_ip: ipaddress.IPv4Address, src_ip: ipaddress.IPv4Address):
        dest_ip_bin = bin(int(dest_ip))
        
        # initialise longest_matching_path as the first
        longest_matching_path_ip = (ips[0], 0)
        
        for ip in ips:
            # dont count the src ip
            if ip == src_ip: continue
            
            print(f"checking ip: {ip}")
            count = 0
            neighbour_ip_bin = bin(int(ip))
            
            for i in range(len(neighbour_ip_bin)):
                if dest_ip_bin[i] != neighbour_ip_bin[i]: break
                
                count += 1
            print(f"{ip} count {count}")
            if count > longest_matching_path_ip[1]:
                longest_matching_path_ip = (ip, count)
            
        print(f"longest matching ip: {longest_matching_path_ip[0]}")
        return longest_matching_path_ip[0]
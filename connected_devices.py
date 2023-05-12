"""
Stores mappings of all connected clients and hosts to group together all 
functionality involving: 
    - finding hosts/clients
    - storing distances to devices
    - prefix matching ip in a packets with known ips
"""
import device

class ConnectedDevices:
    def __init__(self) -> None:
        self.hosts = []
        self.clients = []
        self.distance_to_devices = {} # dist to neighbours and known non neighbours
    
    def add_new_connection(self, new_device: device.Device):
        """
        NOTE At time this method is called the new_device may not have had an ip assigned yet

        Args:
            new_device (device.Device): _description_
        """
        if isinstance(new_device, device.ClientDevice):
            self.clients.append(new_device)
        if isinstance(new_device, device.HostSwitch):
            self.hosts.append(new_device)

    def get_udp_client_with_addr(self, addr):
        for client in self.clients:
            if isinstance(client, device.ClientAdapter) and client.socket_addr == addr:
                return client
        return None
    
    def update_distance_to_device(self, new_dist: int, device_ip: int, via_device:int=None):
        if device_ip not in self.distance_to_devices.keys():
            self.distance_to_devices[device_ip] = (via_device, new_dist)
            print(f"conn devices: added device info to known distances: {device_ip} -> {self.distance_to_devices[device_ip]}")
            return
        
        # check if device current distance is < currently saved
        current_dist = self.distance_to_devices[device_ip]
        
        if new_dist < current_dist and new_dist <= 1000:
            self.distance_to_devices[device_ip] = (via_device, new_dist)
            print(f"conn devices: updated device info in known distances: {device_ip} -> {self.distance_to_devices[device_ip]}")
            
    def get_neighbours(self):
        return self.hosts + self.clients
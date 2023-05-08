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
        self.hosts = {}
        self.clients = {}
    
    def add_new_connection(self, new_device: device.Device):
        if isinstance(new_device, device.ClientDevice):
            self.clients[new_device.client_ip] = new_device
        if isinstance(new_device, device.HostSwitch):
            self.hosts[new_device.host_ip] = new_device

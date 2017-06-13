import socket

from asciimatics.widgets import MultiColumnListBox, Widget

from Project.config import SW_VERSION
from arrow import utcnow

from SnifferAPI.Devices import Device


class Client():
    def __init__(self,):
        self.IP, self.host = self.get_connection_information()
        self.firmware_version = None
        self.software_version = SW_VERSION
        self.port = None
        self.missed_packets = None
        self.online_since = str(utcnow())

    def to_JSON(self):
        data  = self.__dict__.copy()
        return data

    def update_client_with_sniffer(self, sniffer):
        self.firmware_version = sniffer.fwversion
        self.port = str(sniffer.portnum)
        self.missed_packets = sniffer.missedPackets
        return self

    def get_connection_information(self):
        testIP = "8.8.8.8"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((testIP, 0))
        ipaddr = s.getsockname()[0]
        host = socket.gethostname()
        return ipaddr, host

    def get_client_info(self):
        client_options = []
        items = 0
        for client_info_key, client_info_value in self.__dict__.items():
            items += 1
            client_options.append(([client_info_key, str(client_info_value)], items))
        return client_options

    def get_client_widget(self):
        return (
        MultiColumnListBox(
            Widget.FILL_FRAME,
            columns=["<50%", "<50%"],
            label=None,
            name="client_info_view",
            options=self.get_client_info(),
        ))

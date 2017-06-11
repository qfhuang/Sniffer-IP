import json
import socket

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

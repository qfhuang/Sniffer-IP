import json
import os
import logging
import copy

import arrow

from Project.shared import get_direction, get_Address
from Project.config import *

def initialize_logging_to_Filebeat():
    log_file = os.path.join("Logs", LOG_FILE_NAME)
    logger = logging.getLogger(BLE_PACKETS_LOGGER)
    logger.setLevel(LOG_LEVEL)
    logger.propagate = False
    handler = logging.handlers.TimedRotatingFileHandler(log_file,
                                       when=LOG_FILE_TIME_BASE,
                                       interval=1,
                                       backupCount=CLEAN_UP_INTERVAL,
                                       utc=True)
    logger.addHandler(handler)


class BLEPacket():
    """
    This class prepares part of the data so that it will be stored as a JSON and will
    then be searchable on the web site with logs.
    """
    def __init__(self, packet, args=None, **kwargs):
        self.timestamp = str(arrow.utcnow())
        self.RSSI = packet.RSSI
        self.channel = packet.channel
        self.direction = get_direction(packet.direction)
        self.headerLength = packet.headerLength
        self.payloadLength = packet.payloadLength
        self.header = packet.packetList[:6]
        self.header = packet.payload
        self.CRC = packet.crcOK
        self._blePacket = packet.blePacket

        if self._blePacket:
            self.address = self._get_address(self._blePacket.advAddress)
            self.deviceName = self._blePacket.name
            self.BLEPayload = self._blePacket.payload
            self.PDULength = self._blePacket.length

        self.args = args
        self.kwargs = kwargs

    def to_JSON(self):
        if self.kwargs:
            dict_copy = copy.deepcopy(self.__dict__)
            del dict_copy['_blePacket']
            optional = dict_copy.pop('kwargs')
            data = optional.copy()
            data.update(dict_copy)
        else:
            data  = self.__dict__.copy()
            del data['_blePacket']
            del data['kwargs']

        if not self.args:
            del data['args']
        try:
            return json.dumps(data, sort_keys=True)
        except Exception as e:
            for key, value in data.items():
                print("{}:{} Type:{}".format(key, value, type(value)))
                raise e

    def _get_address(self, address):
        return get_Address(address[0:-1])


class BLEAdvPacket(BLEPacket):
    """
    This class prepares part of the data so that it will be stored as a JSON and will
    then be searchable on the web site with logs.
    """
    def __init__(self, packet, args=None, **kwargs):
        super().__init__(packet, args, **kwargs)
        if self._blePacket:
            self.advType = self._blePacket.payload
            self.advAddress = self._get_address(self._blePacket.advAddress)


class BLEConnPacket(BLEPacket):
    """
    This class prepares part of the data so that it will be stored as a JSON and will
    then be searchable on the web site with logs.
    """
    def __init__(self, packet, packet_num, args=None, **kwargs):
        super().__init__(packet, args, **kwargs)
        self.address = self._get_address(packet)
        self.PDUType = packet.blePacket.advType

    def _get_address(self, packet):
        return get_Address(packet.blePacket.advAddress[0:-1])
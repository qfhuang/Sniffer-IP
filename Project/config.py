import sys

from logging import INFO, ERROR

SW_VERSION = "1.0-beta"

SNIFFER_PORT_KEYWORD_SEARCH = "USB"
if sys.platform == 'win32':
    SNIFFER_PORT_KEYWORD_SEARCH = "Serial"

DEBUG = False
SAVE_TO_PCAP = False
SAVE_TO_FILEBEAT = True

SETUP_DELAY = 6 #in sec
SETUP_RETRY = 30 #in sec
SEND_CLIENT_STATUS_INTERVAL = 60*5 #in sec

#Logging Packets Settings
BLE_PACKETS_LOGGER = 'BLE Packets Log'
PACKETS_LOG_FILE_NAME = "ble_packets.log"
PACKETS_LOG_LEVEL = INFO
PACKETS_LOG_FILE_TIME_BASE = 'midnight'
PACKETS_CLEAN_UP_INTERVAL = 15 #log clean up interval in days

#Logging Service Settings
SERVICE_LOGGER = 'Service Log'
SERVICE_LOG_FILE_NAME = "ble_service.log"
SERVICE_LOG_LEVEL = INFO
SERVICE_LOG_FILE_TIME_BASE = 'midnight'
SERVICE_CLEAN_UP_INTERVAL = 30 #log clean up interval in days

#Logging Scheduler Settings
SCHEDULER_LOGGER = "Scheduler Log"
SCHEDULER_LOG_FILE_NAME = "scheduler.log"
SCHEDULER_LOG_LEVEL = ERROR
SCHEDULER_LOG_FILE_TIME_BASE = 'midnight'
SCHEDULER_LOG_CLEAN_UP_INTERVAL = 1 #log clean up interval in days

#PCAP
PCAP_FILE_DIRECTORY = "pcap_log"

#UI
UPDATE_SCREEN_INTERVAL = 6 #in sec
SCAN_DEVICES_INTERVAL = 8 #in sec
from logging import INFO

SW_VERSION = "1.0-beta"
SNIFFER_PORT_KEYWORD_SEARCH = "Serial Port"

SAVE_TO_PCAP = False
SAVE_TO_FILEBEAT = True


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

#UI
UPDATE_SCREEN_INTERVAL = 6 #in sec
SCAN_DEVICES_INTERVAL = 8 #in sec
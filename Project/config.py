from logging import INFO

SAVE_TO_PCAP = False
SAVE_TO_FILEBEAT = True


#Logging Settings
BLE_PACKETS_LOGGER = 'BLE Packets Log'
LOG_FILE_NAME = "ble_packets.log"
LOG_LEVEL = INFO
LOG_FILE_TIME_BASE = 'midnight'
CLEAN_UP_INTERVAL = 30 #log clean up interval in days
import os
import logging

from pythonjsonlogger import jsonlogger

from Project.config import *


class ServiceFilter(logging.Filter):
    def __init__(self, client):
        super().__init__()
        self.client = client

    def filter(self, record):
        record.client = self.client.to_JSON()
        return True


def initialize_packets_logging_to_Filebeat():
    log_file = os.path.join("Logs", PACKETS_LOG_FILE_NAME)
    logger = logging.getLogger(BLE_PACKETS_LOGGER)
    logger.setLevel(PACKETS_LOG_LEVEL)
    stream_handler = logging.StreamHandler(stream=None)
    logger.propagate = False
    handler = logging.handlers.TimedRotatingFileHandler(log_file,
                                       when=PACKETS_LOG_FILE_TIME_BASE,
                                       interval=1,
                                       backupCount=PACKETS_CLEAN_UP_INTERVAL,
                                       utc=True)
    logger.addHandler(handler)
    logger.addHandler(stream_handler)

def initialize_service_logging(client):
    log_file = os.path.join("Logs", SERVICE_LOG_FILE_NAME)
    logger = logging.getLogger(SERVICE_LOGGER)
    logger.addFilter(ServiceFilter(client))
    logger.setLevel(SERVICE_LOG_LEVEL)
    logger.propagate = False
    stream_handler = logging.StreamHandler(stream=None)
    handler = logging.handlers.TimedRotatingFileHandler(log_file,
                                       when=SERVICE_LOG_FILE_TIME_BASE,
                                       interval=1,
                                       backupCount=SERVICE_CLEAN_UP_INTERVAL,
                                       utc=True)
    format_str = '%(message)%(levelname)%(name)%(asctime)%(client)'
    formatter = jsonlogger.JsonFormatter(format_str, '%Y-%m-%dT%H:%M:%S')
    handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    logger.addHandler(handler)


def initialize_scheduler_logging():
    log_file = os.path.join("Logs", SCHEDULER_LOG_FILE_NAME)
    logger = logging.getLogger(SCHEDULER_LOGGER)
    logger.setLevel(SCHEDULER_LOG_LEVEL)
    logger.propagate = False
    stream_handler = logging.StreamHandler(stream=None)
    handler = logging.handlers.TimedRotatingFileHandler(log_file,
                                                        when=SCHEDULER_LOG_FILE_TIME_BASE,
                                                        interval=1,
                                                        backupCount=SCHEDULER_LOG_CLEAN_UP_INTERVAL,
                                                        utc=True)
    format_str = '%(message)%(levelname)%(name)%(asctime)'
    formatter = jsonlogger.JsonFormatter(format_str, '%Y-%m-%dT%H:%M:%S')
    handler.setFormatter(formatter)
    logger.addFilter(stream_handler)
    logger.addHandler(handler)

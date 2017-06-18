import os
import logging

import arrow
from pythonjsonlogger import jsonlogger

from Project.config import *


class CustomJsonFormatter(jsonlogger.JsonFormatter):

    def process_log_record(self, log_record):
        del(log_record['asctime'])
        log_record["timestamp"] = arrow.utcnow()
        return jsonlogger.JsonFormatter.process_log_record(self, log_record)


class ServiceFilter(logging.Filter):
    def __init__(self, client):
        super().__init__()
        self.client = client

    def filter(self, record):
        record.client = self.client.to_JSON()
        return True


def initialize_packets_logging_to_Filebeat():
    log_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), "Logs", PACKETS_LOG_FILE_NAME)
    logger = logging.getLogger(BLE_PACKETS_LOGGER)
    logger.setLevel(PACKETS_LOG_LEVEL)
    handler = logging.handlers.TimedRotatingFileHandler(log_file,
                                       when=PACKETS_LOG_FILE_TIME_BASE,
                                       interval=1,
                                       backupCount=PACKETS_CLEAN_UP_INTERVAL,
                                       utc=True)

    stream_handler = logging.StreamHandler(stream=None)
    stream_handler.setLevel(logging.CRITICAL)

    logger.addHandler(handler)
    logger.addHandler(stream_handler)
    logger.propagate = False

def initialize_service_logging(client):
    log_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), "Logs", SERVICE_LOG_FILE_NAME)
    logger = logging.getLogger(SERVICE_LOGGER)
    logger.addFilter(ServiceFilter(client))
    logger.setLevel(SERVICE_LOG_LEVEL)
    handler = logging.handlers.TimedRotatingFileHandler(log_file,
                                       when=SERVICE_LOG_FILE_TIME_BASE,
                                       interval=1,
                                       backupCount=SERVICE_CLEAN_UP_INTERVAL,
                                       utc=True)
    format_str = '%(message)%(levelname)%(name)%(asctime)%(client)'
    formatter = CustomJsonFormatter(format_str, '%Y-%m-%dT%H:%M:%S')
    handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler(stream=None)
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(logging.CRITICAL)

    logger.addHandler(handler)
    logger.addHandler(stream_handler)
    logger.propagate = False


def initialize_scheduler_logging():
    log_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), "Logs", SCHEDULER_LOG_FILE_NAME)
    logger = logging.getLogger(SCHEDULER_LOGGER)
    logger.setLevel(SCHEDULER_LOG_LEVEL)

    handler = logging.handlers.TimedRotatingFileHandler(log_file,
                                                        when=SCHEDULER_LOG_FILE_TIME_BASE,
                                                        interval=1,
                                                        backupCount=SCHEDULER_LOG_CLEAN_UP_INTERVAL,
                                                        utc=True)
    format_str = '%(message)%(levelname)%(name)%(asctime)'
    formatter = CustomJsonFormatter(format_str, '%Y-%m-%dT%H:%M:%S')
    handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler(stream=None)
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(logging.CRITICAL)

    logger.addHandler(handler)
    logger.addHandler(stream_handler)
    logger.propagate = False

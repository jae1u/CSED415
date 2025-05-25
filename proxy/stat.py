import logging
from multiprocessing import Lock, Value

logger = logging.getLogger(__name__)

total_sent_proxy = Value('i', 0)
total_received_proxy = Value('i', 0)
total_sent_snic = Value('i', 0)
total_received_snic = Value('i', 0)

# from https://stackoverflow.com/a/43750422
def human_size(bytes, units=[' bytes','KB','MB','GB','TB', 'PB', 'EB']):
    """ Returns a human readable string representation of bytes """
    return str(bytes) + units[0] if bytes < 1024 else human_size(bytes>>10, units[1:])

def increase_total_sent_proxy(by: int):
    global total_sent_proxy
    with total_sent_proxy.get_lock():
        total_sent_proxy.value += by

def increase_total_received_proxy(by: int):
    global total_received_proxy
    with total_received_proxy.get_lock():
        total_received_proxy.value += by

def increase_total_sent_snic(by: int):
    global total_sent_snic
    with total_sent_snic.get_lock():
        total_sent_snic.value += by

def increase_total_received_snic(by: int):
    global total_received_snic
    with total_received_snic.get_lock():
        total_received_snic.value += by


def log_stats():
    logger.info(f"total_sent_proxy = {human_size(total_sent_proxy.value)}")
    logger.info(f"total_received_proxy = {human_size(total_received_proxy.value)}")
    logger.info(f"total_sent_snic = {human_size(total_sent_snic.value)}")
    logger.info(f"total_received_snic = {human_size(total_received_snic.value)}")



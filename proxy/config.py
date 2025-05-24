import logging
import tomllib
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

@dataclass
class Config:
    host: str = '127.0.0.1'
    port: int = 11556
    cert_file: str = './proxy/rootCA.crt'
    key_file: str = './proxy/rootCA.key'
    dns_server_addr: str = '1.1.1.1'
    dns_server_port: int = 53
    proxy_addr: str = '127.0.0.1'
    proxy_port: int = 10808
    fetch_adaptive_snic_timeout: int = 3
    fetch_adaptive_snic_works_override: dict[str, bool] = field(default_factory=dict)

conf = Config()

def configure_from_file(path: str):
    if path is not None:
        with open(path, "rb") as f:
            conf_override = tomllib.load(f)
    else:
        conf_override = {}

    global conf
    for k, v in conf_override.items():
        setattr(conf, k, v)

    logger.log(logging.DEBUG, f"config: {conf}")

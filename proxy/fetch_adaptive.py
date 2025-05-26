# adaptive fetching:
#   - try SNIC, falling back to fetch_proxy() if it times out
#   - record hosts that fetch_snic() works with

import asyncio
import logging
from typing import Optional
from urllib.parse import urlparse
from threading import Lock
from time import time

from proxy import dns
from proxy.config import conf
from proxy.interface import Request, Response
from proxy.fetch_proxy import fetch as fetch_proxy
from proxy.fetch_snic import fetch as fetch_snic, SNICConnection

logger = logging.getLogger(__name__)

snic_works: dict[str, bool] = dict()
lock_snic_works = Lock()

def record_snic_works(host: str, result: bool):
    with lock_snic_works:
        if host not in snic_works:
            snic_works[host] = result

def check_snic_works(host: str) -> Optional[bool]:
    # check override in config
    if host in conf.fetch_adaptive_snic_works_override:
        return conf.fetch_adaptive_snic_works_override[host]
    if host in snic_works:
        return snic_works[host]
    return None

def fetch(req: Request, proxy_config: tuple[str, int]) -> Response:
    url = urlparse(req.url)
    assert url.hostname is not None

    # check if host is already checked
    if (use_snic := check_snic_works(url.hostname)) is not None:
        if use_snic:
            logger.log(logging.INFO, f"{url.hostname}: using SNIC (already checked)")
            return fetch_snic(req, proxy_config)
        else:
            logger.log(logging.INFO, f"{url.hostname}: using proxy (already checked)")
            return fetch_proxy(req, proxy_config)
    
    # try SNIC
    timeout = conf.fetch_adaptive_snic_timeout
    assert url.hostname is not None
    dns_server_config = (conf.dns_server_addr, conf.dns_server_port)
    ip = asyncio.run(dns.resolve(url.hostname, dns_server_config, proxy_config))
    conn = SNICConnection(url.hostname, (ip, 443), proxy_config)
    start = time()
    if asyncio.run(conn.connect(timeout)):
        timeout -= time() - start
        if asyncio.run(conn.check_migration(timeout)):
            # use SNIC to fetch result
            logger.log(logging.INFO, f"{url.hostname}: path migration successful, using SNIC")
            record_snic_works(url.hostname, True)
            res = asyncio.run(conn.fetch(req))
            assert isinstance(res, Response)
            asyncio.run(conn.close())
            return res
        else:
            logger.log(logging.WARN, f"{url.hostname}: path migration failed, falling back to proxy")
    else:
        logger.log(logging.WARN, f"{url.hostname}: QUIC connection failed, falling back to proxy")
    asyncio.run(conn.close())
        
    # use fetch_proxy as fallback method
    record_snic_works(url.hostname, False)
    return fetch_proxy(req, proxy_config)


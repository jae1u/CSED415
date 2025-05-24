# adaptive fetching:
#   - try SNIC, falling back to fetch_proxy() if it times out
#   - record hosts that fetch_snic() works with

import asyncio
from urllib.parse import urlparse
from threading import Lock
from time import time

from proxy import dns
from proxy.interface import Request, Response
from proxy.fetch_proxy import fetch as fetch_proxy
from proxy.fetch_snic import fetch as fetch_snic, SNICConnection

snic_works: dict[str, bool] = dict()
lock_snic_works = Lock()

def record_snic_works(host: str, result: bool):
    with lock_snic_works:
        if host not in snic_works:
            snic_works[host] = result

def fetch(req: Request, proxy_config: tuple[str, int]) -> Response:
    url = urlparse(req.url)

    # check if host is already checked
    if url.hostname in snic_works:
        if snic_works[url.hostname]:
            print(f"using SNIC for {url.hostname} (already checked)")
            return fetch_snic(req, proxy_config)
        else:
            print(f"using proxy for {url.hostname} (already checked)")
            return fetch_proxy(req, proxy_config)
    
    # try SNIC
    timeout = 3
    assert url.hostname is not None
    ip = asyncio.run(dns.resolve(url.hostname, ("1.1.1.1", 53), proxy_config))
    conn = SNICConnection(url.hostname, (ip, 443), proxy_config)
    start = time()
    if asyncio.run(conn.connect(timeout)):
        timeout -= time() - start
        if asyncio.run(conn.check_migration(timeout)):
            # use SNIC to fetch result
            print(f"using SNIC for {url.hostname}")
            record_snic_works(url.hostname, True)
            res = asyncio.run(conn.fetch(req))
            assert isinstance(res, Response)
            asyncio.run(conn.close())
            return res
        else:
            print("path migration failed")
    else:
        print("QUIC connection failed")
    asyncio.run(conn.close())
        
    # use fetch_proxy as fallback method
    print(f"using proxy for {url.hostname}")
    record_snic_works(url.hostname, False)
    return fetch_proxy(req, proxy_config)


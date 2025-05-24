import asyncio
import ssl
import socks
import h11
from proxy import dns
from typing import cast
from urllib.parse import urlparse

from proxy.config import conf
from proxy.interface import Request, Response


def fetch(req: Request, proxy_config: tuple[str, int]) -> Response:
    print(f"> {req.method} {req.url}")

    # resolve hostname into ip
    url = urlparse(req.url)
    assert url.hostname is not None
    dns_server_config = (conf.dns_server_addr, conf.dns_server_port)
    ip = asyncio.run(dns.resolve(url.hostname, dns_server_config, proxy_config))
    port = 443 if url.port is None else url.port
    
    # prepare socket and connection
    ctx = ssl.create_default_context()
    sock = socks.create_connection(
        (ip, port), 
        proxy_type=socks.SOCKS5, 
        proxy_addr=proxy_config[0], 
        proxy_port=proxy_config[1]
    )
    sock = ctx.wrap_socket(sock, server_hostname=url.hostname)
    conn = h11.Connection(our_role=h11.CLIENT)

    # send request
    headers = {
        b'Host': url.hostname.encode(),
        b'User-Agent': b'snic/0.1',
        b'Accept': b'*/*',
        **req.header
    }
    target = url.path
    if len(url.query) > 0:
        target += '?' + url.query
    request = h11.Request(
        method=req.method,
        headers=list(headers.items()),
        target=target
    )
    sock.sendall(conn.send(request))
    
    # send request body if exists
    if req.body is not None:
        body = h11.Data(req.body)
        sock.sendall(conn.send(body))
    
    # end of request
    sock.sendall(conn.send(h11.EndOfMessage()))

    # receive response
    response = None
    body_parts = []
    while True:
        event = conn.next_event()
        if event is h11.NEED_DATA:
            conn.receive_data(sock.recv(1024))
        elif isinstance(event, h11.Response):
            response = event
        elif isinstance(event, h11.Data):
            body_parts.append(event.data)
        elif isinstance(event, h11.EndOfMessage):
            break
    response = cast(h11.Response, response)

    # close socket
    sock.close()
    res = Response(
        status_code=response.status_code,
        url=req.url,
        headers={k: v for k, v in response.headers},
        req_id=req.req_id,
        body=bytes().join(body_parts)
    )
    print(f"< {res.status_code} {res.url}")

    return res


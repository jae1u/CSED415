import asyncio
import ssl
import socks
import h11
from typing import cast
from urllib.parse import urlparse

from proxy import dns, stat
from proxy.config import conf
from proxy.interface import Request, Response


def fetch(req: Request, proxy_config: tuple[str, int]) -> Response:
    total_sent = 0
    total_received = 0
    
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
    data = conn.send(request)
    sock.sendall(data)
    total_sent += len(data)
    
    # send request body if exists
    if req.body is not None:
        body = h11.Data(req.body)
        data = conn.send(body)
        sock.sendall(data)
        total_sent += len(data)
    
    # end of request
    data = conn.send(h11.EndOfMessage())
    sock.sendall(data)
    total_sent += len(data)

    # receive response
    response = None
    body_parts = []
    while True:
        event = conn.next_event()
        if event is h11.NEED_DATA:
            data = sock.recv(65535)
            total_received += len(data)
            conn.receive_data(data)
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

    stat.increase_total_received_proxy(total_received)
    stat.increase_total_sent_proxy(total_sent)
    return res


import logging
import asyncio
import multiprocessing
import socket
import socks
from time import time
from urllib.parse import urlparse
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
import aioquic.quic.events
import aioquic.h3.events
import queue
from typing import Optional, cast

from proxy import dns
from proxy.config import conf
from proxy.interface import Request, Response

logger = logging.getLogger(__name__)

def quic_loop(
    req_q: multiprocessing.Queue, 
    res_q: multiprocessing.Queue,
    evt_connected,
    evt_migrated,
    evt_terminate,
    hostname: str, 
    dst_addr: tuple[str, int], 
    proxy_addr: str, 
    proxy_port: int,
):
    # create socks UDP socket
    sock_proxy = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_proxy.set_proxy(proxy_type=socks.SOCKS5, addr=proxy_addr, port=proxy_port)
    sock_proxy.setblocking(False)

    # create underlying UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', 0))
    sock.setblocking(False)

    # create QUIC and H3 connection
    quic_config = QuicConfiguration(
        alpn_protocols=["h3"], 
        is_client=True,
        server_name=hostname,
        secrets_log_file=open("keylog", "w")
    )
    quic_conn = QuicConnection(configuration=quic_config)
    h3_conn = H3Connection(quic_conn)

    # initiate QUIC connection
    quic_conn.connect(dst_addr, now=time())

    # main QUIC loop
    timer = None
    connected = False
    terminated = False
    migrated = False
    resp_map: dict[int, Response] = {}  # key: stream ID, value: response
    req_map: dict[int, Request] = {}    # key: stream ID, value: request
    while not terminated:
        # transmit data
        for data, addr in quic_conn.datagrams_to_send(now=time()):
            if migrated:
                sock.sendto(data, addr)
            else:
                sock_proxy.sendto(data, addr)

        # re-arm timer
        t = quic_conn.get_timer()
        if timer is not None and timer != t:
            timer = None
        if timer is None and t is not None:
            timer = t

        # handle timer
        if timer is not None and time() >= timer:
            timer = None
            quic_conn.handle_timer(now=time())

        # process events
        while (evt := quic_conn.next_event()) is not None:
            if isinstance(evt, aioquic.quic.events.ConnectionIdIssued):
                logger.debug(f"[event] new connection id issued: {evt.connection_id}")
            elif isinstance(evt, aioquic.quic.events.ConnectionIdRetired):
                logger.debug(f"[event] connection id retired: {evt.connection_id}")
            elif isinstance(evt, aioquic.quic.events.ConnectionTerminated):
                logger.debug(f"[event] connection terminated, reason: {evt.reason_phrase}")
                terminated = True
            elif isinstance(evt, aioquic.quic.events.HandshakeCompleted):
                logger.debug(f"[event] handshake completed, negotiated protocols: {evt.alpn_protocol}")
                quic_conn.send_ping(41)
            elif isinstance(evt, aioquic.quic.events.PingAcknowledged):
                logger.debug(f"[event] ping acked, uid={evt.uid}")
                if evt.uid == 42:
                    evt_migrated.set()
                elif evt.uid == 41:
                    evt_connected.set()
                    connected = True
            elif isinstance(evt, aioquic.quic.events.StopSendingReceived):
                logger.debug(f"[event] stop sending received")
            elif isinstance(evt, aioquic.quic.events.StreamDataReceived):
                for evt in h3_conn.handle_event(evt):
                    if isinstance(evt, aioquic.h3.events.HeadersReceived):
                        # create new response object
                        headers = {k: v for k, v in evt.headers}
                        req = req_map[evt.stream_id]
                        resp = Response(
                            status_code=int(headers[b':status'].decode()),
                            url=req.url,
                            headers=headers,
                            req_id=req.req_id,
                            body=None
                        )
                        resp_map[evt.stream_id] = resp

                        if evt.stream_ended:
                            res_q.put(resp)
                    elif isinstance(evt, aioquic.h3.events.DataReceived):
                        res = resp_map[evt.stream_id]
                        if res.body is None:
                            res.body = evt.data
                        else:
                            res.body += evt.data

                        if evt.stream_ended:
                            res_q.put(res)
                    else:
                        logging.debug(f"unknown H3 event: {evt}")
            else:
                logging.debug(f"unknown QUIC event: {evt}")

        # receive data from proxy socket
        try:
            data, addr = sock_proxy.recvfrom(65535)

            if data:
                quic_conn.receive_datagram(data, addr, now=time())
        except BlockingIOError:
            pass

        # receive data from socket
        try:
            data, addr = sock.recvfrom(65535)
            
            if data:
                quic_conn.receive_datagram(data, addr, now=time())
        except BlockingIOError:
            pass
                    
        # send HTTP/3 GET request once connection is established
        if connected:
            try:
                # create new bidi stream
                req = cast(Request, req_q.get_nowait())
                stream_id = quic_conn.get_next_available_stream_id(is_unidirectional=False)
                url = urlparse(req.url)
                req_map[stream_id] = req
                
                # prepare request header
                assert url.hostname is not None
                if len(url.query) > 0:
                    path = url.path + '?' + url.query
                else:
                    path = url.path
                headers = {
                    b':method': req.method.encode(),
                    b':scheme': b'https',
                    b':authority': url.hostname.encode(),
                    b':path': path.encode(),
                    b'user-agent': b'snic/0.1',
                    b'accept': b'*/*',
                    **req.header
                }
                headers = {k.lower(): v for k, v in headers.items()}    # normalize
                if b'connection' in headers:
                    del headers[b'connection']
                if b'host' in headers:
                    del headers[b'host']
                
                # send GET request using stream
                h3_conn.send_headers(stream_id, list(headers.items()), end_stream=(req.body is None))
                if req.body is not None:
                    h3_conn.send_data(stream_id, req.body, end_stream=True)
                logging.debug(f"{req.method} {req.url} (stream id: {stream_id})")
            except queue.Empty:
                pass

        # trigger migration once connection is established
        if connected and not migrated:
            migrated = True
            logging.debug(f"{hostname}: QUIC connection migrated")
            quic_conn.send_ping(42)

        # terminate if event is set
        if evt_terminate.is_set():
            quic_conn.close()
            terminated = True

    logging.debug(f"{hostname}: QUIC loop terminated")

class SNICConnection:
    def __init__(self, hostname: str, dst_addr: tuple[str, int], proxy_addr: tuple[str, int]):
        self.req_q = multiprocessing.Queue()
        self.res_q = multiprocessing.Queue()
        self.evt_connected = multiprocessing.Event()
        self.evt_migrated = multiprocessing.Event()
        self.evt_terminate = multiprocessing.Event()
        self.hostname = hostname
        self.dst_addr = dst_addr
        self.proxy_addr = proxy_addr
        self.proc = None
        self.responses: dict[int, Response] = {}    # key: request ID, value: response
    
    async def connect(self, timeout: Optional[float] = None) -> bool:        
        self.proc = multiprocessing.Process(target=quic_loop, args=(
            self.req_q,
            self.res_q,
            self.evt_connected,
            self.evt_migrated,
            self.evt_terminate,
            self.hostname,
            self.dst_addr,
            self.proxy_addr[0],
            self.proxy_addr[1],
        ))
        self.proc.start()
        return await asyncio.to_thread(lambda: self.evt_connected.wait(timeout))

    async def check_migration(self, timeout: float) -> bool:
        return await asyncio.to_thread(lambda: self.evt_migrated.wait(timeout))

    async def fetch(self, req: Request):
        self.req_q.put(req)
        return await asyncio.to_thread(self._recv_response, req)

    def _recv_response(self, req: Request):
        if req.req_id in self.responses:
            return self.responses[req.req_id]
        
        while (res := self.res_q.get()):
            self.responses[res.req_id] = res
            if res.req_id == req.req_id:
                return res

    async def close(self):
        self.evt_terminate.set()
        await asyncio.to_thread(self._wait_join)

    def _wait_join(self):
        assert self.proc is not None
        self.proc.join()

def fetch(req: Request, proxy_config: tuple[str, int]) -> Response:
    # resolve hostname into ip
    url = urlparse(req.url)
    assert url.hostname is not None
    dns_server_config = (conf.dns_server_addr, conf.dns_server_port)
    ip = asyncio.run(dns.resolve(url.hostname, dns_server_config, proxy_config))
    port = 443 if url.port is None else url.port

    # fetch resource using SNIC
    assert url.hostname is not None
    conn = SNICConnection(url.hostname, (ip, port), proxy_config)
    asyncio.run(conn.connect())
    res = asyncio.run(conn.fetch(req))
    assert isinstance(res, Response)
    asyncio.run(conn.close())

    return res

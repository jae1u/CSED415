import logging
import asyncio
import socket
import socks
from scapy.layers.dns import DNS, DNSQR

from proxy import stat
from proxy.config import conf


logger = logging.getLogger(__name__)

cache: dict[str, str] = {}

class DNSClientProtocol(asyncio.DatagramProtocol):
    def __init__(self, hostname: str, dns_server: tuple[str, int], answer_future: asyncio.Future):
        self.hostname = hostname
        self.dns_server = dns_server
        self.answer_future = answer_future
        self.transport = None
        self.total_sent = 0
        self.total_received = 0

    def connection_made(self, transport):
        self.transport = transport

        # send DNS query packet
        query_pkt = DNS(rd=1, qd=DNSQR(qname=self.hostname, qtype="A"))
        self.total_sent += len(bytes(query_pkt))
        transport.sendto(bytes(query_pkt), self.dns_server)

    def datagram_received(self, data, addr):
        assert addr == self.dns_server
        answer_pkt = DNS(data)
        self.total_received += len(data)
        ip = [a for a in answer_pkt.an if a.type == 1][0].rdata
        self.answer_future.set_result(ip)

async def resolve(hostname: str, dns_server: tuple[str, int], proxy_config: tuple[str, int]) -> str:
    if hostname in conf.dns_override:
        ip = conf.dns_override[hostname]
        logger.log(logging.DEBUG, f"resolved {hostname} to {ip} (overrided)")
        return ip
    
    # lookup cache before making request
    if hostname in cache:
        ip = cache[hostname]
        logger.log(logging.DEBUG, f"resolved {hostname} to {ip} (cached)")
        return ip
    
    # create proxy socket for lookup
    sock = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.set_proxy(
        proxy_type=socks.SOCKS5, 
        addr=proxy_config[0], 
        port=proxy_config[1]
    )

    loop = asyncio.get_running_loop()
    answer_future = loop.create_future()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: DNSClientProtocol(hostname=hostname, dns_server=dns_server, answer_future=answer_future),
        sock=sock
    )

    try:
        ip = await answer_future
        cache[hostname] = ip
        logger.log(logging.DEBUG, f"resolved {hostname} to {ip}")
    finally:
        transport.close()
        stat.increase_total_sent_proxy(protocol.total_sent)
        stat.increase_total_received_proxy(protocol.total_received)
    return ip

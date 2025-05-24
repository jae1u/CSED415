# PoC v3: given a url,
#   1) resolve its ip using proxy and
#   2) GET url using aioquic + passive migration

import socket
import socks
from time import time
from urllib.parse import urlparse
from scapy.layers.dns import DNS, DNSQR
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.h3.connection import H3Connection
import aioquic.quic.events
import aioquic.h3.events
import sys
import getopt
import os
import multiprocessing
import io
from contextlib import redirect_stdout

SUCCESS_MARKER = "end of stream"


def usage():
    print("Usage: python test_connection_migration.py [--url <URL>]")
    print("Options:")
    print("  --url <URL>   Specify the URL to test ")
    print("                (default: https://www.theguardian.com/international)")
    print("  --help        Show this help message")
    print("  --all         Test all URLs in the predefined list")
    print("                (URLs.txt)")
    exit(0)

# inputs
# URL = "https://cloudflare-ech.com/cdn-cgi/trace" # not ok
# URL = "https://www.arxiv.org/" # ok
# URL = "https://www.google.com/" # ok
# URL = "https://quasar.kim/" # ok
# URL = "https://openai.com/" # not ok
# URL = "https://claude.ai/" # not ok
# URL = "https://namu.wiki/" # not ok - cloudflare
# URL = "https://www.instagram.com/" # not ok - migration disabled
# URL = "https://www.youtube.com/" # ok
# URL = "https://www.pinterest.com/" # ok
# URL = "https://golang.google.cn/" # ok
# URL = "https://github.com/" # not ok - no H3
# URL = "https://www.reddit.com/" # ok - with manual IP
# URL = "https://discord.com/" # not ok - cloudflare
# URL = "https://copilot.microsoft.com/" # not ok - unsupported
# URL = "https://www.wired.com/" # ok (not blocked)
URL = "https://www.theguardian.com/international"

PROXY_HOST = "localhost"
PROXY_PORT = 10808
DNS_ADDR = ("1.1.1.1", 53)


def resolve_ip(url: str):
    _url = urlparse(url)

    # create proxy socket for lookup
    sock = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.set_proxy(proxy_type=socks.SOCKS5, addr=PROXY_HOST, port=PROXY_PORT)

    # create DNS request packet
    req_packet = DNS(rd=1, qd=DNSQR(qname=_url.hostname, qtype="A"))
    sock.sendto(bytes(req_packet), DNS_ADDR)

    # receive DNS response
    data, _ = sock.recvfrom(65535)
    res_packet = DNS(data)
    ip = [a for a in res_packet.an if a.type == 1][0].rdata

    sock.close()
    return ip


def get_response(url: str, dst_addr):
    _url = urlparse(url)

    # create socks UDP socket
    sock_proxy = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_proxy.set_proxy(proxy_type=socks.SOCKS5, addr=PROXY_HOST, port=PROXY_PORT)
    sock_proxy.setblocking(False)

    # create underlying UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", 0))
    sock.setblocking(False)

    # create QUIC and H3 connection
    f = open("aioquic_keylog", "w")
    quic_config = QuicConfiguration(
        alpn_protocols=["h3"],
        is_client=True,
        server_name=_url.hostname,
        secrets_log_file=f,
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
    stream_id = None
    req_sent = False
    resp_headers = None
    resp_data = []
    while not terminated:
        # transmit data
        for data, addr in quic_conn.datagrams_to_send(now=time()):
            if migrated:
                sock.sendto(data, addr)
            else:
                sock_proxy.sendto(data, addr)
            print(f"[>] sent {len(data)} bytes")

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
                print(f"[event] new connection id issued: {evt.connection_id}")
            elif isinstance(evt, aioquic.quic.events.ConnectionIdRetired):
                print(f"[event] connection id retired: {evt.connection_id}")
            elif isinstance(evt, aioquic.quic.events.ConnectionTerminated):
                print(f"[event] connection terminated, reason: {evt.reason_phrase}")
                terminated = True
            elif isinstance(evt, aioquic.quic.events.HandshakeCompleted):
                print(
                    f"[event] handshake completed, negotiated protocols: {evt.alpn_protocol}"
                )
                connected = True
            elif isinstance(evt, aioquic.quic.events.PingAcknowledged):
                print(f"[event] ping acked")
            elif isinstance(evt, aioquic.quic.events.StopSendingReceived):
                print(f"[event] stop sending received")
            elif isinstance(evt, aioquic.quic.events.StreamDataReceived):
                for evt in h3_conn.handle_event(evt):
                    if isinstance(evt, aioquic.h3.events.HeadersReceived):
                        resp_headers = evt.headers
                        print(f"[event] H3 headers received: {resp_headers}")
                    elif isinstance(evt, aioquic.h3.events.DataReceived):
                        resp_data.append(evt.data)
                        print(f"[event] H3 data {len(evt.data)} bytes received")

                        # terminate
                        if evt.stream_ended:
                            quic_conn.close()
                            print("end of stream")
                            terminated = True

                    else:
                        print(f"unknown H3 event: {evt}")
            else:
                print(f"unknown QUIC event: {evt}")

        # # receive data
        # try:
        #     if migrated:
        #         data, addr = sock.recvfrom(65535)
        #     else:
        #         data, addr = sock_proxy.recvfrom(65535)

        #     if data:
        #         quic_conn.receive_datagram(data, addr, now=time())
        #         print(f"[<] received {len(data)} bytes")
        # except BlockingIOError:
        #     pass
        # receive data
        try:
            data, addr = sock_proxy.recvfrom(65535)

            if data:
                quic_conn.receive_datagram(data, addr, now=time())
                print(f"[<*] received {len(data)} bytes (from proxy)")
        except BlockingIOError:
            pass

        try:
            data, addr = sock.recvfrom(65535)

            if data:
                quic_conn.receive_datagram(data, addr, now=time())
                print(f"[<] received {len(data)} bytes")
        except BlockingIOError:
            pass

        # send HTTP/3 GET request once connection is established
        if connected and not req_sent:
            # create new bidi stream
            stream_id = quic_conn.get_next_available_stream_id(is_unidirectional=False)
            print(f"creating stream {stream_id}")

            assert _url.hostname is not None, "URL hostname is None"
            # send GET request using stream
            h3_conn.send_headers(
                stream_id,
                [
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", _url.hostname.encode("utf-8")),
                    (b":path", _url.path.encode("utf-8")),
                    (b"user-agent", b"curl/8.13.0"),
                    (b"accept", b"*/*"),
                ],
                end_stream=True,
            )
            req_sent = True
            print("request sent")

        # trigger migration once connection is established
        if connected and not migrated:
            migrated = True
            print("===== migrated =====")

    # print received
    print()
    # print(bytes().join(resp_data).decode('utf-8'))

def URL_gen():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    urls_path = os.path.join(script_dir, "URLs.txt")

    if not os.path.isfile(urls_path):
        raise FileNotFoundError(f"'URLs.txt' not found in the script directory: {script_dir}")

    with open(urls_path, "r", encoding="utf-8") as f:
        urls = f.read().splitlines()
        for url in urls:
            url = url.split("#")[0].strip()
            if url:
                yield url

test_all = False
def parse_args(argv):
    global URL
    global test_all

    try:
        opts, args = getopt.getopt(argv, "", ["help", "url=", "all"])
    except getopt.GetoptError as err:
        print(err)
        usage()

    for opt, arg in opts:
        if opt == "--help":
            usage()
        elif opt == "--url":
            URL = arg.split("#")[0].strip()
        elif opt == "--all":
            test_all = True

    if test_all:
        print("Testing all URLs in the predefined list...")
    else:
        print(f"Testing URL: {URL}")

def test_url_worker(url, ip_addr, output_queue):
    f = io.StringIO()
    with redirect_stdout(f):
        try:
            get_response(url, (ip_addr, 443))
        except Exception as e:
            print(f"ERROR: {e}")
    output_queue.put(f.getvalue()) 

if __name__ == "__main__":
    parse_args(sys.argv[1:])
    
    if test_all:
        success_list = []
        failure_list = []

        for url in URL_gen():
            print(f"Testing URL: {url}")
            try:
                ip_addr = resolve_ip(url)
                print(f"Resolved {url} to {ip_addr}")
            except Exception as e:
                print(f"DNS resolution failed: {e}")
                failure_list.append(url)
                continue

            result_queue = multiprocessing.Queue()
            p = multiprocessing.Process(
                target=test_url_worker, 
                args=(url, ip_addr, result_queue)
            )
            p.start()
            p.join(timeout=5)

            if p.is_alive():
                print(f"[TIMEOUT] {url}")
                p.terminate()
                p.join()
                failure_list.append(url)
            else:
                try:
                    result = result_queue.get_nowait()
                    print(f"Result for {url}: \n{result}")
                    if SUCCESS_MARKER in result:
                        success_list.append(url)
                        print(f"Success: {url}")
                    else:
                        failure_list.append(url)
                        print(f"Failure: {url} - {result}")
                except Exception:
                    failure_list.append(url)
                    print(f"Failure: {url} - No output from process")

            print("-" * 40)

        print("\nSummary:")
        print(f"Successful URLs: {len(success_list)}")
        for url in success_list:
            print(f"  - {url}")
        print(f"Failed URLs: {len(failure_list)}")
        for url in failure_list:
            print(f"  - {url}")
    else:
        ip_addr = resolve_ip(URL)
        print(f"resolved {URL} to {ip_addr}")
        get_response(URL, (ip_addr, 443))


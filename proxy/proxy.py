#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import socket
import ssl
import threading
import logging
from itertools import count
from http import HTTPStatus
from proxy import config
from proxy.config import conf
from proxy.certs import generate_cert
from proxy.interface import Request as Request_t, Response as Response_t
from proxy.fetch_adaptive import fetch

logger = logging.getLogger(__name__)

class ProxyHandler(threading.Thread):
    """
    클라이언트 연결 처리: HTTP 요청 파싱 -> fetch 호출 -> 응답 전송.
    HTTPS의 경우 CONNECT 처리 후 TLS 구성.
    """
    req_counter = count(1)

    def __init__(self, client_socket: socket.socket, address, certfile: str, keyfile: str):
        super().__init__()
        self.client_socket = client_socket
        self.address = address
        self.certfile = certfile
        self.keyfile = keyfile
        self.daemon = True
        self.is_tls = False     # TLS 상태 확인
        self.current_host = None

    def run(self):
        try:
            self.handle_client()
        except Exception as e:
            logger.log(logging.ERROR, f"[Error] {e}")
        finally:
            self.client_socket.close()

    def handle_client(self):
        conn = self.client_socket
        while True:
            data = self._recv_line(conn)
            if not data:
                break
            request_line = data.decode('utf-8').strip()
            parts = request_line.split()
            if len(parts) != 3:
                break
            method, path, version = parts

            # 헤더 읽기
            headers = {}
            while True:
                header_line = self._recv_line(conn)
                if not header_line or header_line == b"\r\n":
                    break
                line = header_line.decode('utf-8')
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()

            # CONNECT 처리 (HTTPS 터널링 시작)
            if method.upper() == 'CONNECT':
                host_port = path.split(':')
                host = host_port[0]
                port = int(host_port[1]) if len(host_port) > 1 else 443
                self.current_host = host
                conn.sendall(f"{version} 200 Connection Established\r\n\r\n".encode('utf-8'))
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                logger.log(logging.DEBUG, f"[TLS] Setting up TLS for {host}:{port} with cert {self.certfile} and key {self.keyfile}")
                context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
                try:
                    tls_conn = context.wrap_socket(conn, server_side=True)
                except Exception as e:
                    logger.log(logging.ERROR, f"[TLS] Handshake failed: {e}")
                    break
                conn = tls_conn
                self.is_tls = True
                continue

            # 바디 읽기 (Content-Length 기반)
            content_length = int(headers.get('Content-Length', 0))
            body = b''
            if content_length > 0:
                remaining = content_length
                while remaining > 0:
                    chunk = conn.recv(min(4096, remaining))
                    if not chunk:
                        return
                    body += chunk
                    remaining -= len(chunk)

            # 전체 URL 구성
            url = path
            if not url.lower().startswith('http'):
                scheme = 'https' if self.is_tls else 'http'
                host = headers.get('Host', '')
                url = f"{scheme}://{host}{path}"

            req_id = next(ProxyHandler.req_counter)
            headers = {k.encode(): v.encode() for k, v in headers.items()}
            request = Request_t(method=method, url=url, header=headers, req_id=req_id, body=body)

            logger.log(logging.INFO, f"> {request.method} {request.url}")
            response = fetch(request, (conf.proxy_addr, conf.proxy_port))
            logger.log(logging.INFO, f"< {response.status_code} {response.url}")

            # response 후처리
            # transfer-encoding 헤더가 설정되어 있을 경우 브라우저에서 오류 발생
            response.headers = {k: v for k, v in response.headers.items() if k.lower() != b'transfer-encoding'}

            # 응답 전송
            self._send_response(conn, response, version)

            # 연결 유지 여부 판단 (Connection 헤더)
            connection_header = headers.get('Connection', '').lower()
            if version == 'HTTP/1.0' and connection_header != 'keep-alive':
                break
            if version == 'HTTP/1.1' and connection_header == 'close':
                break

    def _recv_line(self, conn: socket.socket) -> bytes:
        """ CRLF 단위로 한 줄을 읽음 """
        line = b''
        while not line.endswith(b'\r\n'):
            try:
                chunk = conn.recv(1)
            except Exception:
                return b''
            if not chunk:
                return b''
            line += chunk
        return line

    def _send_response(self, conn: socket.socket, response: Response_t, http_version: str):
        """ Response_t를 기반으로 HTTP 응답 전송 """
        status_text = HTTPStatus(response.status_code).phrase
        status_line = f"{http_version} {response.status_code} {status_text}\r\n"
        headers = {k.decode(): v.decode() for k, v in response.headers.items()}
        if response.body and 'Content-Length' not in headers:
            headers['Content-Length'] = str(len(response.body))
        header_lines = ''.join(f"{k}: {v}\r\n" for k, v in headers.items())
        conn.sendall((status_line + header_lines + "\r\n").encode('utf-8'))
        if response.body:
            conn.sendall(response.body)

class ProxyServer:
    """
    프록시 서버: 소켓 생성/리스닝 및 클라이언트 연결을 ProxyHandler로 처리.
    """
    def __init__(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.server_socket.bind((conf.host, conf.port))
        self.server_socket.listen(5)
        print(f"Proxy listening on {conf.host}:{conf.port}")

    def serve_forever(self):
        try:
            while True:
                client_sock, client_addr = self.server_socket.accept()
                peeked = client_sock.recv(65535, socket.MSG_PEEK).decode(errors='ignore')
                target = peeked.split(" ")[1]
                host, port = target.split(":", 1) if ":" in target else (target, 443)
                cert, key = generate_cert(host)  # 도메인별 인증서 생성
                handler = ProxyHandler(client_sock, client_addr, key, cert)
                handler.start()
        except KeyboardInterrupt:
            print("Proxy shutting down")
        finally:
            self.server_socket.close()

def parse_args():
    parser = argparse.ArgumentParser(
        prog='snic_proxy',
        description='An SNI-concealing https proxy server'
    )
    parser.add_argument('--config', help='Path to a config file (.toml)', required=False)
    parser.add_argument('--loglevel', help='Log level', default='INFO')
    return parser.parse_args()

if __name__ == "__main__":
    # configure logging & proxy-wide settings
    args = parse_args()
    logging.basicConfig(level=args.loglevel)
    logging.getLogger('quic').setLevel(logging.ERROR)
    config.configure_from_file(args.config)

    # start proxy server
    proxy = ProxyServer()
    proxy.serve_forever()

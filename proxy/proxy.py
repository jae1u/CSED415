import socket, ssl, threading
from certs import generate_cert
from urllib.parse import urlparse

PORT = 11556  # Proxy port

def forward(src, dst, direction, shutdown_event, type: str):
    try:
        while not shutdown_event.is_set():
            try:
                data = src.recv(4096)
                if not data:
                    break
                print(f"[{type} {direction}] {len(data)} bytes")
                dst.sendall(data)
            except (ConnectionResetError, BrokenPipeError, OSError):
                break
    except Exception as e:
        print(f"[{type} {direction}] Forward error: {e}")
    finally:
        shutdown_event.set()


def handle_https(client_conn):
    tls_client_conn = None
    tls_server_conn = None
    try:
        request_line = client_conn.recv(1024).decode(errors="ignore")
        # parsing: CONNECT www.example.com:443 HTTP/1.1
        target = request_line.split(" ")[1]
        host, port = target.split(":") if ":" in target else (target, "443")
        port = int(port)

        client_conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        # Generate certificate
        key_path, cert_path = generate_cert(host)

        print(f"[+] Using cert: {cert_path}, key: {key_path}")
        # [CLIENT <---> PROXY] TLS handshake
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=cert_path, keyfile=key_path)
            tls_client_conn = context.wrap_socket(client_conn, server_side=True)
            print(f"[+] TLS handshake success with {host}")
        except Exception as e:
            print(f"[-] TLS handshake failed: {e}")
            return

        # [PROXY <---> REMOTE SERVER] TLS handshake
        try:
            raw_sock = socket.create_connection((host, port))
            tls_server_conn = ssl.create_default_context().wrap_socket(
                raw_sock, server_hostname=host
            )
            print(f"[+] Connected to {host}:{port}")
        except Exception as e:
            print(f"[-] Failed to connect to remote server: {e}")
            return

        shutdown_event = threading.Event()

        t1 = threading.Thread(
            target=forward,
            args=(tls_client_conn, tls_server_conn, "C→S", shutdown_event, "HTTPS"),
        )
        t2 = threading.Thread(
            target=forward,
            args=(tls_server_conn, tls_client_conn, "S→C", shutdown_event, "HTTPS"),
        )

        t1.start()
        t2.start()

        t1.join()
        t2.join()

    finally:
        for sock in [tls_client_conn, tls_server_conn]:
            if sock:
                try:
                    sock.close()
                except:
                    pass
        try:
            client_conn.close()
        except:
            pass


def handle_http(client_conn):
    remote_sock = None
    try:
        request = client_conn.recv(65536)
        request_line = request.split(b"\r\n", 1)[0].decode()
        method, full_url, version = request_line.split()

        url = urlparse(full_url)
        host, port = url.hostname, url.port or 80
        path = url.path or "/"

        # Connect to the remote server
        remote_sock = socket.create_connection((host, port))
        print(f"[HTTP] Forwarding request to {host}:{port}")

        # Modify request to use the path
        request = request.replace(full_url.encode(), path.encode(), 1)
        remote_sock.sendall(request)

        shutdown_event = threading.Event()

        t1 = threading.Thread(
            target=forward,
            args=(client_conn, remote_sock, "C→S", shutdown_event, "HTTP"),
        )
        t2 = threading.Thread(
            target=forward,
            args=(remote_sock, client_conn, "S→C", shutdown_event, "HTTP"),
        )

        t1.start()
        t2.start()

        t1.join()
        t2.join()

    finally:
        for sock in [client_conn, remote_sock]:
            if sock:
                try:
                    sock.close()
                except:
                    pass


def handle_client(client_conn, addr):
    try:
        peeked = client_conn.recv(65536, socket.MSG_PEEK)
        if peeked.startswith(b"CONNECT"):
            handle_https(client_conn)
        else:
            handle_http(client_conn)
    except Exception as e:
        print(f"[!] Error handling client: {e}")
        client_conn.close()
    finally:
        try:
            client_conn.close()
        except:
            pass


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind(("0.0.0.0", PORT))
    s.listen()
    print(f"Proxy running on port {PORT}...")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()


if __name__ == "__main__":
    main()

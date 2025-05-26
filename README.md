# SNIC
---

## Setting up a secure tunnel

You need a tunnel, like v2ray.

## Generating and Installing Root CA

First, you need to generate self-signed root CA. This is required since SNIC needs to decrypt HTTPS traffic. Issue following commands to generate one:

```bash
cd ./proxy
openssl genrsa -out rootCA.key 2048
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 3650 \
  -out rootCA.crt \
  -subj "/C=KR/ST=Seoul/O=MyProxy/CN=MyRootCA"
```

To use this certificate in your browser, you need to import the `rootCA.crt` file into your browser's trusted certificate store. Then, you need to configure your browser to use your proxy server.

If you are using Firefox, you can use
- `settings > Privacy & Security > Certificates > View Certificates > Authorities > Import` to import the `rootCA.crt` file.
- `settings > General > Network Settings > Settings > Manual proxy configuration` to set up your proxy server

If you are using Chrome, you can use
- `settings > Prvacy and security > Security > Manage certificates > Custom (Installed by you) > Import` to import the `rootCA.crt` file.
- `settings > System > Open your computer's proxy settings` to set up your proxy server. (Chrome uses the system proxy settings)

## Running SNIC

SNIC is coded with python and can be run by using a python interpreter. After cloning the [SNIC repository](https://github.com/jae1u/CSED415), run the following command in the project root directory to start SNIC.

```bash
python -m proxy.proxy
```

The network location at which SNIC is listening to is printed. Configure application to use that address as HTTPS proxy. For example, to launch chromium browser with SNIC listening at localhsot:11556 set as a proxy, issue following command:

```bash
chromium --proxy-server="http=localhost:11556;https=localhost:11556"
```

## Configuration
Following options are configurable:

- `host`, `port`: address at which SNIC listens to
- `cert_file`: root CA certificate file path
- `key_file`: root CA private key file path
- `dns_server_addr`, `dns_server_port`: address of a DNS server to use.
- `proxy_addr`, `proxy_port`: address at which SOCKS5 proxy listens to
- `fetch_adaptive_snic_timeout`: timeout of path migration
- `fetch_adaptive_snic_works_override`: a table indicating whether to use QUICstep for hostnames. key: hostname, value: boolean.
- `dns_override`: a table overriding built-in DNS resolver. key: hostname, value: ip address

Example Configuration file:

```toml
host = "127.0.0.1"
port = 11556
cert_file = "./proxy/rootCA.crt"
key_file = "./proxy/rootCA.key"
dns_server_addr = "1.1.1.1"
dns_server_port = 53
proxy_addr = "127.0.0.1"
proxy_port = 10808
fetch_adaptive_snic_timeout = 3

[fetch_adaptive_snic_works_override]
"www.google.com" = true

[dns_override]
"www.theguardian.com" = "146.75.49.111"
```

To load config file, use `--config` command line argument:

```bash
python -m proxy.proxy --config config.toml
```
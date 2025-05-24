import os
import subprocess
from string import Template

from proxy.config import conf

def generate_cert(domain):
    # Configs
    key_path = f"proxy/certs/{domain}.key"
    crt_path = f"proxy/certs/{domain}.crt"
    csr_path = f"proxy/certs/{domain}.csr"
    config_path = f"proxy/certs/{domain}.cnf"
    if os.path.exists(crt_path):
        return key_path, crt_path
    os.makedirs("certs", exist_ok=True)

    # Generate config file
    template = Template("""
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[dn]
CN = $domain

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = $domain
""")
    with open(config_path, "w") as f:
        f.write(template.substitute(domain=domain))

    # Generate private key
    subprocess.run(["openssl", "genrsa", "-out", key_path, "2048"], check=True)

    # Generate CSR including SAN
    subprocess.run([
        "openssl", "req", "-new", "-key", key_path, "-out", csr_path,
        "-config", config_path
    ], check=True)

    # Certificate
    subprocess.run([
        "openssl", "x509", "-req", "-in", csr_path,
        "-CA", conf.cert_file, "-CAkey", conf.key_file,
        "-CAcreateserial", "-out", crt_path,
        "-days", "365", "-sha256",
        "-extfile", config_path, "-extensions", "req_ext"
    ], check=True)

    return key_path, crt_path

import asyncio
import socket
import time
from proxy.fetch_snic import SNICConnection
import os
from urllib.parse import urlparse
import subprocess

def resolve_ip(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        try:
            result = subprocess.run([
                "dig", "+short", hostname
            ], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=2)
            output = result.stdout.decode().strip().splitlines()
            for line in output:
                if line and all(part.isdigit() or part == '.' for part in line):
                    return line
        except Exception as e:
            print(f"dig failed for {hostname}: {e}")
    raise RuntimeError(f"DNS resolution failed for {hostname}")

def URL_gen():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    urls_path = os.path.join(script_dir, "URLs.txt")

    if not os.path.isfile(urls_path):
        raise FileNotFoundError(f"'URLs.txt' not found in the script directory: {script_dir}")

    with open(urls_path, "r", encoding="utf-8") as f:
        urls = f.read().splitlines()
        for url in urls:
            url = url.split("#")[0].strip()
            hostname = urlparse(url).hostname
            if hostname:
                yield hostname

async def check_migration_support(hostname: str):
    # ip = socket.gethostbyname(hostname)
    ip = resolve_ip(hostname)
    conn = SNICConnection(hostname, (ip, 443), ("localhost", 10808))

    timeout = 5
    start = time.time() 
    await conn.connect(timeout)
    timeout -= (time.time() - start)
    
    result = await conn.check_migration(timeout)
    await conn.close()
    return hostname, result

async def main():
    hosts = list(URL_gen())
    sem = asyncio.Semaphore(100)
    SUCC_LIST = []
    FAIL_LIST = []

    async def bound_check(host):
        async with sem:
            try:
                hostname, result = await check_migration_support(host)
                if result:
                    SUCC_LIST.append(hostname)
                else:
                    FAIL_LIST.append(hostname)
            except Exception as e:
                print(f"Error checking {host}: {e}")
                FAIL_LIST.append(host)

    tasks = [asyncio.create_task(bound_check(host)) for host in hosts]
    await asyncio.gather(*tasks)

    print("Migration Support Check Results:")
    print(f"Success: {len(SUCC_LIST)}")
    for hostname in SUCC_LIST:
        print(f" - {hostname}")
    print()
    print(f"Failure: {len(FAIL_LIST)}")
    for hostname in FAIL_LIST:
        print(f" - {hostname}")


asyncio.run(main())


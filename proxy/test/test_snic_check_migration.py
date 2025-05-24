import asyncio
import socket
import time
from proxy.fetch_snic import SNICConnection

async def check_migration_support(hostname: str):
    ip = socket.gethostbyname(hostname)
    conn = SNICConnection(hostname, (ip, 443), ("localhost", 10808))

    timeout = 5
    start = time.time() 
    await conn.connect(timeout)
    timeout -= (time.time() - start)
    
    result = await conn.check_migration(timeout)
    await conn.close()
    return result

async def main():
    hosts = [
        "www.arxiv.org",
        "www.reddit.com",
        "www.google.com",
        "www.naver.com"
    ]

    for hostname in hosts:
        print(hostname, await check_migration_support(hostname))

asyncio.run(main())
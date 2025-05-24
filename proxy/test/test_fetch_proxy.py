from proxy.fetch_proxy import fetch
from proxy.interface import Request

request = Request(
    method="POST",
    url="https://httpbin.org/post",
    header={
        b'Host': b'httpbin.org',
        b'Content-Length': b'10'
    },
    req_id=0,
    body=b'1234567890'
)
proxy_config = ("localhost", 10808)
print(fetch(request, proxy_config))